
from flask import Flask, request, jsonify , redirect
import os
import subprocess
import logging
import hmac
import hashlib
import shutil
import json
import asyncio
from github import Github, GithubIntegration
from dotenv import load_dotenv
from datetime import datetime
from flask_cors import CORS
from models import db, AnalysisResult
from sqlalchemy import or_, text, create_engine
from sqlalchemy.pool import QueuePool
import traceback
import requests
from scanner import SecurityScanner, ScanConfig, scan_repository_handler
from api import api, analysis_bp
import time
from sqlalchemy import event
from progress import progress_bp
from flask_caching import Cache
import redis
from urllib.parse import quote_plus
import logging
from db_utils import create_db_engine
from flask_socketio import SocketIO, emit, join_room, disconnect
from threading import Thread, Lock
from progress_tracking import get_scan_progress, update_scan_progress,clear_scan_progress
from progress_tracking import get_redis_client
from aws_api import aws_bp
from gitlab_api import gitlab_bp
import random
from urllib.parse import urlencode


# Configure logging
logging.basicConfig(
    level=logging.INFO if os.getenv('FLASK_ENV') == 'production' else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Session management for WebSockets
session_lock = Lock()
active_sessions = {}

def manage_session(sid, action='add'):
    """Manage active sessions"""
    with session_lock:
        if action == 'add':
            active_sessions[sid] = time.time()
        elif action == 'remove' and sid in active_sessions:
            del active_sessions[sid]
        elif action == 'check':
            return sid in active_sessions

def cleanup_old_sessions():
    """Clean up expired sessions"""
    now = time.time()
    with session_lock:
        expired = [sid for sid, timestamp in active_sessions.items() 
                  if now - timestamp > 300]  # 5 minutes timeout
        for sid in expired:
            del active_sessions[sid]

def configure_app_db(app, database_url=None):
    """Configure database for Flask app"""
    engine = create_db_engine(database_url)
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url or engine.url
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 20,
        'max_overflow': 40,
        'pool_timeout': 30,
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'connect_args': {
            'connect_timeout': 10,
            'keepalives': 1,
            'keepalives_idle': 30,
            'keepalives_interval': 10,
            'keepalives_count': 5
        }
    }
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = False
    
    return engine

def check_db_connection():
    try:
        with app.app_context():
            db.session.execute(text('SELECT 1'))
            db.session.commit()
            return True
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        return False

def execute_with_retry(operation, max_retries=3, delay=1):
    def run_with_context():
        with app.app_context():
            return operation()
            
    for attempt in range(max_retries):
        try:
            return run_with_context()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            logger.warning(f"Database operation failed, attempt {attempt + 1} of {max_retries}")
            time.sleep(delay)
            if not check_db_connection():
                logger.info("Reconnecting to database...")
                db.session.remove()

def check_and_add_columns():
    try:
        result = db.session.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='analysis_results' AND column_name='user_id'
        """))
        column_exists = bool(result.scalar())
        
        if not column_exists:
            logger.info("Adding user_id column...")
            db.session.execute(text("""
                ALTER TABLE analysis_results 
                ADD COLUMN IF NOT EXISTS user_id VARCHAR(255)
            """))
            db.session.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_analysis_results_user_id 
                ON analysis_results (user_id)
            """))
            db.session.commit()

        result = db.session.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='analysis_results' AND column_name='rerank'
        """))
        rerank_exists = bool(result.scalar())
        
        if not rerank_exists:
            logger.info("Adding rerank column...")
            db.session.execute(text("""
                ALTER TABLE analysis_results 
                ADD COLUMN IF NOT EXISTS rerank JSONB
            """))
            db.session.commit()
            
    except Exception as e:
        logger.error(f"Error checking/adding columns: {str(e)}")
        db.session.rollback()
        raise

# Initialize Flask app and Redis
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
redis_client = redis.from_url(
    REDIS_URL,
    decode_responses=True,
    socket_timeout=5,
    socket_connect_timeout=5,
    socket_keepalive=True,
    health_check_interval=30,
    retry_on_timeout=True
)

# Initialize Redis pub/sub for WebSocket communication
pubsub = redis_client.pubsub(ignore_subscribe_messages=True)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Initialize SocketIO
socketio = SocketIO(
    cors_allowed_origins=[
        "https://developer.rezliant.com",
        "https://stg.rezliant.com",
        "http://localhost:3000"
    ],
    message_queue=REDIS_URL,
    channel="semgrep-scan",
    async_mode='asgi',
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=5 * 1024 * 1024,
    async_handlers=True,
    logger=True,
    engineio_logger=True,
    manage_session=False,
    cookie=None
)
socketio.init_app(app)

# Initialize cache
cache = Cache(config={
    'CACHE_TYPE': 'SimpleCache',
    'CACHE_DEFAULT_TIMEOUT': 7200  # 2 hours
})
cache.init_app(app)
app.cache = cache

# Register blueprints
app.register_blueprint(progress_bp)
app.register_blueprint(api, name='api_main') 
app.register_blueprint(analysis_bp, name="analysis_main")
app.register_blueprint(aws_bp, name="aws_main")
app.register_blueprint(gitlab_bp, name="gitlab_main")

def redis_listener():
    """
    Listen for Redis pub/sub messages with improved error handling,
    automatic reconnection, and reliable message delivery.
    """
    last_processed = {}  # Track last processed message time by room and stage
    min_interval = 0.1  # Minimum time between messages for the same room and stage
    reconnect_delay = 5  # Initial reconnect delay in seconds
    max_reconnect_delay = 30  # Maximum reconnect delay in seconds
    connection_attempt = 0  # Count connection attempts for backoff
    
    # Create dedicated Redis connection for the listener
    listener_redis = None
    pubsub = None
    
    # Critical stages that should always be delivered
    CRITICAL_STAGES = {'initializing', 'error', 'completed', 'validation_complete', 
                      'scan_complete', 'reset'}
    
    while True:
        try:
            # Initialize or reinitialize Redis connection if needed
            if listener_redis is None or pubsub is None or not hasattr(pubsub, 'connection') or pubsub.connection is None:
                connection_attempt += 1
                try:
                    logger.info("Initializing Redis pub/sub connection")
                    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
                    listener_redis = redis.from_url(
                        REDIS_URL,
                        decode_responses=True,
                        socket_timeout=10,
                        socket_connect_timeout=5,
                        socket_keepalive=True,
                        health_check_interval=30,
                        retry_on_timeout=True
                    )
                    
                    # Create new pubsub instance
                    pubsub = listener_redis.pubsub(ignore_subscribe_messages=True)
                    pubsub.subscribe('scan_updates')
                    
                    logger.info("Successfully subscribed to scan_updates channel")
                    
                    # Reset connection attempt counter on success
                    connection_attempt = 0
                    reconnect_delay = 5  # Reset backoff
                    
                    # Purge any old messages to avoid flooding reconnected clients
                    while pubsub.get_message(timeout=0.1):
                        pass  # Discard old messages
                        
                except Exception as e:
                    logger.error(f"Failed to initialize Redis connection: {str(e)}")
                    
                    # Implement exponential backoff for reconnection attempts
                    current_delay = min(max_reconnect_delay, reconnect_delay * (1.5 ** min(connection_attempt - 1, 5)))
                    logger.info(f"Retrying in {current_delay:.1f} seconds (attempt {connection_attempt})")
                    time.sleep(current_delay)
                    continue
            
            # Get message with timeout to detect connection issues faster
            try:
                message = pubsub.get_message(timeout=1.0)
            except redis.TimeoutError:
                # Handle timeouts gracefully - just try again
                time.sleep(0.1)
                continue
            except (redis.ConnectionError, ConnectionError) as e:
                logger.error(f"Redis connection error: {str(e)}")
                # Reset connection on next iteration
                pubsub = None
                listener_redis = None
                time.sleep(reconnect_delay)
                continue
            
            if not message:
                # No message, just check connection health and continue
                if random.random() < 0.01:  # ~1% of iterations, check connection health
                    try:
                        # Ping Redis to verify connection
                        if listener_redis is not None:
                            listener_redis.ping()
                    except Exception as e:
                        logger.error(f"Redis health check failed: {str(e)}")
                        pubsub = None
                        listener_redis = None
                        time.sleep(1)  # Brief pause before reconnecting
                time.sleep(0.01)  # Short sleep to prevent CPU spinning
                continue
                
            # Process message if it's the right type
            if message and message['type'] == 'message':
                try:
                    data = json.loads(message['data'])
                    
                    # Get message components
                    scan_type = data.get('scan_type', 'repository')
                    user_id = data.get('user_id')
                    resource_id = data.get('repo_name')
                    room = data.get('room')
                    progress_data = data.get('data', {})
                    
                    # Check if this is a completion message
                    is_completion = data.get('is_completion', False)
                    is_error = data.get('is_error', False)
                    
                    # PRIORITIZE COMPLETION MESSAGES
                    if is_completion or is_error:
                        logger.info(f"Processing {'completion' if is_completion else 'error'} message for {room}")
                        
                        # Get room members for direct delivery
                        from progress_tracking import get_room_members
                        members = get_room_members(room)
                        
                        # Broadcast to room first
                        socketio.emit('progress_update', progress_data, room=room)
                        socketio.emit('scan_complete', {
                            'status': 'completed' if is_completion else 'error',
                            'timestamp': int(time.time())
                        }, room=room)
                        
                        # Also send directly to each client with slight delays
                        for member in members:
                            try:
                                socketio.emit('progress_update', progress_data, to=member)
                                socketio.emit('scan_complete', {
                                    'status': 'completed' if is_completion else 'error',
                                    'direct': True,
                                    'timestamp': int(time.time())
                                }, to=member)
                                logger.info(f"Sent direct completion to {member}")
                            except Exception as direct_err:
                                logger.error(f"Error sending direct message: {str(direct_err)}")
                            
                            # Small delay between clients to avoid overwhelming system
                            time.sleep(0.05)
                        
                        logger.info(f"Processed completion event for {len(members)} clients")
                    else:
                        # Regular progress update
                        socketio.emit('progress_update', progress_data, room=room)
                    
                except Exception as e:
                    logger.error(f"Error processing message: {str(e)}")
            
            # Brief sleep to prevent CPU spinning
            time.sleep(0.01)
            
        except Exception as e:
            logger.error(f"Redis listener error: {str(e)}")
            time.sleep(1)

def cleanup_room_after_delay(room, delay_seconds):
    """Clean up a room after a delay with improved approach."""
    socketio.sleep(delay_seconds)
    try:
        # When sending the completion message, use a special identifier
        completion_data = {
            'status': 'completed', 
            'timestamp': int(time.time()),
            'message_type': 'final_completion'  # Add this identifier
        }
        
        # Send as a PROGRESS_UPDATE instead of a separate event type
        socketio.emit('progress_update', {
            's': 'final_complete',  
            'p': 100,
            'o': 100,
            't': int(time.time()),
            'final': True  # Add this flag
        }, room=room)
        
        # Now also send the original event
        socketio.emit('scan_complete', completion_data, room=room)
        
    except Exception as e:
        logger.error(f"Error during room cleanup: {str(e)}")

@socketio.on_error_default
def error_handler(e):
    """Global error handler with improved logging"""
    logger.error(f"SocketIO error: {str(e)}", exc_info=True)
    
    # Get the client's socket ID
    try:
        sid = request.sid
        logger.error(f"Error occurred for client {sid}")
    except:
        pass

@socketio.on('connect')
def handle_connect():
    """Handle client connection with reliable session tracking"""
    try:
        sid = request.sid
        # Create a more secure session tracking mechanism
        manage_session(sid, 'add')
        cleanup_old_sessions()
        
        # Log the connection with more detail
        user_agent = request.headers.get('User-Agent', 'Unknown')
        transport = getattr(request, 'transport', 'Unknown')
        logger.info(f"Client connected: {sid} | Transport: {transport} | UA: {user_agent[:50]}")
        
        # Record connection timestamp in Redis
        redis_client = get_redis_client()
        redis_client.hset(f"socket:{sid}", "connected_at", int(time.time()))
        redis_client.expire(f"socket:{sid}", 3600)  # 1 hour expiration
        
        # Send connection acknowledgment with server timestamp for latency calculation
        emit('connected', {
            'status': 'connected',
            'sid': sid,
            'server_time': int(time.time() * 1000)  # milliseconds
        })
    except Exception as e:
        logger.error(f"Connection error: {str(e)}", exc_info=True)
        return False

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection with proper cleanup"""
    try:
        sid = request.sid
        if sid:
            # Remove from session management
            manage_session(sid, 'remove')
            
            # Get the client's subscriptions before removing them
            redis_client = get_redis_client()
            subscription_key = f"socket_subscription:{sid}"
            subscription_data = redis_client.hgetall(subscription_key)
            
            if subscription_data:
                room = subscription_data.get('room')
                logger.info(f"Client {sid} disconnected from room {room}")
                
                # Clean up subscription data
                from progress_tracking import unregister_socket_subscription
                unregister_socket_subscription(sid)
            else:
                logger.info(f"Client {sid} disconnected (no subscriptions)")
                
            # Remove connection record
            redis_client.delete(f"socket:{sid}")
    except Exception as e:
        logger.error(f"Disconnection error: {str(e)}", exc_info=True)

@socketio.on('ping_server')
def handle_ping(data=None):
    """Enhanced ping handler with latency tracking"""
    try:
        sid = request.sid
        client_time = data.get('time', 0) if isinstance(data, dict) else 0
        now = int(time.time() * 1000)  # milliseconds
        
        # Calculate latency if client provided a timestamp
        latency = None
        if client_time > 0:
            latency = now - client_time
            
        response = {
            'server_time': now,
            'sid': sid
        }
        
        if latency is not None:
            response['latency'] = latency
            
            # Log high latency values
            if latency > 500:  # 500ms threshold
                logger.warning(f"High latency ({latency}ms) detected for client {sid}")
        
        emit('pong_server', response)
    except Exception as e:
        logger.error(f"Ping/pong error: {str(e)}")

@socketio.on('subscribe_to_aws_scan')
def handle_aws_subscribe(data):
    try:
        sid = request.sid
        user_id = data.get('user_id')
        account_id = data.get('account_id')
        
        if not all([user_id, account_id]):
            emit('error', {'message': 'Invalid parameters'})
            return
        
        # Join the room
        room = f"aws_scan_{user_id}_{account_id}"
        join_room(room)
        logger.info(f"Client {sid} joined room {room}")
        
        # Send confirmation
        emit('room_joined', {'room': room, 'timestamp': int(time.time())})
        
        # Check if scan has already completed
        redis_client = get_redis_client()
        completion_key = f"scan_complete:{user_id}:{account_id}"
        completion_data = redis_client.get(completion_key)
        
        if completion_data:
            # Scan already completed, send immediate notification
            try:
                completion_info = json.loads(completion_data)
                emit('progress_update', {
                    's': 'completed',
                    'p': 100,
                    'o': 100,
                    't': int(time.time()),
                    'id': completion_info.get('scan_id', 'unknown'),
                    'from_cache': True
                })
                emit('scan_complete', {'status': 'completed', 'timestamp': int(time.time())})
                logger.info(f"Sent cached completion to new subscriber {sid}")
            except Exception as e:
                logger.error(f"Error sending cached completion: {str(e)}")
        else:
            # Check for current progress
            progress_key = f"scan_progress:{user_id}:{account_id}"
            progress_data = redis_client.get(progress_key)
            
            if progress_data:
                try:
                    progress = json.loads(progress_data)
                    emit('progress_update', {
                        's': progress.get('stage', 'unknown'),
                        'p': progress.get('stage_progress', 0),
                        'o': progress.get('overall_progress', 0),
                        't': progress.get('unix_timestamp', int(time.time())),
                        'id': progress.get('scan_id', 'unknown')
                    })
                    logger.info(f"Sent current progress to {sid}: {progress.get('stage')} ({progress.get('stage_progress')}%)")
                except Exception as e:
                    logger.error(f"Error sending progress: {str(e)}")
            else:
                # No active scan
                emit('scan_waiting', {'message': 'No active scan', 'timestamp': int(time.time())})
                
    except Exception as e:
        logger.error(f"Subscription error: {str(e)}")
        emit('error', {'message': 'Subscription failed'})


@socketio.on('subscribe_to_gitlab_scan')
def handle_gitlab_subscribe(data):
    try:
        sid = request.sid
        user_id = data.get('user_id')
        project_id = data.get('project_id')
        
        if not all([user_id, project_id]):
            emit('error', {'message': 'Invalid parameters'})
            return
        
        # Join the room
        room = f"gitlab_scan_{user_id}_{project_id}"
        join_room(room)
        logger.info(f"Client {sid} joined GitLab scan room {room}")
        
        # Send confirmation
        emit('room_joined', {'room': room, 'timestamp': int(time.time())})
        
        # Check if scan has already completed
        redis_client = get_redis_client()
        completion_key = f"scan_complete:{user_id}:{project_id}"
        completion_data = redis_client.get(completion_key)
        
        if completion_data:
            # Scan already completed, send immediate notification
            try:
                completion_info = json.loads(completion_data)
                emit('progress_update', {
                    's': 'completed',
                    'p': 100,
                    'o': 100,
                    't': int(time.time()),
                    'id': completion_info.get('scan_id', 'unknown'),
                    'from_cache': True
                })
                emit('scan_complete', {'status': 'completed', 'timestamp': int(time.time())})
                logger.info(f"Sent cached completion to new GitLab subscriber {sid}")
            except Exception as e:
                logger.error(f"Error sending cached GitLab completion: {str(e)}")
        else:
            # Check for current progress
            progress_key = f"scan_progress:{user_id}:{project_id}"
            progress_data = redis_client.get(progress_key)
            
            if progress_data:
                try:
                    progress = json.loads(progress_data)
                    emit('progress_update', {
                        's': progress.get('stage', 'unknown'),
                        'p': progress.get('stage_progress', 0),
                        'o': progress.get('overall_progress', 0),
                        't': progress.get('unix_timestamp', int(time.time())),
                        'id': progress.get('scan_id', 'unknown')
                    })
                    logger.info(f"Sent current GitLab progress to {sid}: {progress.get('stage')} ({progress.get('stage_progress')}%)")
                except Exception as e:
                    logger.error(f"Error sending GitLab progress: {str(e)}")
            else:
                # No active scan
                emit('scan_waiting', {'message': 'No active GitLab scan', 'timestamp': int(time.time())})
                
    except Exception as e:
        logger.error(f"GitLab subscription error: {str(e)}")
        emit('error', {'message': 'GitLab subscription failed'})

@socketio.on('subscribe_to_scan')
def handle_subscribe(data):
    """
    Handle repository scan progress subscription with the same improvements
    as the AWS scan handler.
    """
    try:
        sid = request.sid
        logger.info(f"Repository scan subscription request from {sid}: {data}")
        
        # Validate session
        if not manage_session(sid, 'check'):
            logger.warning(f"Invalid session attempting to subscribe: {sid}")
            emit('error', {'message': 'Invalid session'})
            return
        
        # Validate subscription data
        user_id = data.get('user_id')
        repo_name = data.get('repo_name')
        
        if not all([user_id, repo_name]):
            logger.warning(f"Invalid repository subscription request: {data}")
            emit('error', {'message': 'Invalid subscription parameters'})
            return
        
        # Create room name
        room = f"scan_{user_id}_{repo_name}"
        
        # Join the room
        join_room(room)
        logger.info(f"Client {sid} subscribed to repository scan room: {room}")
        
        # Register subscription in Redis
        from progress_tracking import register_socket_subscription, get_scan_progress
        register_socket_subscription(
            socket_id=sid,
            user_id=user_id,
            resource_id=repo_name,
            scan_type='repository'
        )
        
        # Send confirmation to client
        emit('room_joined', {
            'room': room,
            'status': 'subscribed',
            'timestamp': int(time.time())
        })
        
        # Send current progress if available
        progress = get_scan_progress(user_id, repo_name)
        if progress:
            scan_id = progress.get('scan_id')
            
            # Send initial progress update
            ws_data = {
                's': progress.get('stage', 'unknown'),
                'p': progress.get('stage_progress', 0),
                'o': progress.get('overall_progress', 0),
                't': progress.get('unix_timestamp', int(time.time())),
                'id': scan_id
            }
            
            emit('progress_update', ws_data)
            logger.info(f"Sent initial progress to {sid}: {progress.get('stage')} at {progress.get('overall_progress')}%")
            
            # If scan is already completed or in error state, also send final status
            if progress.get('stage') in ['completed', 'error']:
                emit('scan_complete', {
                    'status': progress.get('stage'),
                    'scan_id': scan_id,
                    'timestamp': int(time.time())
                })
        else:
            # No progress data yet, send waiting message
            emit('scan_waiting', {
                'message': 'Waiting for scan to start',
                'timestamp': int(time.time())
            })
            
    except Exception as e:
        logger.error(f"Repository scan subscription error: {str(e)}", exc_info=True)
        emit('error', {'message': 'Subscription failed, please try again'})



# Start Redis listener in background
redis_listener_thread = Thread(target=redis_listener, daemon=True)
redis_listener_thread.start()

@app.route('/health')
def health_check():
    try:
        # Test database connection
        with app.app_context():
            db.session.execute(text('SELECT 1'))
            db.session.commit()
            
        # Test Redis connection
        redis_client.ping()
            
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'connected',
            'redis': 'connected',
            'database_url': DATABASE_URL is not None,
            'redis_url': REDIS_URL is not None,
            'git_integration': 'initialized' if 'git_integration' in globals() else 'not initialized'
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500
    
@app.route('/api/v1/debug/schema', methods=['GET'])
def debug_schema():
    try:
        result = db.session.execute(text("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name='cloud_scans'
            ORDER BY ordinal_position;
        """))
        
        columns = [{'name': row.column_name, 'type': row.data_type} for row in result]
        
        return jsonify({
            'table': 'cloud_scans',
            'columns': columns
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    


@app.route('/api/v1/debug/add-columns', methods=['POST'])
def add_columns_endpoint():
    try:
        with app.app_context():
            # Check if completed_at column exists
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='cloud_scans' AND column_name='completed_at'
            """))
            completed_at_exists = bool(result.scalar())
            
            # Check if error column exists
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='cloud_scans' AND column_name='error'
            """))
            error_exists = bool(result.scalar())
            
            # Add columns if they don't exist
            changes_made = False
            
            if not completed_at_exists:
                db.session.execute(text("""
                    ALTER TABLE cloud_scans 
                    ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP
                """))
                db.session.commit()
                changes_made = True
            
            if not error_exists:
                db.session.execute(text("""
                    ALTER TABLE cloud_scans 
                    ADD COLUMN IF NOT EXISTS error TEXT
                """))
                db.session.commit()
                changes_made = True
                
            # Check schema after changes
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='cloud_scans'
                ORDER BY ordinal_position
            """))
            
            columns = [row.column_name for row in result]
            
            return jsonify({
                'success': True,
                'changes_made': changes_made,
                'before': {
                    'completed_at_exists': completed_at_exists,
                    'error_exists': error_exists
                },
                'after': {
                    'completed_at_exists': 'completed_at' in columns,
                    'error_exists': 'error' in columns
                },
                'columns': columns
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500
    


def format_private_key(key_data):
    """Format the private key correctly for GitHub integration"""
    try:
        if not key_data:
            raise ValueError("Private key is empty")
        
        key_data = key_data.strip()
        
        if '\\n' in key_data:
            parts = key_data.split('\\n')
            key_data = '\n'.join(part.strip() for part in parts if part.strip())
        elif '\n' not in key_data:
            key_length = len(key_data)
            if key_length < 64:
                raise ValueError("Key content too short")
            
            if not key_data.startswith('-----BEGIN'):
                key_data = (
                    '-----BEGIN RSA PRIVATE KEY-----\n' +
                    '\n'.join(key_data[i:i+64] for i in range(0, len(key_data), 64)) +
                    '\n-----END RSA PRIVATE KEY-----'
                )
        
        if not key_data.startswith('-----BEGIN RSA PRIVATE KEY-----'):
            key_data = '-----BEGIN RSA PRIVATE KEY-----\n' + key_data
        if not key_data.endswith('-----END RSA PRIVATE KEY-----'):
            key_data = key_data + '\n-----END RSA PRIVATE KEY-----'
        
        lines = key_data.split('\n')
        if len(lines) < 3:
            raise ValueError("Invalid key format - too few lines")
        
        logger.info("Private key formatted successfully")
        return key_data
        
    except Exception as e:
        logger.error(f"Error formatting private key: {str(e)}")
        raise ValueError(f"Private key formatting failed: {str(e)}")

def verify_webhook_signature(request_data, signature_header):
    """
    Enhanced webhook signature verification for GitHub webhooks
    """
    try:
        webhook_secret = os.getenv('GITHUB_WEBHOOK_SECRET')
        
        logger.info("Starting webhook signature verification")
        
        if not webhook_secret:
            logger.error("GITHUB_WEBHOOK_SECRET environment variable is not set")
            return False

        if not signature_header:
            logger.error("No X-Hub-Signature-256 header received")
            return False

        if not signature_header.startswith('sha256='):
            logger.error("Signature header doesn't start with sha256=")
            return False
            
        # Get the raw signature without 'sha256=' prefix
        received_signature = signature_header.replace('sha256=', '')
        
        # Ensure webhook_secret is bytes
        if isinstance(webhook_secret, str):
            webhook_secret = webhook_secret.strip().encode('utf-8')
            
        # Ensure request_data is bytes
        if isinstance(request_data, str):
            request_data = request_data.encode('utf-8')
            
        # Calculate expected signature
        mac = hmac.new(
            webhook_secret,
            msg=request_data,
            digestmod=hashlib.sha256
        )
        expected_signature = mac.hexdigest()
        
        # Debug logging
        logger.debug("Signature Details:")
        logger.debug(f"Request Data Length: {len(request_data)} bytes")
        logger.debug(f"Secret Key Length: {len(webhook_secret)} bytes")
        logger.debug(f"Raw Request Data: {request_data[:100]}...")  # First 100 bytes
        logger.debug(f"Received Header: {signature_header}")
        logger.debug(f"Calculated HMAC: sha256={expected_signature}")
        
        # Use constant time comparison
        is_valid = hmac.compare_digest(expected_signature, received_signature)
        
        if not is_valid:
            logger.error("Signature mismatch detected")
            logger.error(f"Header format: {signature_header}")
            logger.error(f"Received signature: {received_signature[:10]}...")
            logger.error(f"Expected signature: {expected_signature[:10]}...")
            
            # Additional debug info
            if os.getenv('FLASK_ENV') != 'production':
                logger.debug("Full signature comparison:")
                logger.debug(f"Full received: {received_signature}")
                logger.debug(f"Full expected: {expected_signature}")
        else:
            logger.info("Webhook signature verified successfully")
            
        return is_valid

    except Exception as e:
        logger.error(f"Signature verification failed: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def verify_gitlab_webhook_signature(request_data, signature_header):
    """Verify GitLab webhook signature"""
    try:
        webhook_secret = os.getenv('GITLAB_WEBHOOK_SECRET')
        if not webhook_secret or not signature_header:
            return False

        expected_signature = hmac.new(
            webhook_secret.encode('utf-8'),
            msg=request_data,
            digestmod=hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature_header, expected_signature)
    except Exception as e:
        logger.error(f"GitLab signature verification failed: {str(e)}")
        return False

@app.route('/api/v1/gitlab/webhook', methods=['POST'])
def gitlab_webhook():
    """Handle GitLab webhook events"""
    try:
        signature = request.headers.get('X-Gitlab-Token')
        if not verify_gitlab_webhook_signature(request.get_data(), signature):
            return jsonify({'error': 'Invalid signature'}), 401

        event_type = request.headers.get('X-Gitlab-Event')
        event_data = request.get_json()

        if event_type == 'Push Hook':
            project_id = event_data.get('project', {}).get('id')
            project_url = event_data.get('project', {}).get('web_url')
            user_id = event_data.get('user_id')

            if not all([project_id, project_url, user_id]):
                return jsonify({'error': 'Missing required information'}), 400

            # Import the handler when needed
            from gitlab_scanner import scan_gitlab_repository_handler
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            loop.run_until_complete(scan_gitlab_repository_handler(
                project_url=project_url,
                access_token=os.getenv('GITLAB_TOKEN'),
                user_id=str(user_id)
            ))

        return jsonify({'success': True})

    except Exception as e:
        logger.error(f"GitLab webhook error: {str(e)}")
        return jsonify({'error': str(e)}), 500
@app.route('/api/v1/gitlab/oauth/callback')
def gitlab_oauth_callback():
    """Handle GitLab OAuth callback"""
    try:
        code = request.args.get('code')
        if not code:
            return jsonify({'error': 'No code provided'}), 400

        # Get GitLab environment variables
        GITLAB_APP_ID = os.getenv('GITLAB_APP_ID')
        GITLAB_APP_SECRET = os.getenv('GITLAB_APP_SECRET')
        GITLAB_CALLBACK_URL = os.getenv('GITLAB_CALLBACK_URL')
        
        if not all([GITLAB_APP_ID, GITLAB_APP_SECRET, GITLAB_CALLBACK_URL]):
            return jsonify({'error': 'GitLab OAuth not configured'}), 500

        # Exchange code for access token
        data = {
            'client_id': GITLAB_APP_ID,
            'client_secret': GITLAB_APP_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': GITLAB_CALLBACK_URL
        }

        response = requests.post('https://gitlab.com/oauth/token', data=data)
        if response.status_code == 200:
            token_data = response.json()
            # Get user information
            headers = {'Authorization': f"Bearer {token_data['access_token']}"}
            user_response = requests.get('https://gitlab.com/api/v4/user', headers=headers)
            
            if user_response.status_code == 200:
                user_data = user_response.json()
                frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
                from urllib.parse import urlencode
                params = urlencode({
                    'status': 'success',
                    'user_id': str(user_data['id']),
                    'platform': 'gitlab',
                    'access_token': token_data['access_token']
                })
                return redirect(f"{frontend_url}/auth/callback?{params}")
            
            return jsonify({'error': 'Failed to get user information'}), 400
        
        return jsonify({'error': 'Failed to get access token'}), 400

    except Exception as e:
        logger.error(f"GitLab OAuth error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    

@app.route('/debug/test-webhook', methods=['POST'])
def test_webhook():
    """Test endpoint to verify webhook signatures"""
    if os.getenv('FLASK_ENV') != 'production':
        try:
            webhook_secret = os.getenv('GITHUB_WEBHOOK_SECRET')
            raw_data = request.get_data()
            received_signature = request.headers.get('X-Hub-Signature-256')
            
            # Test with the exact data received
            result = verify_webhook_signature(raw_data, received_signature)
            
            # Calculate signature for debugging
            mac = hmac.new(
                webhook_secret.encode('utf-8') if isinstance(webhook_secret, str) else webhook_secret,
                msg=raw_data,
                digestmod=hashlib.sha256
            )
            expected_signature = f"sha256={mac.hexdigest()}"
            
            return jsonify({
                'webhook_secret_configured': bool(webhook_secret),
                'webhook_secret_length': len(webhook_secret) if webhook_secret else 0,
                'received_signature': received_signature,
                'expected_signature': expected_signature,
                'payload_size': len(raw_data),
                'signatures_match': result,
                'raw_data_preview': raw_data.decode('utf-8')[:100] if raw_data else None
            })
        except Exception as e:
            return jsonify({'error': str(e)})
    return jsonify({'message': 'Not available in production'}), 403

def clean_directory(directory):
    """Safely remove a directory"""
    try:
        if os.path.exists(directory):
            shutil.rmtree(directory)
    except Exception as e:
        logger.error(f"Error cleaning directory {directory}: {str(e)}")

def trigger_semgrep_analysis(repo_url, installation_token, user_id):
    """Run Semgrep analysis with enhanced error handling"""
    clone_dir = None
    repo_name = repo_url.split('github.com/')[-1].replace('.git', '')
    
    try:
        repo_url_with_auth = f"https://x-access-token:{installation_token}@github.com/{repo_name}.git"
        clone_dir = f"/tmp/semgrep_{repo_name.replace('/', '_')}_{os.getpid()}"
        
        # Create initial database entry
        analysis = AnalysisResult(
            repository_name=repo_name,
            user_id=user_id,
            status='in_progress'
        )
        db.session.add(analysis)
        db.session.commit()
        logger.info(f"Created analysis record with ID: {analysis.id}")
        
        # Clean directory first
        clean_directory(clone_dir)
        logger.info(f"Cloning repository to {clone_dir}")
        
        # Enhanced clone command with detailed error capture
        try:
            # First verify the repository exists and is accessible
            test_url = f"https://api.github.com/repos/{repo_name}"
            headers = {
                'Authorization': f'Bearer {installation_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            logger.info(f"Verifying repository access: {test_url}")
            
            response = requests.get(test_url, headers=headers)
            if response.status_code != 200:
                raise ValueError(f"Repository verification failed: {response.status_code} - {response.text}")
            
            # Clone with more detailed error output
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url_with_auth, clone_dir],
                capture_output=True,
                text=True
            )
            
            if clone_result.returncode != 0:
                error_msg = (
                    f"Git clone failed with return code {clone_result.returncode}\n"
                    f"STDERR: {clone_result.stderr}\n"
                    f"STDOUT: {clone_result.stdout}"
                )
                logger.error(error_msg)
                raise Exception(error_msg)
                
            logger.info(f"Repository cloned successfully: {repo_name}")
            
            # Run semgrep analysis
            semgrep_cmd = ["semgrep", "--config=auto", "--json", "."]
            logger.info(f"Running semgrep with command: {' '.join(semgrep_cmd)}")
            
            semgrep_process = subprocess.run(
                semgrep_cmd,
                capture_output=True,
                text=True,
                check=True,
                cwd=clone_dir
            )
            
            try:
                semgrep_output = json.loads(semgrep_process.stdout)
                analysis.status = 'completed'
                analysis.results = semgrep_output
                db.session.commit()
                
                logger.info(f"Semgrep analysis completed successfully for {repo_name}")
                return semgrep_process.stdout
                
            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse Semgrep output: {str(e)}"
                logger.error(error_msg)
                analysis.status = 'failed'
                analysis.error = error_msg
                db.session.commit()
                return None

        except subprocess.CalledProcessError as e:
            error_msg = (
                f"Command '{' '.join(e.cmd)}' failed with return code {e.returncode}\n"
                f"STDERR: {e.stderr}\n"
                f"STDOUT: {e.stdout}"
            )
            logger.error(error_msg)
            if 'analysis' in locals():
                analysis.status = 'failed'
                analysis.error = error_msg
                db.session.commit()
            raise Exception(error_msg)

    except Exception as e:
        logger.error(f"Analysis error for {repo_name}: {str(e)}")
        if 'analysis' in locals():
            analysis.status = 'failed'
            analysis.error = str(e)
            db.session.commit()
        return None
        
    finally:
        if clone_dir:
            clean_directory(clone_dir)

def format_semgrep_results(raw_results):
    """Format Semgrep results for frontend"""
    try:
        # Handle string input
        if isinstance(raw_results, str):
            try:
                results = json.loads(raw_results)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON results: {str(e)}")
                return {
                    'summary': {
                        'total_files_scanned': 0,
                        'total_findings': 0,
                        'files_scanned': [],
                        'semgrep_version': 'unknown',
                        'scan_status': 'failed'
                    },
                    'findings': [],
                    'findings_by_severity': {
                        'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
                    },
                    'findings_by_category': {},
                    'errors': [f"Failed to parse results: {str(e)}"],
                    'severity_counts': {},
                    'category_counts': {}
                }
        else:
            results = raw_results

        if not isinstance(results, dict):
            raise ValueError(f"Invalid results format: expected dict, got {type(results)}")

        formatted_response = {
            'summary': {
                'total_files_scanned': len(results.get('paths', {}).get('scanned', [])),
                'total_findings': len(results.get('results', [])),
                'files_scanned': results.get('paths', {}).get('scanned', []),
                'semgrep_version': results.get('version', 'unknown'),
                'scan_status': 'success' if not results.get('errors') else 'completed_with_errors'
            },
            'findings': [],
            'findings_by_severity': {
                'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
            },
            'findings_by_category': {},
            'errors': results.get('errors', [])
        }

        for finding in results.get('results', []):
            try:
                severity = finding.get('extra', {}).get('severity', 'INFO')
                category = finding.get('extra', {}).get('metadata', {}).get('category', 'uncategorized')
                
                formatted_finding = {
                    'id': finding.get('check_id', 'unknown'),
                    'file': finding.get('path', 'unknown'),
                    'line_start': finding.get('start', {}).get('line', 0),
                    'line_end': finding.get('end', {}).get('line', 0),
                    'code_snippet': finding.get('extra', {}).get('lines', ''),
                    'message': finding.get('extra', {}).get('message', ''),
                    'severity': severity,
                    'category': category,
                    'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                    'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                    'fix_recommendations': {
                        'description': finding.get('extra', {}).get('metadata', {}).get('message', ''),
                        'references': finding.get('extra', {}).get('metadata', {}).get('references', [])
                    }
                }

                formatted_response['findings'].append(formatted_finding)
                
                if severity not in formatted_response['findings_by_severity']:
                    formatted_response['findings_by_severity'][severity] = []
                formatted_response['findings_by_severity'][severity].append(formatted_finding)
                
                if category not in formatted_response['findings_by_category']:
                    formatted_response['findings_by_category'][category] = []
                formatted_response['findings_by_category'][category].append(formatted_finding)
                
            except Exception as e:
                logger.error(f"Error processing finding: {str(e)}")
                formatted_response['errors'].append(f"Error processing finding: {str(e)}")

        formatted_response['severity_counts'] = {
            severity: len(findings)
            for severity, findings in formatted_response['findings_by_severity'].items()
        }

        formatted_response['category_counts'] = {
            category: len(findings)
            for category, findings in formatted_response['findings_by_category'].items()
        }

        return formatted_response

    except Exception as e:
        logger.error(f"Error formatting results: {str(e)}")
        return {
            'summary': {
                'total_files_scanned': 0,
                'total_findings': 0,
                'files_scanned': [],
                'semgrep_version': 'unknown',
                'scan_status': 'failed'
            },
            'findings': [],
            'findings_by_severity': {
                'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
            },
            'findings_by_category': {},
            'errors': [f"Failed to format results: {str(e)}"],
            'severity_counts': {},
            'category_counts': {}
        }

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL')
engine = configure_app_db(app, DATABASE_URL)

# Initialize database
db.init_app(app)

# Create an event loop for async operations
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

# Database initialization
with app.app_context():
    try:
        def init_db():
            # Create tables if they don't exist
            db.create_all()
            logger.info("Database tables created successfully!")

            # Test database connection
            db.session.execute(text('SELECT 1'))
            db.session.commit()
            logger.info("Database connection successful")
            
            # Check and add columns
            check_and_add_columns()
       
        for attempt in range(3):  # 3 retries
            try:
                init_db()
                logger.info("Database initialization successful")
                break
            except Exception as e:
                if attempt == 2:  # Last attempt
                    logger.error(f"Failed to initialize database after retries: {str(e)}")
                    raise
                logger.warning(f"Database operation failed, attempt {attempt + 1} of 3")
                time.sleep(1)
                
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise
    finally:
        db.session.remove()

# Initialize GitHub integration
try:
    # GitHub Verification
    APP_ID = os.getenv('GITHUB_APP_ID')
    WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
    PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
    
    # GitLab Verification 
    GITLAB_APP_ID = os.getenv('GITLAB_APP_ID')
    GITLAB_APP_SECRET = os.getenv('GITLAB_APP_SECRET')
    GITLAB_WEBHOOK_SECRET = os.getenv('GITLAB_WEBHOOK_SECRET')
    GITLAB_CALLBACK_URL = os.getenv('GITLAB_CALLBACK_URL')
    
    if not all([APP_ID, WEBHOOK_SECRET, PRIVATE_KEY]):
        logger.warning("Missing required GitHub environment variables")
    
    if not all([GITLAB_APP_ID, GITLAB_APP_SECRET, GITLAB_WEBHOOK_SECRET, GITLAB_CALLBACK_URL]):
        logger.warning("Missing required GitLab environment variables")
    
    formatted_key = format_private_key(PRIVATE_KEY)
    git_integration = GithubIntegration(
        integration_id=int(APP_ID),
        private_key=formatted_key,
    )
    logger.info("GitHub Integration initialized successfully")
    logger.info("GitLab configuration verified")
except Exception as e:
    logger.error(f"Configuration error: {str(e)}")

def create_app():
    """Factory function for Gunicorn"""
    return socketio.run(app, host='0.0.0.0', port=10000)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    port = int(os.getenv('PORT', 10000))
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=port, 
        debug=True,
        use_reloader=False  
    )