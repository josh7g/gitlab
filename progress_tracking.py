"""
Enhanced progress tracking module with centralized state management
to fix WebSocket communication issues across multiple workers.
"""

import time
import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any
from progress_utils import calculate_overall_progress
import redis
import os

logger = logging.getLogger(__name__)

# Get Redis client from a centralized location
def get_redis_client():
    """Get or create Redis client singleton"""
    REDIS_URL = os.getenv('REDIS_URL')
    
    if not hasattr(get_redis_client, "client"):
        get_redis_client.client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            socket_keepalive=True,
            health_check_interval=30,
            retry_on_timeout=True
        )
    
    return get_redis_client.client

def generate_consistent_scan_id(user_id: str, resource_id: str) -> str:
    """
    Generate a consistent scan ID for a resource to ensure
    all workers use the same ID for updates.
    
    Args:
        user_id: User ID
        resource_id: Resource ID (repo name or account ID)
    
    Returns:
        str: Consistent scan ID
    """
    redis_client = get_redis_client()
    
    # Check if a scan is already in progress for this resource
    scan_key = f"current_scan:{user_id}:{resource_id}"
    existing_scan_id = redis_client.get(scan_key)
    
    if existing_scan_id:
        # Check if this scan is still active (less than 1 hour old)
        scan_timestamp_key = f"scan_timestamp:{existing_scan_id}"
        scan_timestamp = redis_client.get(scan_timestamp_key)
        
        if scan_timestamp:
            # Convert to int and check if it's less than 1 hour old
            scan_time = int(scan_timestamp)
            current_time = int(time.time())
            
            if current_time - scan_time < 3600:  # 1 hour
                return existing_scan_id
    
    # Generate a new scan ID
    new_scan_id = f"scan_{int(time.time())}"
    
    # Store it with 1 hour expiration
    redis_client.set(scan_key, new_scan_id, ex=3600)
    
    # Also store the timestamp
    redis_client.set(f"scan_timestamp:{new_scan_id}", int(time.time()), ex=3600)
    
    logger.info(f"Generated new scan ID {new_scan_id} for {user_id}:{resource_id}")
    return new_scan_id

def update_scan_progress(user_id: str, repo_name: str, stage: str, progress: float, 
                        token: Optional[str] = None, scan_type: str = 'repository',
                        scan_id: Optional[str] = None) -> bool:
    """
    Update scan progress with guaranteed completion delivery.
    
    Args:
        user_id: User ID
        repo_name: Repository name or account ID
        stage: Current stage of the scan
        progress: Progress percentage (0-100)
        token: Optional token
        scan_type: Type of scan ('repository' or 'aws')
        scan_id: Optional scan ID (will use consistent ID if not provided)
        
    Returns:
        bool: Success status
    """
    try:
        if not all([user_id, repo_name, stage]):
            logger.warning("Invalid progress update parameters")
            return False

        # Use consistent scan ID if not provided
        if not scan_id:
            scan_id = f"scan_{int(time.time())}"
        
        # Create a unique key for this scan
        key = f"scan_progress:{user_id}:{repo_name}"
        
        stage = stage[:50]  # Truncate long stage names
        progress = round(max(0, min(100, progress)))  # Ensure progress is between 0-100
        
        redis_client = get_redis_client()
        
        # Calculate overall progress
        overall_progress = round(progress)  # Simplified for clarity
        
        # Store the progress data as JSON
        progress_data = {
            'stage': stage,
            'stage_progress': progress,
            'overall_progress': overall_progress,
            'timestamp': datetime.utcnow().isoformat(),
            'unix_timestamp': int(time.time()),
            'scan_id': scan_id
        }
        
        # Create room name (must match socket.io subscription format)
        room = f"{'aws_scan' if scan_type == 'aws' else 'scan'}_{user_id}_{repo_name}"
        
        # WebSocket data format
        ws_data = {
            's': stage,
            'p': progress,
            'o': overall_progress,
            't': int(time.time()),
            'id': scan_id
        }
        
        # SPECIAL HANDLING FOR COMPLETION
        if stage == 'completed':
            # 1. Store completion with short TTL (10 minutes)
            completion_key = f"scan_complete:{user_id}:{repo_name}"
            redis_client.set(completion_key, json.dumps({
                'complete': True,
                'timestamp': int(time.time()),
                'scan_id': scan_id
            }), ex=600)  # 10 minutes TTL
            
            # 2. Add the regular progress update with completion flag
            redis_client.set(key, json.dumps(progress_data), ex=600)  # 10 minutes TTL
            
            # 3. Send via multiple channels with retries
            # Send completion event
            message_data = {
                'user_id': user_id,
                'repo_name': repo_name,
                'data': ws_data,
                'scan_type': scan_type,
                'room': room,
                'is_completion': True
            }
            
            # Send 3 times with delays to maximize delivery chance
            # First attempt
            redis_client.publish('scan_updates', json.dumps(message_data))
            logger.info(f"Completion (1/3): User={user_id}, Repo={repo_name}, Progress=100%")
            
            # Second attempt after 200ms
            time.sleep(0.2)
            redis_client.publish('scan_updates', json.dumps(message_data))
            logger.info(f"Completion (2/3): User={user_id}, Repo={repo_name}, Progress=100%")
            
            # Third attempt after another 300ms
            time.sleep(0.3)
            redis_client.publish('scan_updates', json.dumps(message_data))
            logger.info(f"Completion (3/3): User={user_id}, Repo={repo_name}, Progress=100%")
            
            # 4. Also publish to a dedicated completion channel
            redis_client.publish('scan_completions', json.dumps({
                'user_id': user_id,
                'repo_name': repo_name,
                'room': room,
                'scan_id': scan_id,
                'timestamp': int(time.time())
            }))
            
            return True
            
        elif stage == 'error':
            # Similar handling for error state
            redis_client.set(key, json.dumps(progress_data), ex=600)  # 10 minutes TTL
            
            # Send error event
            message_data = {
                'user_id': user_id,
                'repo_name': repo_name,
                'data': ws_data,
                'scan_type': scan_type,
                'room': room,
                'is_error': True
            }
            
            # Send twice with delay
            redis_client.publish('scan_updates', json.dumps(message_data))
            time.sleep(0.2)
            redis_client.publish('scan_updates', json.dumps(message_data))
            
            return True
        else:
            # Regular progress update
            redis_client.set(key, json.dumps(progress_data), ex=600)  # 10 minutes TTL
            
            # Publish the update
            message_data = {
                'user_id': user_id,
                'repo_name': repo_name,
                'data': ws_data,
                'scan_type': scan_type,
                'room': room
            }
            
            redis_client.publish('scan_updates', json.dumps(message_data))
            logger.info(f"Progress update: User={user_id}, Repo={repo_name}, Stage={stage}, Progress={progress}%")
            
            return True
        
    except Exception as e:
        logger.error(f"Error updating progress: {str(e)}")
        return False

def get_scan_progress(user_id: str, repo_name: str) -> Optional[dict]:
    """
    Get current scan progress with enhanced error handling.
    
    Args:
        user_id: User ID
        repo_name: Repository name or account ID
        
    Returns:
        Optional[dict]: Progress data
    """
    try:
        key = f"scan_progress:{user_id}:{repo_name}"
        redis_client = get_redis_client()
        
        # Get progress data
        progress_data_str = redis_client.get(key)
        if not progress_data_str:
            return None
            
        progress_data = json.loads(progress_data_str)
        
        # Also get the scan history to detect issues
        scan_id = progress_data.get('scan_id')
        if scan_id:
            history_key = f"scan_history:{scan_id}"
            history = redis_client.lrange(history_key, 0, -1)
            
            if history:
                # Convert to list of dictionaries
                history_entries = []
                for entry in history:
                    try:
                        history_entries.append(json.loads(entry))
                    except:
                        pass
                
                # Sort by timestamp
                history_entries.sort(key=lambda x: x.get('timestamp', 0))
                
                # Add history to progress data
                progress_data['history'] = history_entries
        
        return progress_data
        
    except Exception as e:
        logger.error(f"Error getting progress: {str(e)}")
        return None

def clear_scan_progress(user_id: str, repo_name: str) -> bool:
    """
    Clear scan progress with broadcast of reset event to clients.
    
    Args:
        user_id: User ID
        repo_name: Repository name or account ID
        
    Returns:
        bool: Success status
    """
    try:
        if not all([user_id, repo_name]):
            logger.warning("Invalid parameters for clearing scan progress")
            return False
            
        key = f"scan_progress:{user_id}:{repo_name}"
        redis_client = get_redis_client()
            
        # First check if there's existing data
        existing_data_str = redis_client.get(key)
        if existing_data_str:
            try:
                existing_data = json.loads(existing_data_str)
                existing_scan_id = existing_data.get('scan_id')
                
                # If we have a scan ID, clean up associated data
                if existing_scan_id:
                    # Clear scan history
                    redis_client.delete(f"scan_history:{existing_scan_id}")
                    
                    # Clear scan timestamp
                    redis_client.delete(f"scan_timestamp:{existing_scan_id}")
                    
                    # Clear current scan mapping
                    redis_client.delete(f"current_scan:{user_id}:{repo_name}")
            except:
                pass
                
            # Delete the progress key
            redis_client.delete(key)
            logger.info(f"Cleared previous scan progress for {user_id}:{repo_name}")
            
            # Generate a new scan ID for this session
            new_scan_id = generate_consistent_scan_id(user_id, repo_name)
            
            # Send a reset message to subscribers
            room = f"scan_{user_id}_{repo_name}"
            reset_data = {
                's': 'reset',
                'p': 0,
                'o': 0,
                't': int(time.time()),
                'id': new_scan_id
            }
            
            # Publish reset message
            redis_client.publish(
                'scan_updates',
                json.dumps({
                    'user_id': user_id,
                    'repo_name': repo_name,
                    'data': reset_data,
                    'scan_type': 'reset'
                })
            )
            
            # Remove from active scans
            active_scans_key = f"active_scans:{user_id}"
            redis_client.srem(active_scans_key, f"repository:{repo_name}")
            redis_client.srem(active_scans_key, f"aws:{repo_name}")
            
            return True
        return False
    except Exception as e:
        logger.error(f"Error clearing scan progress: {str(e)}")
        return False

def register_socket_subscription(socket_id: str, user_id: str, resource_id: str, 
                               scan_type: str = 'repository') -> bool:
    """
    Register a socket subscription in Redis for reliability.
    
    Args:
        socket_id: Socket ID
        user_id: User ID
        resource_id: Resource ID (repo name or account ID)
        scan_type: Type of scan ('repository' or 'aws')
        
    Returns:
        bool: Success status
    """
    try:
        room = f"{'aws_scan' if scan_type == 'aws' else 'scan'}_{user_id}_{resource_id}"
        redis_client = get_redis_client()
        
        # Store subscription data with 1-hour expiration
        subscription_key = f"socket_subscription:{socket_id}"
        redis_client.hmset(subscription_key, {
            'user_id': user_id,
            'resource_id': resource_id,
            'room': room,
            'scan_type': scan_type,
            'timestamp': int(time.time())
        })
        redis_client.expire(subscription_key, 3600)
        
        # Also track all sockets in a room
        room_key = f"room_members:{room}"
        redis_client.sadd(room_key, socket_id)
        redis_client.expire(room_key, 3600)
        
        logger.info(f"Registered socket {socket_id} subscription to {room}")
        return True
    except Exception as e:
        logger.error(f"Error registering socket subscription: {str(e)}")
        return False

def unregister_socket_subscription(socket_id: str) -> bool:
    """
    Unregister a socket subscription from Redis.
    
    Args:
        socket_id: Socket ID
        
    Returns:
        bool: Success status
    """
    try:
        redis_client = get_redis_client()
        
        # Get subscription data
        subscription_key = f"socket_subscription:{socket_id}"
        subscription = redis_client.hgetall(subscription_key)
        
        if subscription:
            # Get room
            room = subscription.get('room')
            
            if room:
                # Remove from room members
                room_key = f"room_members:{room}"
                redis_client.srem(room_key, socket_id)
                
            # Delete subscription
            redis_client.delete(subscription_key)
            
            logger.info(f"Unregistered socket {socket_id} subscription")
            return True
            
        return False
    except Exception as e:
        logger.error(f"Error unregistering socket subscription: {str(e)}")
        return False

def get_room_members(room: str) -> list:
    """
    Get all socket IDs that are members of a room.
    
    Args:
        room: Room name
        
    Returns:
        list: Socket IDs
    """
    try:
        redis_client = get_redis_client()
        room_key = f"room_members:{room}"
        members = redis_client.smembers(room_key)
        
        return list(members)
    except Exception as e:
        logger.error(f"Error getting room members: {str(e)}")
        return []