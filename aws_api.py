from flask import Blueprint, jsonify, request
from sqlalchemy import func, desc, create_engine
from sqlalchemy.orm import sessionmaker
from models import db, CloudScan
from datetime import datetime
import logging
import asyncio
import threading
import traceback
from aws_scanner import scan_aws_account_handler, AwsCredentialValidator
from db_utils import create_db_engine
from collections import defaultdict
from sqlalchemy import text
import json
import os
import subprocess
import boto3
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def create_api_engine():
    """Create database engine for API routes"""
    return create_db_engine()

# Create Blueprint
aws_bp = Blueprint('aws', __name__, url_prefix='/api/v1/aws')

@aws_bp.route('/scan', methods=['POST'])
def trigger_aws_scan():
    """Trigger an AWS CIS benchmark scan using Steampipe"""
    # Get data from POST request body
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    # Get required parameters
    user_id = request_data.get('user_id')
    account_id = request_data.get('account_id')
    credentials = request_data.get('credentials', {})
    
    # Validate required parameters
    required_params = {
        'user_id': user_id
    }
    
    missing_params = [param for param, value in required_params.items() if not value]
    if missing_params:
        return jsonify({
            'success': False,
            'error': {
                'message': f'Missing required parameters: {", ".join(missing_params)}',
                'code': 'INVALID_PARAMETERS'
            }
        }), 400
    
    # Validate AWS credentials
    required_creds = ['aws_access_key_id', 'aws_secret_access_key']
    missing_creds = [cred for cred in required_creds if not credentials.get(cred)]
    if missing_creds:
        return jsonify({
            'success': False,
            'error': {
                'message': f'Missing required AWS credentials: {", ".join(missing_creds)}',
                'code': 'INVALID_CREDENTIALS'
            }
        }), 400
    
    # If account_id wasn't provided, derive it from the credentials
    if not account_id:
        try:
            session = boto3.Session(
                aws_access_key_id=credentials.get('aws_access_key_id', '').strip(),
                aws_secret_access_key=credentials.get('aws_secret_access_key', '').strip(),
                aws_session_token=credentials.get('aws_session_token', '').strip() or None
            )
            sts_client = session.client('sts')
            identity = sts_client.get_caller_identity()
            account_id = identity.get("Account")
            logger.info(f"Derived AWS account ID: {account_id}")
        except Exception as e:
            return jsonify({
                'success': False,
                'error': {
                    'message': f'Could not determine AWS account ID: {str(e)}',
                    'code': 'CREDENTIAL_ERROR'
                }
            }), 400
    
    # Create database session
    engine = create_api_engine()
    Session = sessionmaker(bind=engine)
    db_session = Session()
    analysis = None
    
    try:
        # Create analysis record
        analysis = CloudScan(
            user_id=user_id,
            cloud_provider='aws',
            account_id=account_id,
            status='queued' 
        )
        db_session.add(analysis)
        db_session.commit()
        logger.info(f"Created analysis record with ID: {analysis.id}")
        
        # Start scan in background thread
        def run_scan_in_background():
            # Set credentials directly from the request for this scan session
            os.environ['AWS_ACCESS_KEY_ID'] = credentials.get('aws_access_key_id', '').strip()
            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.get('aws_secret_access_key', '').strip()
            if 'aws_session_token' in credentials:
                os.environ['AWS_SESSION_TOKEN'] = credentials.get('aws_session_token', '').strip()
                
            try:
                # Update AWS connection configuration to use these credentials
                # Use /bin/bash explicitly to execute the script
                result = subprocess.run(['/bin/bash', '/home/steampipe/scripts/update_aws_connection.sh'], 
                                      check=False, capture_output=True, text=True)
                logger.info(f"Connection configuration update result: {result.returncode}")
                if result.stdout:
                    logger.info(f"Connection update output: {result.stdout}")
                if result.stderr:
                    logger.warning(f"Connection update stderr: {result.stderr}")
                
                # Update status to in_progress
                analysis.status = 'in_progress'
                db_session.commit()
                
                # Run scan
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(scan_aws_account_handler(
                    user_id=user_id,
                    account_id=account_id,
                    credentials=credentials,
                    db_session=db_session,
                    scan_record=analysis
                ))
                loop.close()
            except Exception as e:
                # Handle errors
                logger.error(f"Background scan error: {str(e)}")
                analysis.status = 'error'
                analysis.error = str(e)
                db_session.commit()
        
        # Start the background thread
        thread = threading.Thread(target=run_scan_in_background)
        thread.daemon = True
        thread.start()
        
        # Return immediately with instructions to poll progress
        return jsonify({
            'success': True,
            'message': 'AWS CIS benchmark scan queued successfully',
            'scan_id': analysis.id,
            'status': 'queued',
            'account_id': account_id
        }), 202  
        
    except Exception as e:
        logger.error(f"Scan initialization error: {str(e)}")
        logger.error(traceback.format_exc())
        
        if analysis and db_session:
            try:
                analysis.status = 'error'
                analysis.error = str(e)
                db_session.commit()
            except Exception as commit_error:
                logger.error(f"Failed to update analysis status: {str(commit_error)}")
                db_session.rollback()
        
        return jsonify({
            'success': False,
            'error': {
                'message': str(e),
                'code': 'SCAN_ERROR'
            }
        }), 500
    finally:
        if db_session:
            db_session.close()


@aws_bp.route('/scans/<user_id>', methods=['GET'])
def get_user_scans(user_id):
    """Get all AWS CIS benchmark scans for a user with optional account filtering"""
    try:
        # Get query parameters for filtering
        account_id = request.args.get('account_id')  # Make account_id an optional filter
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('limit', 30))))
        
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        try:
            # Build query with user_id
            query = db_session.query(CloudScan).filter(
                CloudScan.user_id == user_id
            )
            
            # Add account_id filter if provided
            if account_id:
                query = query.filter(CloudScan.account_id == account_id)
                
            # Apply sorting
            query = query.order_by(desc(CloudScan.created_at))
            
            # Count total
            total_scans = query.count()
            
            # Apply pagination
            scans = query.limit(per_page).offset((page - 1) * per_page).all()
            
            # Format response
            scan_list = []
            for scan in scans:
                findings = scan.findings or {}
                stats = findings.get('stats', {})
                
                # CRITICAL FIX: Calculate the correct total_findings 
                # The total should be the sum of all status-based findings
                if 'failed_findings' in stats and 'pass_findings' in stats and 'warning_findings' in stats and 'skip_findings' in stats:
                    total_findings = (
                        stats.get('failed_findings', 0) + 
                        stats.get('pass_findings', 0) + 
                        stats.get('warning_findings', 0) + 
                        stats.get('skip_findings', 0)
                    )
                    # Update the total_findings to the correct sum
                    stats['total_findings'] = total_findings
                
                scan_data = {
                    'id': scan.id,
                    'account_id': scan.account_id,
                    'cloud_provider': scan.cloud_provider,
                    'status': scan.status,
                    'created_at': scan.created_at.isoformat(),
                    'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                    'summary': {
                        'total_findings': stats.get('total_findings', 0),
                        'failed_findings': stats.get('failed_findings', 0),
                        'warning_findings': stats.get('warning_findings', 0),
                        'pass_findings': stats.get('pass_findings', 0),
                        'severity_counts': stats.get('severity_counts', {})
                    } if stats else None,
                    'error': scan.error
                }
                
                scan_list.append(scan_data)
                
            return jsonify({
                'success': True,
                'data': {
                    'benchmark': 'CIS AWS Foundations Benchmark v1.4',
                    'scans': scan_list,
                    'pagination': {
                        'current_page': page,
                        'per_page': per_page,
                        'total_items': total_scans,
                        'total_pages': (total_scans + per_page - 1) // per_page
                    },
                    'filters': {
                        'account_id': account_id if account_id else None
                    }
                }
            })
            
        finally:
            db_session.close()
            
    except Exception as e:
        logger.error(f"Error getting user scans: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500
    
@aws_bp.route('/scans/<user_id>/list', methods=['GET'])
def list_user_scans(user_id):
    """Get a paginated list of AWS CIS benchmark scans for a user"""
    try:
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        try:
            # Get query parameters with defaults
            page = max(1, int(request.args.get('page', 1)))
            per_page = min(100, max(1, int(request.args.get('limit', 30))))
            sort_by = request.args.get('sort_by', 'created_at')
            sort_order = request.args.get('sort_order', 'desc')
            
            # Validate sort parameters
            valid_sort_fields = ['created_at', 'account_id', 'status', 'completed_at']
            if sort_by not in valid_sort_fields:
                sort_by = 'created_at'
                
            valid_sort_orders = ['asc', 'desc']
            if sort_order not in valid_sort_orders:
                sort_order = 'desc'
                
            # Build query
            query = db_session.query(CloudScan).filter(
                CloudScan.user_id == user_id
            )
            
            # Apply sorting
            if sort_order == 'asc':
                query = query.order_by(getattr(CloudScan, sort_by).asc())
            else:
                query = query.order_by(getattr(CloudScan, sort_by).desc())
            
            # Count total scans
            total_scans = query.count()
            
            # Apply pagination
            scans = query.limit(per_page).offset((page - 1) * per_page).all()
            
            # Format response
            scan_list = []
            for scan in scans:
                findings = scan.findings or {}
                stats = findings.get('stats', {})
                
                # CRITICAL FIX: Calculate the correct total_findings 
                # The total should be the sum of all status-based findings
                if 'failed_findings' in stats and 'pass_findings' in stats and 'warning_findings' in stats and 'skip_findings' in stats:
                    total_findings = (
                        stats.get('failed_findings', 0) + 
                        stats.get('pass_findings', 0) + 
                        stats.get('warning_findings', 0) + 
                        stats.get('skip_findings', 0)
                    )
                    # Update the total_findings to the correct sum
                    stats['total_findings'] = total_findings
                
                scan_data = {
                    'id': scan.id,
                    'account_id': scan.account_id,
                    'cloud_provider': scan.cloud_provider,
                    'status': scan.status,
                    'created_at': scan.created_at.isoformat() if scan.created_at else None,
                    'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                    'summary': {
                        'total_findings': stats.get('total_findings', 0),
                        'failed_findings': stats.get('failed_findings', 0),
                        'warning_findings': stats.get('warning_findings', 0),
                        'pass_findings': stats.get('pass_findings', 0),
                        'severity_counts': stats.get('severity_counts', {})
                    } if stats else None,
                    'error': scan.error
                }
                
                scan_list.append(scan_data)
                
            # Build pagination info
            total_pages = (total_scans + per_page - 1) // per_page if total_scans > 0 else 1
            
            pagination = {
                'current_page': page,
                'per_page': per_page,
                'total_items': total_scans,
                'total_pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1
            }
            
            return jsonify({
                'success': True,
                'data': {
                    'scans': scan_list,
                    'pagination': pagination,
                    'user_id': user_id,
                    'benchmark': 'CIS AWS Foundations Benchmark v1.4'
                }
            })
            
        finally:
            db_session.close()
            
    except Exception as e:
        logger.error(f"Error getting user scans: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500

@aws_bp.route('/scans/<scan_id>/result', methods=['GET'])
def get_scan_result(scan_id):
    
    try:
        # Create database session with direct connection to avoid stale data
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        try:
            # Use a raw SQL query to bypass any caching issues
            raw_query = text("""
                SELECT id, user_id, cloud_provider, account_id, status, 
                       created_at, completed_at, findings, error 
                FROM cloud_scans 
                WHERE id = :scan_id
            """)
            
            result = db_session.execute(raw_query, {'scan_id': scan_id}).fetchone()
            
            if not result:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'Scan not found',
                        'code': 'SCAN_NOT_FOUND'
                    }
                }), 404
            
            # Convert result to dictionary
            column_names = ['id', 'user_id', 'cloud_provider', 'account_id', 'status', 
                            'created_at', 'completed_at', 'findings', 'error']
            scan_dict = dict(zip(column_names, result))
            
            # Log detailed diagnostics
            logger.info(f"Scan {scan_id} status: {scan_dict.get('status')}")
            logger.info(f"Scan {scan_id} has findings: {bool(scan_dict.get('findings'))}")
            logger.info(f"Scan {scan_id} completed_at: {scan_dict.get('completed_at')}")
            
            # Check if scan is actually completed based on multiple indicators
            is_actually_completed = (
                scan_dict.get('status') == 'completed' or 
                (scan_dict.get('completed_at') is not None and 
                 scan_dict.get('findings') is not None and
                 len(scan_dict.get('findings', {}).get('findings', [])) > 0)
            )
            
            # If the scan is actually completed but status doesn't show it,
            # update the status first
            if is_actually_completed and scan_dict.get('status') != 'completed':
                logger.info(f"Scan {scan_id} appears complete but status is {scan_dict.get('status')} - fixing")
                update_query = text("""
                    UPDATE cloud_scans
                    SET status = 'completed'
                    WHERE id = :scan_id
                """)
                db_session.execute(update_query, {'scan_id': scan_id})
                db_session.commit()
                scan_dict['status'] = 'completed'
            
            # If scan is completed, return full findings
            if is_actually_completed:
                findings_data = scan_dict.get('findings', {})
                
                # Ensure we have severity counts for all severity levels
                if 'stats' in findings_data:
                    stats = findings_data['stats']
                    
                    # CRITICAL FIX: Calculate the correct total_findings
                    # The total should be the sum of all status-based findings
                    if 'failed_findings' in stats and 'pass_findings' in stats and 'warning_findings' in stats and 'skip_findings' in stats:
                        total_findings = (
                            stats.get('failed_findings', 0) + 
                            stats.get('pass_findings', 0) + 
                            stats.get('warning_findings', 0) + 
                            stats.get('skip_findings', 0)
                        )
                        # Update the total_findings to the correct sum
                        stats['total_findings'] = total_findings
                        
                        # Double-check that the severity counts sum matches the total
                        severity_total = sum(stats.get('severity_counts', {}).values())
                        if severity_total != total_findings:
                            logger.warning(f"Severity counts sum ({severity_total}) doesn't match total findings ({total_findings})")
                
                return jsonify({
                    'success': True,
                    'data': {
                        'id': scan_dict.get('id'),
                        'account_id': scan_dict.get('account_id'),
                        'cloud_provider': scan_dict.get('cloud_provider'),
                        'status': 'completed',
                        'created_at': scan_dict.get('created_at').isoformat() if scan_dict.get('created_at') else None,
                        'completed_at': scan_dict.get('completed_at').isoformat() if scan_dict.get('completed_at') else None,
                        'findings': findings_data
                    }
                })
            
            # If not completed, return in-progress status
            return jsonify({
                'success': True,
                'data': {
                    'id': scan_dict.get('id'),
                    'account_id': scan_dict.get('account_id'),
                    'cloud_provider': scan_dict.get('cloud_provider'),
                    'status': scan_dict.get('status', 'in_progress'),
                    'created_at': scan_dict.get('created_at').isoformat() if scan_dict.get('created_at') else None,
                    'message': 'Scan is still in progress',
                    'error': scan_dict.get('error')
                }
            })
        
        finally:
            db_session.close()
    
    except Exception as e:
        logger.error(f"Error retrieving scan result: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to retrieve scan result',
                'details': str(e)
            }
        }), 500


@aws_bp.route('/scans/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a specific AWS CIS benchmark scan"""
    try:
        # Get user_id from query parameter
        user_id = request.args.get('user_id')
        
        if not user_id:
            return jsonify({
                'success': False,
                'error': {'message': 'user_id is required'}
            }), 400
            
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        try:
            # Get the scan record
            scan = db_session.query(CloudScan).filter(
                CloudScan.id == scan_id,
                CloudScan.user_id == user_id
            ).first()
            
            if not scan:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'Scan not found',
                        'code': 'SCAN_NOT_FOUND'
                    }
                }), 404
                
            # Delete the scan
            db_session.delete(scan)
            db_session.commit()
            
            return jsonify({
                'success': True,
                'message': 'CIS benchmark scan deleted successfully'
            })
            
        finally:
            db_session.close()
            
    except Exception as e:
        logger.error(f"Error deleting scan: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500

@aws_bp.route('/security/summary/<user_id>', methods=['GET'])
def get_security_summary(user_id):
    """Get CIS benchmark security summary across all AWS accounts for a user"""
    try:
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        try:
            # Get all completed scans for this user
            scans = db_session.query(CloudScan).filter(
                CloudScan.user_id == user_id,
                CloudScan.status == 'completed',
                CloudScan.findings.isnot(None)
            ).order_by(
                desc(CloudScan.created_at)
            ).all()
            
            if not scans:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'No completed CIS benchmark scans found',
                        'code': 'NO_SCANS_FOUND'
                    }
                }), 404
                
            # Get latest scan per account
            latest_scans = {}
            for scan in scans:
                account_id = scan.account_id
                if account_id not in latest_scans:
                    latest_scans[account_id] = scan
            
            # Compile statistics
            total_findings = 0
            total_failed = 0
            total_warning = 0
            total_passed = 0
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            account_summaries = {}
            latest_scan_time = None
            
            for account_id, scan in latest_scans.items():
                findings = scan.findings or {}
                stats = findings.get('stats', {})
                
                # Count findings
                account_total = stats.get('total_findings', 0)
                account_failed = stats.get('failed_findings', 0)
                account_warning = stats.get('warning_findings', 0)
                account_passed = stats.get('pass_findings', 0)
                
                total_findings += account_total
                total_failed += account_failed
                total_warning += account_warning
                total_passed += account_passed
                
                # Aggregate severity counts
                for severity, count in stats.get('severity_counts', {}).items():
                    severity_counts[severity] += count
                    
                # Aggregate category counts
                for category, count in stats.get('category_counts', {}).items():
                    category_counts[category] += count
                
                # Build account summary
                account_summaries[account_id] = {
                    'account_id': account_id,
                    'last_scan_id': scan.id,
                    'last_scan_time': scan.completed_at.isoformat() if scan.completed_at else None,
                    'findings': {
                        'total': account_total,
                        'failed': account_failed,
                        'warning': account_warning,
                        'passed': account_passed
                    },
                    'severity_counts': stats.get('severity_counts', {}),
                    'cis_compliance_percentage': _calculate_compliance_percentage(stats)
                }
                
                # Track latest scan time
                if scan.completed_at:
                    if not latest_scan_time or scan.completed_at > latest_scan_time:
                        latest_scan_time = scan.completed_at
            
            # Calculate overall compliance percentage
            overall_compliance = 0
            if total_findings > 0:
                overall_compliance = round((total_passed / total_findings) * 100, 1)
            
            return jsonify({
                'success': True,
                'data': {
                    'user_id': user_id,
                    'benchmark': 'CIS AWS Foundations Benchmark v1.4',
                    'summary': {
                        'total_accounts': len(latest_scans),
                        'total_findings': total_findings,
                        'failed_findings': total_failed,
                        'warning_findings': total_warning,
                        'passed_findings': total_passed,
                        'severity_counts': dict(severity_counts),
                        'category_counts': dict(category_counts),
                        'last_scan_time': latest_scan_time.isoformat() if latest_scan_time else None,
                        'overall_compliance_percentage': overall_compliance
                    },
                    'accounts': account_summaries
                }
            })
            
        finally:
            db_session.close()
            
    except Exception as e:
        logger.error(f"Error getting security summary: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500
    

@aws_bp.route('/validate-credentials', methods=['POST'])
def validate_aws_credentials():
    """
    Validate AWS credentials by performing multiple checks
    
    Expected JSON payload:
    {
        "aws_access_key_id": "...",
        "aws_secret_access_key": "...",
        "aws_session_token": "..." (optional)
    }
    """
    # Get credentials from request
    credentials = request.get_json()
    if not credentials:
        return jsonify({
            'success': False,
            'error': {
                'message': 'Request body is required',
                'code': 'INVALID_REQUEST'
            }
        }), 400
    
    # Validate required credentials
    required_creds = ['aws_access_key_id', 'aws_secret_access_key']
    missing_creds = [cred for cred in required_creds if not credentials.get(cred)]
    if missing_creds:
        return jsonify({
            'success': False,
            'error': {
                'message': f'Missing required credentials: {", ".join(missing_creds)}',
                'code': 'MISSING_CREDENTIALS'
            }
        }), 400
    
    try:
        # Create a session with the provided credentials
        session = boto3.Session(
            aws_access_key_id=credentials['aws_access_key_id'].strip(),
            aws_secret_access_key=credentials['aws_secret_access_key'].strip(),
            aws_session_token=credentials.get('aws_session_token', '').strip() or None
        )
        
        # Validation results dictionary
        validation_results = {
            "valid": False,
            "account_id": None,
            "caller_identity": None,
            "regions_accessible": [],
            "services_accessible": {},
            "errors": [],
            "diagnostic_info": {}
        }
        
        # Test STS (Security Token Service)
        try:
            sts_client = session.client('sts')
            identity = sts_client.get_caller_identity()
            
            validation_results["valid"] = True
            validation_results["account_id"] = identity.get("Account")
            validation_results["caller_identity"] = {
                "user_id": identity.get("UserId"),
                "account_id": identity.get("Account"),
                "arn": identity.get("Arn")
            }
            logger.info(f"Successfully authenticated as: {identity.get('Arn')}")
        except ClientError as e:
            error_message = f"STS validation error: {str(e)}"
            logger.error(error_message)
            validation_results["errors"].append(error_message)
            validation_results["diagnostic_info"]["sts_error"] = str(e)
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Authentication failed',
                    'details': error_message
                }
            }), 401
        
        # Check available regions
        try:
            ec2_client = session.client('ec2', region_name='us-east-1')
            regions_response = ec2_client.describe_regions()
            validation_results["regions_accessible"] = [
                region['RegionName'] for region in regions_response['Regions']
            ]
        except ClientError as e:
            validation_results["errors"].append(f"Error accessing regions: {str(e)}")
        
        # Test access to common services
        # IMPORTANT: The problem is here - you need to specify a region
        services_to_test = [
            ('ec2', 'us-east-1'),
            ('s3', None),  # S3 is global
            ('iam', None),  # IAM is global
            ('cloudtrail', 'us-east-1'),
        ]
        
        for service, region in services_to_test:
            try:
                # THIS IS THE LINE THAT'S FAILING (line 649 in your error)
                # You need to specify a region for region-specific services
                if region:
                    client = session.client(service, region_name=region)
                else:
                    client = session.client(service)
                
                # Check service-specific operations
                if service == 'ec2':
                    client.describe_instances(MaxResults=1)
                elif service == 's3':
                    client.list_buckets()
                elif service == 'iam':
                    client.list_users(MaxItems=1)
                elif service == 'cloudtrail':
                    client.describe_trails()
                
                validation_results["services_accessible"][service] = True
            except ClientError as e:
                validation_results["services_accessible"][service] = False
                validation_results["errors"].append(f"Cannot access {service} service")
                validation_results["diagnostic_info"][f"{service}_error"] = str(e)
        
        # Prepare response
        return jsonify({
            'success': True,
            'data': {
                'account_id': validation_results['account_id'],
                'caller_identity': validation_results['caller_identity'],
                'regions_accessible': validation_results['regions_accessible'],
                'services_accessible': validation_results['services_accessible']
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Unexpected credential validation error: {str(e)}")
        logger.error(traceback.format_exc())
        
        return jsonify({
            'success': False,
            'error': {
                'message': 'Unexpected error during credential validation',
                'code': 'VALIDATION_ERROR',
                'details': str(e)
            }
        }), 500
    
@aws_bp.route('/scans/<scan_id>/reranked', methods=['GET'])
def get_reranked_aws_findings(scan_id):
    """Get reranked AWS security findings for a specific scan"""
    try:
        # Create database session
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        try:
            # Get the scan by ID
            scan = db_session.query(CloudScan).get(scan_id)
            
            if not scan:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'Scan not found',
                        'code': 'SCAN_NOT_FOUND'
                    }
                }), 404

            if not scan.rerank:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'No reranked results available',
                        'code': 'NO_RERANK_RESULTS'
                    }
                }), 404

            # Return just the reranked findings
            return jsonify({
                'success': True,
                'data': {
                    'scan_id': scan.id,
                    'account_id': scan.account_id,
                    'findings': scan.rerank
                }
            })
            
        finally:
            db_session.close()
            
    except Exception as e:
        logger.error(f"Error getting reranked AWS findings: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500