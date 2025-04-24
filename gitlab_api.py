from flask import Blueprint, jsonify, request, redirect
from sqlalchemy import func, desc, create_engine
from sqlalchemy.orm import sessionmaker
from models import db, GitLabAnalysisResult
from collections import defaultdict
import os
import ssl
import fnmatch
import logging
import json
import traceback
import asyncio
import aiohttp
from pathlib import Path
import requests
from datetime import datetime, timedelta
from flask import current_app
from urllib.parse import urlencode
from db_utils import create_db_engine
from progress_tracking import update_scan_progress, clear_scan_progress
from gitlab_scanner import (
    scan_gitlab_repository_handler, 
    deduplicate_findings, 
    GitLabScanConfig, 
    GitLabSecurityScanner
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def create_api_engine():
    """Create database engine for API routes"""
    return create_db_engine(os.getenv('GITLAB_DATABASE_URL', os.getenv('DATABASE_URL')))

# Create Blueprint
gitlab_bp = Blueprint('gitlab', __name__, url_prefix='/api/v1/gitlab')

@gitlab_bp.route('/install', methods=['GET'])
def install_app():
    """Redirect to GitLab OAuth page"""
    gitlab_auth_url = (
        f"https://gitlab.com/oauth/authorize?"
        f"client_id={os.getenv('GITLAB_APP_ID')}&"
        f"redirect_uri={os.getenv('GITLAB_CALLBACK_URL')}&"
        f"response_type=code&"
        f"scope=api+read_user+read_repository"
    )
    return redirect(gitlab_auth_url)

@gitlab_bp.route('/oauth/callback')
def gitlab_oauth_callback():
    """Handle GitLab OAuth callback"""
    try:
        code = request.args.get('code')
        if not code:
            return jsonify({'error': 'No code provided'}), 400

        # Exchange code for access token
        data = {
            'client_id': os.getenv('GITLAB_APP_ID'),
            'client_secret': os.getenv('GITLAB_APP_SECRET'),
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': os.getenv('GITLAB_CALLBACK_URL')
        }

        logger.info("Exchanging code for access token")
        response = requests.post('https://gitlab.com/oauth/token', data=data)
        if response.status_code != 200:
            logger.error(f"Failed to get access token: {response.text}")
            return jsonify({'error': 'Failed to get access token'}), 400

        token_data = response.json()
        access_token = token_data['access_token']
        refresh_token = token_data.get('refresh_token')

        # Get user information
        headers = {'Authorization': f"Bearer {access_token}"}
        user_response = requests.get('https://gitlab.com/api/v4/user', headers=headers)
        
        if user_response.status_code != 200:
            logger.error(f"Failed to get user information: {user_response.text}")
            return jsonify({'error': 'Failed to get user information'}), 400

        user_data = user_response.json()
        user_id = str(user_data['id'])

        # Get user's repositories
        repos_response = requests.get(
            'https://gitlab.com/api/v4/projects',
            headers=headers,
            params={'membership': True, 'min_access_level': 30}
        )

        if repos_response.status_code == 200:
            repositories = repos_response.json()
            
            formatted_repos = [{
                'id': repo['id'],
                'name': repo['name'],
                'full_name': repo['path_with_namespace'],
                'url': repo['web_url'],
                'description': repo['description'],
                'default_branch': repo['default_branch'],
                'visibility': repo['visibility'],
                'created_at': repo['created_at'],
                'last_activity_at': repo['last_activity_at']
            } for repo in repositories]

            # For the web app, redirect to frontend with params
            frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
            params = urlencode({
                'status': 'success',
                'user_id': user_id,
                'platform': 'gitlab',
                'access_token': access_token
            })
            return redirect(f"{frontend_url}/auth/callback?{params}")

        return jsonify({'error': 'Failed to fetch repositories'}), 400

    except Exception as e:
        logger.error(f"GitLab OAuth error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@gitlab_bp.route('/refresh-token', methods=['POST'])
def refresh_access_token():
    """Get new access token using refresh token"""
    try:
        data = request.get_json()
        refresh_token = data.get('refresh_token')
        
        if not refresh_token:
            return jsonify({
                'success': False,
                'error': {'message': 'Refresh token is required'}
            }), 400

        # Exchange refresh token for new access token
        token_data = {
            'client_id': os.getenv('GITLAB_APP_ID'),
            'client_secret': os.getenv('GITLAB_APP_SECRET'),
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }

        response = requests.post('https://gitlab.com/oauth/token', data=token_data)
        
        if response.status_code != 200:
            return jsonify({
                'success': False,
                'error': {'message': 'Failed to refresh token'}
            }), 400

        new_token_data = response.json()
        
        return jsonify({
            'success': True,
            'data': {
                'access_token': new_token_data['access_token'],
                'refresh_token': new_token_data.get('refresh_token'),  # GitLab might provide new refresh token
                'expires_in': new_token_data.get('expires_in', 7200),
                'created_at': datetime.utcnow().isoformat()
            }
        })

    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500

@gitlab_bp.route('/validate-token', methods=['POST'])
def validate_token():
    """Validate the current access token"""
    try:
        data = request.get_json()
        access_token = data.get('access_token')
        
        if not access_token:
            return jsonify({
                'success': False,
                'error': {'message': 'No token provided'}
            }), 400

        headers = {'Authorization': f"Bearer {access_token}"}
        response = requests.get('https://gitlab.com/api/v4/user', headers=headers)
        
        return jsonify({
            'success': True,
            'data': {
                'valid': response.status_code == 200,
                'status': response.status_code,
                'user_info': response.json() if response.status_code == 200 else None
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500

@gitlab_bp.route('/repositories/<repo_id>/scan', methods=['POST'])
def trigger_specific_repository_scan(repo_id):
    """Trigger a security scan for a specific repository with LLM reranking"""
    logger.info(f"Starting scan for repository ID: {repo_id}")
    db_session = None
    analysis = None
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': {'message': 'Request body is required'}
            }), 400

        access_token = data.get('access_token')
        user_id = data.get('user_id')
        
        logger.info(f"Fetching repository details for ID: {repo_id}")
        headers = {'Authorization': f"Bearer {access_token}"}
        repo_response = requests.get(
            f'https://gitlab.com/api/v4/projects/{repo_id}',
            headers=headers
        )

        if repo_response.status_code != 200:
            logger.error(f"Failed to fetch repository details: {repo_response.text}")
            return jsonify({
                'success': False,
                'error': {'message': 'Repository not found or inaccessible'}
            }), 404

        repo_data = repo_response.json()
        project_url = repo_data['web_url']
        logger.info(f"Successfully fetched repository details for {project_url}")

        # Create database session
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Create initial analysis record
        analysis = GitLabAnalysisResult(
            project_id=str(repo_id),
            project_url=project_url,
            user_id=user_id,
            status='queued',
            timestamp=datetime.utcnow()
        )
        db_session.add(analysis)
        db_session.commit()
        logger.info(f"Created analysis record with ID: {analysis.id}")

        # Initialize progress tracking
        clear_scan_progress(user_id, repo_id)
        update_scan_progress(user_id, repo_id, 'initializing', 0)

        # Run scan in background thread
        def run_scan_in_background():
            try:
                # Update status to in_progress
                analysis.status = 'in_progress'
                db_session.commit()
                
                # Run scan
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(scan_gitlab_repository_handler(
                    project_url=project_url,
                    access_token=access_token,
                    user_id=user_id,
                    db_session=db_session,
                    analysis_record=analysis
                ))
                loop.close()
                
                logger.info(f"Scan completed with success status: {results.get('success', False)}")
                
                # Process with reranking only if successful
                if results.get('success'):
                    # Get findings
                    findings = results['data'].get('findings', [])
                    
                    # Add IDs to findings if needed
                    for idx, finding in enumerate(findings, 1):
                        if 'ID' not in finding:
                            finding['ID'] = idx
                    
                    # Rerank through AI service
                    rerank_findings(findings, user_id, project_url, repo_id, analysis, db_session)
                
            except Exception as e:
                logger.error(f"Background scan error: {str(e)}")
                logger.error(traceback.format_exc())
                try:
                    analysis.status = 'error'
                    analysis.error = str(e)
                    update_scan_progress(user_id, repo_id, 'error', 0)
                    db_session.commit()
                except Exception as db_e:
                    logger.error(f"Database error: {str(db_e)}")
                    db_session.rollback()
        
        # Start the background thread
        from threading import Thread
        thread = Thread(target=run_scan_in_background)
        thread.daemon = True
        thread.start()
        
        # Return immediately with instructions to poll progress
        return jsonify({
            'success': True,
            'message': 'GitLab scan queued successfully',
            'scan_id': analysis.id,
            'status': 'queued',
            'repository': repo_data['path_with_namespace'],
            'project_id': repo_id
        }), 202  # Return 202 Accepted
        
    except Exception as e:
        logger.error(f"GitLab scan initialization error: {str(e)}")
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
            logger.info("Database session closed")

def rerank_findings(findings, user_id, project_url, project_id, analysis, db_session):
    """Helper function to rerank findings through AI"""
    try:
        if not findings:
            logger.info("No findings to rerank")
            analysis.status = 'completed'
            analysis.results = {'findings': [], 'summary': {}, 'metadata': {}}
            analysis.rerank = []
            db_session.commit()
            return
            
        logger.info(f"Preparing to rerank {len(findings)} findings")
        
        # Prepare data for LLM
        llm_data = {
            'findings': [{
                "ID": finding["ID"],
                "file": finding.get("file", ""),
                "code_snippet": finding.get("code_snippet", ""),
                "message": finding.get("message", ""),
                "severity": finding.get("severity", "")
            } for finding in findings],
            'metadata': {
                'repository': project_url.split('gitlab.com/')[-1],
                'project_url': project_url,
                'user_id': user_id,
                'timestamp': datetime.utcnow().isoformat(),
                'scan_id': analysis.id if analysis else None
            }
        }
        
        # Call LLM reranking service
        AI_RERANK_URL = os.getenv('RERANK_API_URL')
        if not AI_RERANK_URL:
            logger.error("RERANK_API_URL not configured, skipping reranking")
            analysis.status = 'completed'
            analysis.results = {'findings': findings, 'summary': {}, 'metadata': {}}
            analysis.rerank = findings
            db_session.commit()
            return
            
        try:
            # Synchronous call for simplicity in this thread
            headers = {'Content-Type': 'application/json'}
            response = requests.post(
                AI_RERANK_URL, 
                headers=headers,
                json=llm_data
            )
            
            if response.status_code == 200:
                response_data = response.json()
                reranked_ids = extract_ids_from_llm_response(response_data)
                
                if reranked_ids:
                    # Create finding dictionary by ID
                    findings_map = {finding['ID']: finding for finding in findings}
                    
                    # Create reordered list
                    reordered_findings = [
                        findings_map[rank_id] for rank_id in reranked_ids 
                        if rank_id in findings_map
                    ]
                    
                    # Prepare results structure with stats
                    severity_counts = defaultdict(int)
                    category_counts = defaultdict(int)
                    for finding in findings:
                        severity = finding.get('severity', 'INFO')
                        category = finding.get('category', 'unknown')
                        severity_counts[severity] += 1
                        category_counts[category] += 1
                    
                    summary = {
                        'total_findings': len(findings),
                        'severity_counts': dict(severity_counts),
                        'category_counts': dict(category_counts),
                        'files_scanned': len(set(f.get('file', '') for f in findings)),
                        'files_with_findings': len(set(f.get('file', '') for f in findings))
                    }
                    
                    # Store in database
                    results_data = {
                        'findings': findings,
                        'summary': summary,
                        'metadata': {
                            'scan_duration_seconds': 0,  # We don't have this info here
                            'timestamp': datetime.utcnow().isoformat(),
                            'project_id': project_id,
                            'project_url': project_url,
                            'user_id': user_id,
                            'reranking': 'completed'
                        }
                    }
                    
                    analysis.status = 'completed'
                    analysis.results = results_data
                    analysis.rerank = reordered_findings
                    db_session.commit()
                    logger.info(f"Successfully reranked findings and updated analysis {analysis.id}")
                else:
                    logger.warning("Reranking failed: No valid IDs returned")
                    analysis.status = 'completed'
                    analysis.results = {'findings': findings, 'summary': {}, 'metadata': {}}
                    analysis.rerank = findings
                    db_session.commit()
            else:
                logger.error(f"LLM reranking failed: {response.status_code} - {response.text}")
                analysis.status = 'completed'
                analysis.results = {'findings': findings, 'summary': {}, 'metadata': {}}
                analysis.rerank = findings
                db_session.commit()
                
        except Exception as e:
            logger.error(f"Error calling LLM service: {str(e)}")
            analysis.status = 'completed'
            analysis.results = {'findings': findings, 'summary': {}, 'metadata': {}}
            analysis.rerank = findings
            db_session.commit()
    
    except Exception as e:
        logger.error(f"Error in rerank_findings: {str(e)}")
        logger.error(traceback.format_exc())
        try:
            analysis.status = 'completed'
            analysis.results = {'findings': findings, 'summary': {}, 'metadata': {}}
            analysis.rerank = findings
            db_session.commit()
        except:
            db_session.rollback()

def extract_ids_from_llm_response(response_data):
    """Extract IDs from LLM response text"""
    try:
        logger.info("Extracting IDs from LLM response")
        if isinstance(response_data, dict) and 'llm_response' in response_data:
            # If llm_response is already a list, use it directly
            if isinstance(response_data['llm_response'], list):
                logger.info(f"Found ID list: {response_data['llm_response']}")
                return response_data['llm_response']
            
            # If it's a string (the old format), try to parse it
            response_text = response_data['llm_response']
            if isinstance(response_text, str):
                import re
                array_match = re.search(r'\[([\d,\s]+)\]', response_text)
                if array_match:
                    id_string = array_match.group(1)
                    return [int(id.strip()) for id in id_string.split(',')]
                    
        logger.warning("Could not find valid ID list in response")
        return None
    except Exception as e:
        logger.error(f"Error extracting IDs from LLM response: {str(e)}")
        logger.error(f"Response data type: {type(response_data)}")
        return None

@gitlab_bp.route('/repositories', methods=['GET'])
def list_repositories():
    """List repositories accessible to the authenticated user"""
    access_token = request.headers.get('Authorization')
    if not access_token or not access_token.startswith('Bearer '):
        access_token = request.args.get('access_token')
        if not access_token:
            return jsonify({'error': 'Authorization token required'}), 401
    
    # If it starts with Bearer, strip it
    if access_token.startswith('Bearer '):
        access_token = access_token[7:]
        
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json'
    }
    
    try:
        response = requests.get(
            'https://gitlab.com/api/v4/projects',
            headers=headers,
            params={'membership': True, 'min_access_level': 30}
        )
        
        if response.status_code == 200:
            repositories = response.json()
            
            # Format repositories consistently
            formatted_repos = [{
                'id': repo['id'],
                'name': repo['name'],
                'full_name': repo['path_with_namespace'],
                'url': repo['web_url'],
                'description': repo['description'],
                'default_branch': repo['default_branch'],
                'visibility': repo['visibility'],
                'created_at': repo['created_at'],
                'last_activity_at': repo['last_activity_at']
            } for repo in repositories]
            
            return jsonify({
                'success': True,
                'data': formatted_repos
            })
        return jsonify({
            'success': False,
            'error': {'message': f'Failed to fetch repositories: {response.text}'}
        }), response.status_code
        
    except Exception as e:
        logger.error(f"Error fetching repositories: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500

@gitlab_bp.route('/files', methods=['POST'])
def get_vulnerable_file():
    """Fetch vulnerable file content from GitLab using POST with all parameters in request body"""
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    project_id = request_data.get('project_id')
    file_path = request_data.get('file_path')
    access_token = request_data.get('access_token')
    user_id = request_data.get('user_id')
    
    required_params = {
        'project_id': project_id,
        'file_path': file_path,
        'access_token': access_token,
        'user_id': user_id
    }
    
    missing_params = [param for param, value in required_params.items() if not value]
    if missing_params:
        return jsonify({
            'success': False,
            'error': {'message': f'Missing required parameters: {", ".join(missing_params)}'}
        }), 400

    try:
        # Correct header format for GitLab API
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        # Get default branch
        project_url = f"https://gitlab.com/api/v4/projects/{project_id}"
        project_response = requests.get(project_url, headers=headers)
        if project_response.status_code != 200:
            return jsonify({
                'success': False,
                'error': {'message': 'Failed to get project information'}
            }), 404
            
        default_branch = project_response.json().get('default_branch', 'main')
        
        # URL encode the file path for GitLab API
        encoded_file_path = requests.utils.quote(file_path, safe='')
        
        # Get file content
        file_url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/files/{encoded_file_path}/raw"
        params = {'ref': default_branch}
        
        file_response = requests.get(file_url, headers=headers, params=params)
        if file_response.status_code != 200:
            return jsonify({
                'success': False,
                'error': {'message': 'File not found or inaccessible'}
            }), 404

        return jsonify({
            'success': True,
            'data': {
                'file': file_response.text,
                'user_id': user_id,
                'version': default_branch,
                'project_id': project_id,
                'filename': file_path
            }
        })

    except Exception as e:
        logger.error(f"GitLab API error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500

@gitlab_bp.route('/projects/<project_id>/analysis/result', methods=['GET'])
def get_analysis_findings(project_id: str):
    """Get latest analysis findings for a GitLab project"""
    try:
        # Get query parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('limit', 30))))
        severity = request.args.get('severity', '').upper()
        category = request.args.get('category', '')
        file_path = request.args.get('file', '')
        user_id = request.args.get('user_id')
        
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        try:
            # Build query
            query = db_session.query(GitLabAnalysisResult).filter_by(
                project_id=project_id
            )
            
            # Add user_id filter if provided
            if user_id:
                query = query.filter_by(user_id=user_id)
                
            # Get latest analysis result
            result = query.order_by(
                desc(GitLabAnalysisResult.timestamp)
            ).first()
            
            if not result:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'No analysis found',
                        'code': 'ANALYSIS_NOT_FOUND'
                    }
                }), 404

            # Get findings from the results
            findings = result.results.get('findings', [])
            
            # Apply filters
            if severity:
                findings = [f for f in findings if f.get('severity', '').upper() == severity]
            if category:
                findings = [f for f in findings if f.get('category', '').lower() == category.lower()]
            if file_path:
                findings = [f for f in findings if file_path in f.get('file', '')]
            
            # Get total count before pagination
            total_findings = len(findings)
            
            # Apply pagination
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            paginated_findings = findings[start_idx:end_idx]
            
            # Get unique values for filters
            all_severities = sorted(set(f.get('severity', '').upper() for f in findings))
            all_categories = sorted(set(f.get('category', '').lower() for f in findings))
            
            # Get summary and metadata
            summary = result.results.get('summary', {})
            metadata = result.results.get('metadata', {})
            
            return jsonify({
                'success': True,
                'data': {
                    'project': {
                        'id': project_id,
                        'url': result.project_url
                    },
                    'metadata': {
                        'analysis_id': result.id,
                        'timestamp': result.timestamp.isoformat(),
                        'status': result.status,
                        'duration_seconds': metadata.get('scan_duration_seconds')
                    },
                    'summary': {
                        'files_scanned': summary.get('files_scanned', 0),
                        'files_with_findings': summary.get('files_with_findings', 0),
                        'skipped_files': summary.get('skipped_files', 0),
                        'partially_scanned': summary.get('partially_scanned', 0),
                        'total_findings': summary.get('total_findings', total_findings),
                        'severity_counts': summary.get('severity_counts', {}),
                        'category_counts': summary.get('category_counts', {})
                    },
                    'findings': paginated_findings,
                    'pagination': {
                        'current_page': page,
                        'total_pages': (total_findings + per_page - 1) // per_page,
                        'total_items': total_findings,
                        'per_page': per_page
                    },
                    'filters': {
                        'available_severities': all_severities,
                        'available_categories': all_categories
                    }
                }
            })
            
        finally:
            db_session.close()
            
    except Exception as e:
        logger.error(f"Error getting findings: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR'
            }
        }), 500

@gitlab_bp.route('/projects/<project_id>/analysis/reranked', methods=['GET'])
def get_reranked_findings(project_id: str):
    """Get reranked findings for a GitLab project"""
    try:
        # Create engine using the function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        session = Session()

        try:
            # Get user_id from query parameters
            user_id = request.args.get('user_id')
            
            # Build query
            query = session.query(GitLabAnalysisResult).filter_by(
                project_id=project_id
            )
            
            # Add user_id filter if provided
            if user_id:
                query = query.filter_by(user_id=user_id)
            
            # Get latest analysis result
            result = query.order_by(
                desc(GitLabAnalysisResult.timestamp)
            ).first()
            
            if not result:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'No analysis found',
                        'code': 'ANALYSIS_NOT_FOUND'
                    }
                }), 404

            if not result.rerank:
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
                'data': result.rerank
            })
            
        finally:
            session.close()
            
    except Exception as e:
        logger.error(f"Error getting reranked findings: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR'
            }
        }), 500

@gitlab_bp.route('/users/<user_id>/top-vulnerabilities', methods=['GET'])
def get_top_vulnerabilities(user_id):
    """Get top vulnerabilities for a user across all GitLab projects"""
    try:
        # Create engine using the function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        session = Session()

        try:
            analyses = session.query(GitLabAnalysisResult).filter(
                GitLabAnalysisResult.user_id == user_id,
                GitLabAnalysisResult.status == 'completed',
                GitLabAnalysisResult.results.isnot(None)
            ).order_by(GitLabAnalysisResult.timestamp.desc()).all()

            if not analyses:
                return jsonify({
                    'success': False,
                    'error': {'message': 'No analyses found'}
                }), 404

            # Track statistics
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            project_counts = defaultdict(int)
            unique_vulns = {}

            for analysis in analyses:
                findings = analysis.results.get('findings', [])
                project_id = analysis.project_id
                
                for finding in findings:
                    vuln_id = finding.get('id')
                    if vuln_id not in unique_vulns:
                        unique_vulns[vuln_id] = {
                            'vulnerability_id': vuln_id,
                            'severity': finding.get('severity'),
                            'category': finding.get('category'),
                            'message': finding.get('message'),
                            'code_snippet': finding.get('code_snippet'),
                            'file': finding.get('file'),
                            'line_range': {
                                'start': finding.get('line_start'),
                                'end': finding.get('line_end')
                            },
                            'security_references': {
                                'cwe': finding.get('cwe', []),
                                'owasp': finding.get('owasp', [])
                            },
                            'fix_recommendations': {
                                'description': finding.get('fix_recommendations', ''),
                                'references': finding.get('references', [])
                            },
                            'project': {
                                'id': project_id,
                                'url': analysis.project_url,
                                'analyzed_at': analysis.timestamp.isoformat()
                            }
                        }
                        
                        severity_counts[finding.get('severity')] += 1
                        category_counts[finding.get('category')] += 1
                        project_counts[project_id] += 1

            return jsonify({
                'success': True,
                'data': {
                    'metadata': {
                        'user_id': user_id,
                        'total_vulnerabilities': len(unique_vulns),
                        'total_projects': len(project_counts),
                        'severity_breakdown': dict(severity_counts),
                        'category_breakdown': dict(category_counts),
                        'project_breakdown': dict(project_counts),
                        'last_scan': analyses[0].timestamp.isoformat() if analyses else None
                    },
                    'vulnerabilities': list(unique_vulns.values())
                }
            })

        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error getting top vulnerabilities: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500

@gitlab_bp.route('/users/severity-counts', methods=['POST'])
def get_user_severity_counts():
    """Get severity counts for all projects of a user"""
    try:
        request_data = request.get_json()
        if not request_data or 'user_id' not in request_data:
            return jsonify({
                'success': False,
                'error': {'message': 'user_id is required'}
            }), 400
        
        user_id = request_data['user_id']
        logger.info(f"Processing severity counts for user_id: {user_id}")

        # Create engine using the function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        try:
            # Get all completed analyses
            all_analyses = db_session.query(GitLabAnalysisResult).filter(
                GitLabAnalysisResult.user_id == user_id,
                GitLabAnalysisResult.status == 'completed',
                GitLabAnalysisResult.results.isnot(None)
            ).order_by(GitLabAnalysisResult.timestamp.desc()).all()

            # Get latest analysis per project
            latest_analyses = {}
            for analysis in all_analyses:
                project_id = analysis.project_id
                if project_id not in latest_analyses:
                    latest_analyses[project_id] = analysis

            if not latest_analyses:
                return jsonify({
                    'success': False,
                    'error': {'message': 'No analyses found for this user'}
                }), 404

            project_data = {}
            total_severity_counts = defaultdict(int)
            total_findings = 0
            latest_scan_time = None

            for project_id, analysis in latest_analyses.items():
                results = analysis.results
                summary = results.get('summary', {})
                severity_counts = summary.get('severity_counts', {})
                project_findings = summary.get('total_findings', 0)

                latest_scan_time = max(latest_scan_time, analysis.timestamp) if latest_scan_time else analysis.timestamp
                
                project_data[project_id] = {
                    'id': project_id,
                    'url': analysis.project_url,
                    'severity_counts': severity_counts
                }

                # Update totals
                for severity, count in severity_counts.items():
                    total_severity_counts[severity] += count
                total_findings += project_findings

            return jsonify({
                'success': True,
                'data': {
                    'user_id': user_id,
                    'total_findings': total_findings,
                    'total_projects': len(project_data),
                    'severity_counts': dict(total_severity_counts),
                    'projects': project_data,
                    'metadata': {
                        'last_scan': latest_scan_time.isoformat() if latest_scan_time else None,
                        'scans_analyzed': len(project_data)
                    }
                }
            })

        finally:
            db_session.close()

    except Exception as e:
        logger.error(f"Error getting severity counts: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500

@gitlab_bp.route('/scan', methods=['POST'])
def trigger_general_repository_scan():
    """Trigger a security scan for a GitLab repository"""
    # Get data from POST request body
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    # Get required parameters
    project_id = request_data.get('project_id')
    project_url = request_data.get('project_url')
    access_token = request_data.get('access_token')
    user_id = request_data.get('user_id')
    
    # Validate required parameters
    required_params = {
        'project_id': project_id,
        'project_url': project_url, 
        'access_token': access_token,
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
        
    db_session = None
    analysis = None
    
    try:
        # Create engine using the function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Create analysis record
        analysis = GitLabAnalysisResult(
            project_id=project_id,
            user_id=user_id,
            status='queued',
            timestamp=datetime.utcnow()
        )
        db_session.add(analysis)
        db_session.commit()
        logger.info(f"Created analysis record with ID: {analysis.id}")
        
        # Initialize progress tracking
        clear_scan_progress(user_id, project_id)
        update_scan_progress(user_id, project_id, 'initializing', 0)

        # Start scan in background thread
        def run_scan_in_background():
            try:
                # Update status to in_progress
                analysis.status = 'in_progress'
                db_session.commit()
                
                # Run scan
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(scan_gitlab_repository_handler(
                    project_url=project_url,
                    access_token=access_token,
                    user_id=user_id,
                    db_session=db_session,
                    analysis_record=analysis
                ))
                loop.close()
                
                # Handle reranking
                if results.get('success'):
                    findings = results['data'].get('findings', [])
                    for idx, finding in enumerate(findings, 1):
                        if 'ID' not in finding:
                            finding['ID'] = idx
                    
                    # Call reranking helper
                    rerank_findings(findings, user_id, project_url, project_id, analysis, db_session)
                    
            except Exception as e:
                # Handle errors
                logger.error(f"Background scan error: {str(e)}")
                logger.error(traceback.format_exc())
                analysis.status = 'error'
                analysis.error = str(e)
                update_scan_progress(user_id, project_id, 'error', 0)
                db_session.commit()
        
        # Start the background thread
        from threading import Thread
        thread = Thread(target=run_scan_in_background)
        thread.daemon = True
        thread.start()
        
        # Return immediately with instructions to poll progress
        return jsonify({
            'success': True,
            'message': 'GitLab scan queued successfully',
            'scan_id': analysis.id,
            'status': 'queued',
            'project_id': project_id
        }), 202  # Return 202 Accepted
        
    except Exception as e:
        logger.error(f"GitLab scan initialization error: {str(e)}")
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