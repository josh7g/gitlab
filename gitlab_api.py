from flask import Blueprint, jsonify, request
from sqlalchemy import func, desc, create_engine
from sqlalchemy.orm import sessionmaker
from models import db, GitLabAnalysisResult
from collections import defaultdict
import os
import logging
import json
import traceback
import asyncio
from datetime import datetime
from db_utils import create_db_engine
from progress_tracking import update_scan_progress, clear_scan_progress
from gitlab_scanner import scan_gitlab_repository_handler

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
gitlab_bp = Blueprint('gitlab', __name__, url_prefix='/api/v1/gitlab')

@gitlab_bp.route('/files', methods=['POST'])
def get_gitlab_file():
    """Fetch file content from GitLab using POST with parameters in request body"""
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    # Get required parameters from request body
    project_id = request_data.get('project_id')
    access_token = request_data.get('access_token')
    file_path = request_data.get('file_path')
    user_id = request_data.get('user_id')
    
    # Validate required parameters
    required_params = {
        'project_id': project_id,
        'access_token': access_token,
        'file_path': file_path,
        'user_id': user_id
    }
    
    missing_params = [param for param, value in required_params.items() if not value]
    if missing_params:
        return jsonify({
            'success': False,
            'error': {'message': f'Missing required parameters: {", ".join(missing_params)}'}
        }), 400

    try:
        # Make a request to the GitLab API
        import requests
        
        # Get GitLab URL from environment or use default
        gitlab_url = os.getenv('GITLAB_URL', 'https://gitlab.com')
        
        # URL-encode the file path
        import urllib.parse
        encoded_file_path = urllib.parse.quote_plus(file_path)
        
        # Build API URL for file content
        api_url = f"{gitlab_url}/api/v4/projects/{project_id}/repository/files/{encoded_file_path}/raw"
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        # Make the request
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            # Return file content
            return jsonify({
                'success': True,
                'data': {
                    'file': response.text,
                    'user_id': user_id,
                    'project_id': project_id,
                    'filename': file_path
                }
            })
        else:
            return jsonify({
                'success': False,
                'error': {
                    'message': f'Error fetching file: {response.status_code}',
                    'details': response.text
                }
            }), response.status_code

    except Exception as e:
        logger.error(f"GitLab API error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500

@gitlab_bp.route('/scan', methods=['POST'])
def trigger_gitlab_scan():
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
    access_token = request_data.get('access_token')
    repo_url = request_data.get('repo_url')
    user_id = request_data.get('user_id')
    
    # Extract repository name from URL
    repository_name = repo_url.split('/')[-1].replace('.git', '') if repo_url else None
    
    # Validate required parameters
    required_params = {
        'project_id': project_id,
        'access_token': access_token,
        'repo_url': repo_url,
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

    analysis = None
    db_session = None
    
    try:
        # Create engine using the function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Create analysis record
        analysis = GitLabAnalysisResult(
            repository_name=repository_name,
            project_id=project_id,
            user_id=user_id,
            status='queued'  # Start with queued status
        )
        db_session.add(analysis)
        db_session.commit()
        logger.info(f"Created GitLab analysis record with ID: {analysis.id}")
        
        # Initialize progress tracking
        clear_scan_progress(user_id, repository_name)
        update_scan_progress(user_id, repository_name, 'initializing', 0)

        # Start scan in background thread
        def run_scan_in_background():
            try:
                # Update status to in_progress
                analysis.status = 'in_progress'
                db_session.commit()
                
                # Run scan using our GitLab scanner
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(scan_gitlab_repository_handler(
                    project_url=repo_url,
                    access_token=access_token,
                    user_id=user_id,
                    db_session=db_session,
                    analysis_record=analysis
                ))
                loop.close()
                
            except Exception as e:
                # Handle errors
                logger.error(f"Background scan error: {str(e)}")
                logger.error(traceback.format_exc())
                analysis.status = 'error'
                analysis.error = str(e)
                update_scan_progress(user_id, repository_name, 'error', 0)
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
            'repository': repository_name,
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
@gitlab_bp.route('/analysis/<project_id>/result', methods=['GET'])
def get_gitlab_analysis_findings(project_id: str):
    """Get latest analysis findings for a GitLab project"""
    try:
        # Create engine using the function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        try:
            # Get query parameters
            page = max(1, int(request.args.get('page', 1)))
            per_page = min(100, max(1, int(request.args.get('limit', 30))))
            severity = request.args.get('severity', '').upper()
            category = request.args.get('category', '')
            file_path = request.args.get('file', '')
            user_id = request.args.get('user_id')
            
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

            # Extract results dynamically
            results = result.results or {}
            stats = results.get('stats', {})
            metadata = results.get('metadata', {})
            findings = results.get('findings', [])

            # Apply filters
            if severity:
                findings = [f for f in findings if f.get('severity', '').upper() == severity]
            if category:
                findings = [f for f in findings if f.get('category', '').lower() == category.lower()]
            if file_path:
                findings = [f for f in findings if file_path in f.get('file', '')]

            # Prepare findings with ID
            indexed_findings = [{
                **finding,
                'ID': idx + 1,
                'cwe': finding.get('cwe', []),
                'owasp': finding.get('owasp', []),
                'references': finding.get('references', []),
                'fix_recommendations': finding.get('fix_recommendations', ''),
                'scan_source': finding.get('scan_source', '')
            } for idx, finding in enumerate(findings)]

            # Total findings after filtering
            total_findings = len(indexed_findings)

            # Pagination
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            paginated_findings = indexed_findings[start_idx:end_idx]

            # Get summary from results or stats
            summary = {}
            if 'summary' in results:
                summary = results['summary']
            else:
                summary = {
                    'category_counts': stats.get('category_counts', {}),
                    'files_scanned': stats.get('scan_stats', {}).get('files_scanned', 0),
                    'files_with_findings': stats.get('scan_stats', {}).get('files_with_findings', 0),
                    'partially_scanned': stats.get('scan_stats', {}).get('partially_scanned', 0),
                    'severity_counts': stats.get('severity_counts', {}),
                    'skipped_files': stats.get('scan_stats', {}).get('skipped_files', 0),
                    'total_findings': total_findings
                }

            # Prepare filters
            available_categories = sorted(set(f.get('category', '').lower() for f in findings))
            available_severities = sorted(set(f.get('severity', '').upper() for f in findings))

            return jsonify({
                'success': True,
                'data': {
                    'repository': {
                        'name': result.repository_name,
                        'project_id': project_id
                    },
                    'metadata': {
                        'analysis_id': result.id,
                        'duration_seconds': metadata.get('scan_duration_seconds', 0),
                        'status': result.status,
                        'timestamp': result.timestamp.isoformat()
                    },
                    'pagination': {
                        'current_page': page,
                        'per_page': per_page,
                        'total_items': total_findings,
                        'total_pages': (total_findings + per_page - 1) // per_page
                    },
                    'filters': {
                        'available_categories': available_categories,
                        'available_severities': available_severities
                    },
                    'summary': summary,
                    'findings': paginated_findings
                }
            })
            
        finally:
            db_session.close()
            
    except Exception as e:
        logger.error(f"Error getting GitLab findings: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500

@gitlab_bp.route('/analysis/<project_id>/reranked', methods=['GET'])
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
            return jsonify(result.rerank)
            
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
    try:
        # Create engine using the function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        try:
            analyses = db_session.query(GitLabAnalysisResult).filter(
                GitLabAnalysisResult.user_id == user_id,
                GitLabAnalysisResult.status == 'completed',
                GitLabAnalysisResult.results.isnot(None)
            ).order_by(GitLabAnalysisResult.timestamp.desc()).all()

            if not analyses:
                return jsonify({
                    'success': False,
                    'error': {'message': 'No analyses found'}}), 404

            # Track statistics
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            repo_counts = defaultdict(int)
            unique_vulns = {}

            for analysis in analyses:
                findings = analysis.results.get('findings', [])
                repo_name = analysis.repository_name
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
                            'repository': {
                                'name': repo_name,
                                'project_id': project_id,
                                'analyzed_at': analysis.timestamp.isoformat()
                            }
                        }
                        
                        severity_counts[finding.get('severity')] += 1
                        category_counts[finding.get('category')] += 1
                        repo_counts[repo_name] += 1

            return jsonify({
                'success': True,
                'data': {
                    'metadata': {
                        'user_id': user_id,
                        'total_vulnerabilities': len(unique_vulns),
                        'total_repositories': len(repo_counts),
                        'severity_breakdown': severity_counts,
                        'category_breakdown': category_counts,
                        'repository_breakdown': repo_counts,
                        'last_scan': analyses[0].timestamp.isoformat() if analyses else None
                    },
                    'vulnerabilities': list(unique_vulns.values())
                }
            })
            
        finally:
            db_session.close()

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500

@gitlab_bp.route('/users/<user_id>/severity-counts', methods=['POST'])
def get_user_severity_counts(user_id):
    try:
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

            logger.info(f"Found {len(all_analyses)} total analyses")

            # Get latest analysis per repository
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

            repository_data = {}
            total_severity_counts = defaultdict(int)
            total_findings = 0
            latest_scan_time = None

            for project_id, analysis in latest_analyses.items():
                results = analysis.results or {}
                
                # Try to get severity counts from summary first, then from stats
                severity_counts = {}
                if 'summary' in results and 'severity_counts' in results['summary']:
                    severity_counts = results['summary']['severity_counts']
                elif 'stats' in results and 'severity_counts' in results['stats']:
                    severity_counts = results['stats']['severity_counts']
                
                # Try to get total findings count
                repo_findings = 0
                if 'summary' in results and 'total_findings' in results['summary']:
                    repo_findings = results['summary']['total_findings']
                elif 'stats' in results and 'total_findings' in results['stats']:
                    repo_findings = results['stats']['total_findings']
                else:
                    repo_findings = len(results.get('findings', []))

                current_scan_time = analysis.timestamp
                latest_scan_time = max(latest_scan_time, current_scan_time) if latest_scan_time else current_scan_time

                repository_data[project_id] = {
                    'name': analysis.repository_name,
                    'project_id': project_id,
                    'severity_counts': severity_counts
                }

                for severity, count in severity_counts.items():
                    total_severity_counts[severity] += count
                total_findings += repo_findings

            return jsonify({
                'success': True,
                'data': {
                    'user_id': user_id,
                    'total_findings': total_findings,
                    'total_repositories': len(repository_data),
                    'severity_counts': dict(total_severity_counts),
                    'repositories': repository_data,
                    'metadata': {
                        'last_scan': latest_scan_time.isoformat() if latest_scan_time else None,
                        'scans_analyzed': len(repository_data)
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