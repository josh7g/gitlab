from flask import Blueprint, jsonify, request
from sqlalchemy import func, desc, create_engine
from sqlalchemy.orm import sessionmaker
from models import db, AnalysisResult
from collections import defaultdict
import os
import ssl
import fnmatch
import logging
from pathlib import Path
from github import Github, GithubIntegration
import asyncio
import aiohttp
import json
from scanner import (
    scan_repository_handler,
    deduplicate_findings,
    process_findings_with_rag,
    extract_ids_from_llm_response,
    SecurityScanner,
    ScanConfig
)
from db_utils import create_db_engine
from progress_tracking import update_scan_progress

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def create_api_engine():
    """Create database engine for API routes"""
    return create_db_engine()


api = Blueprint('api', __name__, url_prefix='/api/v1')

@api.route('/files', methods=['POST'])
def get_vulnerable_file():
    """Fetch vulnerable file content from GitHub using POST with all parameters in request body"""
    from app import git_integration
    
    # Get data from POST request body
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    # Get required parameters from request body
    owner = request_data.get('owner')
    repo = request_data.get('repo')
    installation_id = request_data.get('installation_id')
    filename = request_data.get('file_name')
    user_id = request_data.get('user_id')
    
    # Validate required parameters
    required_params = {
        'owner': owner,
        'repo': repo,
        'installation_id': installation_id,
        'file_name': filename,
        'user_id': user_id
    }
    
    missing_params = [param for param, value in required_params.items() if not value]
    if missing_params:
        return jsonify({
            'success': False,
            'error': {'message': f'Missing required parameters: {", ".join(missing_params)}'}
        }), 400

    try:
        # Get GitHub token
        installation_token = git_integration.get_access_token(int(installation_id)).token
        gh = Github(installation_token)
        
        repository = gh.get_repo(f"{owner}/{repo}")
        default_branch = repository.default_branch
        latest_commit = repository.get_branch(default_branch).commit
        commit_sha = latest_commit.sha

        # Get file content from GitHub
        try:
            file_content = repository.get_contents(filename, ref=commit_sha)
            content = file_content.decoded_content.decode('utf-8')
            
            return jsonify({
                'success': True,
                'data': {
                    'file': content,
                    'user_id': user_id,
                    'version': commit_sha,
                    'reponame': f"{owner}/{repo}",
                    'filename': filename
                }
            })

        except Exception as e:
            logger.error(f"Error fetching file: {str(e)}")
            return jsonify({
                'success': False,
                'error': {'message': 'File not found or inaccessible'}
            }), 404

    except Exception as e:
        logger.error(f"GitHub API error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500


analysis_bp = Blueprint('analysis', __name__, url_prefix='/api/v1/analysis')

@analysis_bp.route('/<owner>/<repo>/result', methods=['GET'])
def get_analysis_findings(owner: str, repo: str):
    try:
        # Create engine using the new function
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
            
            repo_name = f"{owner}/{repo}"
            
            # Get latest analysis result
            result = db_session.query(AnalysisResult).filter_by(
                repository_name=repo_name
            ).order_by(
                desc(AnalysisResult.timestamp)
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

            # Prepare summary
            summary = {
                'category_counts': stats.get('category_counts', {}),
                'files_scanned': stats.get('scan_stats', {}).get('files_scanned', 0),
                'files_with_findings': stats.get('scan_stats', {}).get('files_with_findings', 0),
                'partially_scanned': 0,
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
                        'name': repo_name,
                        'owner': owner,
                        'repo': repo.split('/')[-1]
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
        logger.error(f"Error getting findings: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500
    
@api.route('/scan/<owner>/<repo>', methods=['DELETE'])
def delete_scan_results(owner: str, repo: str):
    """Delete scan results for a specific repository"""
    try:
        # Get user_id from query parameter or request body
        user_id = request.args.get('user_id') or (request.get_json() or {}).get('user_id')
        
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
            # Get all analyses for this repository
            repo_name = f"{owner}/{repo}"
            analyses = db_session.query(AnalysisResult).filter(
                AnalysisResult.repository_name == repo_name,
                AnalysisResult.user_id == user_id
            ).all()

            # Return empty string if no analyses found
            if not analyses:
                return jsonify("")

            # Delete all analyses
            for analysis in analyses:
                db_session.delete(analysis)
            
            db_session.commit()
            
            return jsonify("DONE")

        finally:
            db_session.close()

    except Exception as e:
        logger.error(f"Error deleting scan results: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500
    
@api.route('/users/severity-counts', methods=['POST'])
def get_user_severity_counts():
    try:
        request_data = request.get_json()
        if not request_data or 'user_id' not in request_data:
            return jsonify({
                'success': False,
                'error': {'message': 'user_id is required'}
            }), 400
        
        user_id = request_data['user_id']
        logger.info(f"Processing severity counts for user_id: {user_id}")

        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        try:
            # Get all completed analyses
            all_analyses = db_session.query(AnalysisResult).filter(
                AnalysisResult.user_id == user_id,
                AnalysisResult.status == 'completed',
                AnalysisResult.results.isnot(None)
            ).order_by(AnalysisResult.timestamp.desc()).all()

            logger.info(f"Found {len(all_analyses)} total analyses")

            # Get latest analysis per repository
            latest_analyses = {}
            for analysis in all_analyses:
                repo_name = analysis.repository_name
                if repo_name not in latest_analyses:
                    latest_analyses[repo_name] = analysis

            if not latest_analyses:
                return jsonify({
                    'success': False,
                    'error': {'message': 'No analyses found for this user'}
                }), 404

            repository_data = {}
            total_severity_counts = defaultdict(int)
            total_findings = 0
            latest_scan_time = None

            for repo_name, analysis in latest_analyses.items():
                results = analysis.results or {}
                severity_counts = (
                    results.get('summary', {}).get('severity_counts') or 
                    results.get('stats', {}).get('severity_counts') or 
                    {}
                )

                repo_findings = (
                    results.get('summary', {}).get('total_findings') or
                    results.get('stats', {}).get('total_findings') or
                    len(results.get('findings', []))
                )

                current_scan_time = analysis.timestamp
                latest_scan_time = max(latest_scan_time, current_scan_time) if latest_scan_time else current_scan_time

                repository_data[repo_name] = {
                    'name': repo_name,
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
    
@api.route('/users/<user_id>/top-vulnerabilities', methods=['GET'])
def get_top_vulnerabilities(user_id):
    try:
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        try:
            analyses = db_session.query(AnalysisResult).filter(
                AnalysisResult.user_id == user_id,
                AnalysisResult.status == 'completed',
                AnalysisResult.results.isnot(None)
            ).order_by(AnalysisResult.timestamp.desc()).all()

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
                                'name': repo_name.split('/')[-1],
                                'full_name': repo_name,
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
                        'last_scan': analyses[0].timestamp.isoformat() if analyses else None,
                        'repository': None  # For compatibility with existing format
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

@api.route('/scan', methods=['POST'])
def trigger_repository_scan():
    """Trigger a semgrep security scan for a repository and get reranking"""
    from app import git_integration
    
    # Get data from POST request body
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    # Get required parameters
    owner = request_data.get('owner')
    repo = request_data.get('repo')
    installation_id = request_data.get('installation_id')
    user_id = request_data.get('user_id')
    
    # Validate required parameters
    required_params = {
        'owner': owner,
        'repo': repo,
        'installation_id': installation_id,
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
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Create analysis record
        analysis = AnalysisResult(
            repository_name=f"{owner}/{repo}",
            user_id=user_id,
            status='queued'  # Start with queued status
        )
        db_session.add(analysis)
        db_session.commit()
        logger.info(f"Created analysis record with ID: {analysis.id}")
        
        # Initialize progress tracking
        repo_name = f"{owner}/{repo}"
        update_scan_progress(user_id, repo_name, 'initializing', 0)

        # Start scan in background thread
        def run_scan_in_background():
            try:
                # Get GitHub token
                installation_token = git_integration.get_access_token(int(installation_id)).token
                
                # Update status to in_progress
                analysis.status = 'in_progress'
                db_session.commit()
                
                # Run scan
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(scan_repository_handler(
                    repo_url=f"https://github.com/{owner}/{repo}",
                    installation_token=installation_token,
                    user_id=user_id,
                    db_session=db_session,
                    analysis_record=analysis
                ))
                loop.close()
            except Exception as e:
                # Handle errors
                logger.error(f"Background scan error: {str(e)}")
                analysis.status = 'error'
                analysis.error = str(e)
                update_scan_progress(user_id, repo_name, 'error', 0)
                db_session.commit()
        
        # Start the background thread
        from threading import Thread
        thread = Thread(target=run_scan_in_background)
        thread.daemon = True
        thread.start()
        
        # Return immediately with instructions to poll progress
        return jsonify({
            'success': True,
            'message': 'Scan queued successfully',
            'scan_id': analysis.id,
            'status': 'queued',
            'repository': f"{owner}/{repo}"
        }), 202  # Return 202 Accepted
        
    except Exception as e:
        logger.error(f"Scan initialization error: {str(e)}")
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

@analysis_bp.route('/<owner>/<repo>/reranked', methods=['GET'])
def get_reranked_findings(owner: str, repo: str):
    try:
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        session = Session()

        try:
            # Get latest analysis result
            result = session.query(AnalysisResult).filter_by(
                repository_name=f"{owner}/{repo}"
            ).order_by(
                desc(AnalysisResult.timestamp)
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