# gitlab_scanner.py - Enhanced version with language detection and multiple scan configurations
import os
import subprocess
import logging
import json
import psutil
import tempfile
import shutil
import asyncio
import aiohttp
import git
import ssl
import traceback
import fnmatch
import requests
import time
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from collections import defaultdict
import re
from models import GitLabAnalysisResult
from progress_tracking import update_scan_progress

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

@dataclass
class GitLabScanConfig:
    """Configuration for GitLab repository scanning with language-specific rules"""
    # File size limits
    max_file_size_mb: int = 50
    max_total_size_mb: int = 600
    max_memory_mb: int = 3000
    chunk_size_mb: int = 60
    max_files_per_chunk: int = 100
    
    # Timeout configuration based on ruleset size
    timeout_map: Dict[str, int] = field(default_factory=lambda: {
        "ci": 1200,          
        "security-audit": 540,  
        "owasp-top-ten": 600,  
        "supply-chain": 300,   
        "insecure-transport": 300,
        "jwt": 300,
        "secrets": 300,
        "xss": 300,
        "sql-injection": 300,
        "javascript": 300,
        "python": 300,
        "java": 300,
        "php": 300,
        "csharp": 300,
        "csharp-security": 300,
        "csharp-webconfig": 180,
        "csharp-cors": 180,
        "csharp-jwt": 180,
        "csharp-csrf": 180,
        "csharp-auth": 240,
        "csharp-sqlinjection": 240,
        "csharp-xss": 180,
        "dotnet": 300
    })
    default_timeout: int = 600  # 10 minutes default
    chunk_timeout: int = 120
    file_timeout_seconds: int = 20
    max_retries: int = 2
    concurrent_processes: int = 2

    # File exclusion patterns
    exclude_patterns: List[str] = field(default_factory=lambda: [
        '.git',
        'node_modules',
        'vendor',
        '*.min.*',
        '*.bundle.*',
        '*.map',
        '*.{pdf,jpg,jpeg,png,gif,zip,tar,gz,rar,mp4,mov}'
    ])

    # Scan configurations with rule counts - organized by type
    core_configs: List[Dict] = field(default_factory=lambda: [
        {"name": "security-audit", "config": "p/security-audit", "rules_count": 225},
        {"name": "owasp-top-ten", "config": "p/owasp-top-ten", "rules_count": 300},
        {"name": "secrets", "config": "p/secrets", "rules_count": 50},
        {"name": "supply-chain", "config": "p/supply-chain", "rules_count": 200},
    ])

    web_configs: List[Dict] = field(default_factory=lambda: [
        {"name": "insecure-transport", "config": "p/insecure-transport", "rules_count": 100},
        {"name": "jwt", "config": "p/jwt", "rules_count": 50},
        {"name": "xss", "config": "p/xss", "rules_count": 100},
        {"name": "sql-injection", "config": "p/sql-injection", "rules_count": 75},
        {"name": "command-injection", "config": "p/command-injection", "rules_count": 75},
        {"name": "trailofbits", "config": "p/trailofbits", "rules_count": 100},  
    ])

    language_configs: Dict[str, List[Dict]] = field(default_factory=lambda: {
        "python": [
            {"name": "python", "config": "p/python", "rules_count": 100},
            {"name": "django", "config": "p/django", "rules_count": 75},
            {"name": "flask", "config": "p/flask", "rules_count": 50},
            {"name": "fastapi", "config": "p/fastapi", "rules_count": 40},
        ],
        "javascript": [
            {"name": "javascript", "config": "p/javascript", "rules_count": 100},
            {"name": "nodejs", "config": "p/nodejs", "rules_count": 100},
            {"name": "react", "config": "p/react", "rules_count": 100},
        ],
        "typescript": [
            {"name": "typescript", "config": "p/typescript", "rules_count": 100},
            {"name": "nodejs", "config": "p/nodejs", "rules_count": 100},
            {"name": "react", "config": "p/react", "rules_count": 100},
        ],
        "java": [
            {"name": "java", "config": "p/java", "rules_count": 100},
            {"name": "spring", "config": "p/spring", "rules_count": 100},
        ],
        "php": [
            {"name": "php", "config": "p/php", "rules_count": 100},
        ],
        "c#": [
            {"name": "csharp", "config": "r/csharp", "rules_count": 150},
            {"name": "csharp-security", "config": "r/csharp.security", "rules_count": 200},
            {"name": "csharp-webconfig", "config": "r/csharp.webconfig", "rules_count": 50},
            {"name": "csharp-cors", "config": "r/csharp.security.cors", "rules_count": 25},
            {"name": "csharp-jwt", "config": "r/csharp.security.jwt", "rules_count": 30},
            {"name": "csharp-csrf", "config": "r/csharp.security.csrf", "rules_count": 25},
            {"name": "csharp-auth", "config": "r/csharp.security.auth", "rules_count": 75},
            {"name": "csharp-sqlinjection", "config": "r/csharp.security.injection.sql", "rules_count": 50},
            {"name": "csharp-xss", "config": "r/csharp.security.xss", "rules_count": 40},
            {"name": "dotnet", "config": "r/dotnet", "rules_count": 175},
        ],
        "go": [
            {"name": "go", "config": "p/golang", "rules_count": 100},
        ],
        "ruby": [
            {"name": "ruby", "config": "p/ruby", "rules_count": 75},
            {"name": "rails", "config": "p/rails", "rules_count": 75},
        ]
    })

class GitLabSecurityScanner:
    def __init__(self, config: GitLabScanConfig = GitLabScanConfig(), db_session: Optional[Session] = None, analysis_id: Optional[int] = None):
        self.config = config
        self.db_session = db_session
        self.analysis_id = analysis_id
        self.temp_dir = None
        self.repo_dir = None
        self._session = None
        self.detected_language = None
        self._project_url = None
        self._user_id = None
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'total_files': 0,
            'files_processed': 0,
            'files_skipped': 0,
            'files_too_large': 0,
            'total_size_mb': 0,
            'memory_usage_mb': 0,
            'findings_count': 0,
            'scan_durations': {}
        }

    def set_scan_info(self, project_url: str, user_id: str):
        """Store project URL and user ID for use in progress tracking"""
        self._project_url = project_url
        self._user_id = user_id

    async def __aenter__(self):
        """Initialize scanner resources"""
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Cleanup scanner resources"""
        await self._cleanup()

    async def _setup(self):
        """Initialize scanner with enhanced error handling"""
        try:
            self.temp_dir = Path(tempfile.mkdtemp(prefix='gitlab_scanner_'))
            logger.info(f"Created temporary directory: {self.temp_dir}")
            
            ssl_context = ssl.create_default_context()
            conn = aiohttp.TCPConnector(ssl=ssl_context)
            timeout = aiohttp.ClientTimeout(total=30)
            
            self._session = aiohttp.ClientSession(
                connector=conn,
                timeout=timeout,
                raise_for_status=True
            )
            
            self.scan_stats['start_time'] = datetime.now()
            logger.info("Scanner initialization completed")
            
        except Exception as e:
            logger.error(f"Scanner initialization failed: {str(e)}")
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
            raise

    async def _cleanup(self):
        """Cleanup scanner resources with proper error handling"""
        try:
            if self._session and not self._session.closed:
                await self._session.close()
                logger.info("Closed aiohttp session")
                
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
                
            self.scan_stats['end_time'] = datetime.now()
            
        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")
            
    def get_language_specific_configs(self, language: str) -> List[Dict]:
        """Get relevant scan configs based on repository language."""
        configs = []
        
        # Always include core security configs
        configs.extend(self.config.core_configs)
        logger.info("Added core security configs")
        
        # Always include web security configs
        configs.extend(self.config.web_configs)
        logger.info("Added web security configs")
        
        if not language:
            logger.warning("No language detected, using core and web security configs only")
            return configs

        # Normalize language name
        language = language.lower()
        
        # Handle C# variations
        if language in ["csharp", "cs", "dotnet", "net", "c#"]:
            language = "c#"

        # Add language-specific configs if available
        if language in self.config.language_configs:
            configs.extend(self.config.language_configs[language])
            logger.info(f"Added {language}-specific configs")
        else:
            logger.warning(f"No specific configs available for language: {language}")

        logger.info(f"Total configs to run: {len(configs)} ({[c['name'] for c in configs]})")
        return configs

    async def _check_repository_size(self, project_id: int, access_token: str) -> Dict:
        """Check repository size and detect primary language using GitLab API"""
        if not self._session:
            logger.error("HTTP session not initialized")
            raise RuntimeError("Scanner session not initialized")
            
        try:
            if not access_token:
                raise ValueError("GitLab token is empty or invalid")
                
            logger.info(f"Checking size and language for project ID: {project_id}")
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            api_url = f"https://gitlab.com/api/v4/projects/{project_id}"
            
            async with self._session.get(api_url, headers=headers) as response:
                response_text = await response.text()
                logger.info(f"GitLab API Status: {response.status}")
                
                if response.status != 200:
                    raise ValueError(f"GitLab API error: {response_text}")
                
                data = json.loads(response_text)
                
                # Get repository size
                size_kb = data.get('statistics', {}).get('repository_size', 0)
                size_mb = size_kb / 1024
                
                # Get primary language - different field in GitLab API
                self.detected_language = data.get('predominant_language')
                
                logger.info(f"Repository size: {size_mb:.2f}MB")
                logger.info(f"Detected language: {self.detected_language}")
                logger.info(f"Default branch: {data.get('default_branch', 'main')}")
                
                # For better language detection, also check languages in repository
                languages_url = f"https://gitlab.com/api/v4/projects/{project_id}/languages"
                
                try:
                    async with self._session.get(languages_url, headers=headers) as lang_response:
                        if lang_response.status == 200:
                            languages_data = await lang_response.json()
                            if languages_data:
                                # Languages are returned with percentage values
                                # Get the one with highest percentage
                                primary_language = max(languages_data.items(), key=lambda x: x[1])[0]
                                logger.info(f"Primary language from languages API: {primary_language}")
                                
                                # If languages API returned a value, prefer it over predominant_language
                                if primary_language and not self.detected_language:
                                    self.detected_language = primary_language
                except Exception as lang_error:
                    logger.warning(f"Error getting languages data: {str(lang_error)}")
                
                return {
                    'size_mb': size_mb,
                    'is_compatible': size_mb <= self.config.max_total_size_mb,
                    'language': self.detected_language,
                    'default_branch': data.get('default_branch', 'main'),
                    'visibility': data.get('visibility', 'unknown'),
                    'star_count': data.get('star_count', 0),
                    'fork_count': data.get('forks_count', 0),
                    'created_at': data.get('created_at'),
                    'last_activity_at': data.get('last_activity_at')
                }
                    
        except Exception as e:
            logger.error(f"Error checking repository size: {str(e)}")
            raise

    async def _clone_repository(self, project_url: str, access_token: str) -> Path:
        """Clone repository with size validation and optimizations"""
        try:
            project_id = self._extract_project_id(project_url, access_token)
            size_info = await self._check_repository_size(project_id, access_token)
            
            if not size_info['is_compatible']:
                raise ValueError(
                    f"Repository size ({size_info['size_mb']:.2f}MB) exceeds "
                    f"limit of {self.config.max_total_size_mb}MB"
                )

            self.repo_dir = self.temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            auth_url = project_url.replace('https://', f'https://oauth2:{access_token}@')
            
            logger.info(f"Cloning repository to {self.repo_dir}")
            
            # Optimize clone operation
            git_options = [
                '--depth=1',
                '--single-branch',
                '--no-tags',
                f'--branch={size_info["default_branch"]}'
            ]
            
            repo = git.Repo.clone_from(
                auth_url,
                self.repo_dir,
                multi_options=git_options
            )

            logger.info(f"Successfully cloned repository: {size_info['size_mb']:.2f}MB")
            return self.repo_dir

        except Exception as e:
            if self.repo_dir and self.repo_dir.exists():
                shutil.rmtree(self.repo_dir)
            raise RuntimeError(f"Repository clone failed: {str(e)}") from e

    async def _run_semgrep_scan(self, target_dir: Path, scan_config: Dict) -> Dict:
        """Execute semgrep scan with enhanced error handling and monitoring"""
        semgrepignore_path = target_dir / '.semgrepignore'
        start_time = time.time()
        scan_name = scan_config['name']
        
        try:
            # Create .semgrepignore file
            with open(semgrepignore_path, 'w') as f:
                for pattern in self.config.exclude_patterns:
                    f.write(f"{pattern}\n")

            timeout = self.config.timeout_map.get(scan_name, self.config.default_timeout)
            logger.info(f"Starting {scan_name} scan with {timeout}s timeout")

            cmd = [
                "semgrep",
                "scan",
                "--config", scan_config["config"],
                "--json",
                "--verbose",
                "--metrics=on",
                "--no-git-ignore",
                "--optimizations=all",
                str(target_dir)
            ]

            memory_before = psutil.Process().memory_info().rss / (1024 * 1024)
            logger.info(f"Memory usage before {scan_name}: {memory_before:.2f}MB")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(target_dir)
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                elapsed_time = time.time() - start_time
                error_msg = f"Scan {scan_name} timed out after {elapsed_time:.2f}s"
                logger.error(error_msg)
                return self._create_empty_result(error=error_msg)

            memory_after = psutil.Process().memory_info().rss / (1024 * 1024)
            memory_diff = memory_after - memory_before
            logger.info(f"Memory usage after {scan_name}: {memory_after:.2f}MB (Δ: {memory_diff:+.2f}MB)")

            stderr_output = stderr.decode() if stderr else ""
            if stderr_output:
                logger.warning(f"Semgrep stderr ({scan_name}): {stderr_output}")

            output = stdout.decode() if stdout else ""
            if not output.strip():
                return self._create_empty_result(error=f"No output from {scan_name}")

            try:
                results = json.loads(output)
                processed_results = self._process_scan_results(results)
                scan_duration = time.time() - start_time
                self.scan_stats['scan_durations'][scan_name] = scan_duration
                
                processed_results['scan_source'] = scan_name
                processed_results['scan_duration'] = scan_duration
                processed_results['memory_usage'] = {
                    'before': memory_before,
                    'after': memory_after,
                    'difference': memory_diff
                }
                
                logger.info(f"Completed {scan_name} scan in {scan_duration:.2f}s")
                return processed_results

            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse {scan_name} output: {str(e)}"
                logger.error(error_msg)
                return self._create_empty_result(error=error_msg)

        except Exception as e:
            error_msg = f"Error in {scan_name} scan: {str(e)}"
            logger.error(error_msg)
            return self._create_empty_result(error=error_msg)

        finally:
            if semgrepignore_path.exists():
                semgrepignore_path.unlink()

    async def run_multiple_semgrep_scans(self, target_dir: Path) -> Dict:
        """Run multiple semgrep scans based on detected language"""
        try:
            logger.info(f"Detected repository language: {self.detected_language}")
            
            # Get relevant configs based on language
            selected_configs = self.get_language_specific_configs(self.detected_language)
            
            # Add these lines for progress tracking
            project_url = getattr(self, '_project_url', '')  
            user_id = getattr(self, '_user_id', '')  
            project_id = self._extract_project_id(project_url, None, use_cached=True)
            total_configs = len(selected_configs)
            
            all_results = []
            merged_findings = []
            total_files_scanned = 0
            total_files_skipped = 0
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            seen_findings = set()
            errors = []

            # Run selected scans sequentially
            for i, scan_config in enumerate(selected_configs):
                try:
                    # Update progress here
                    progress = (i / total_configs) * 100
                    update_scan_progress(user_id, project_id, 'analyzing', progress)
                    
                    logger.info(f"Starting scan with config: {scan_config['name']} ({scan_config['rules_count']} rules)")
                    result = await self._run_semgrep_scan(target_dir, scan_config)
                    all_results.append(result)

                    findings = result.get('findings', [])
                    stats = result.get('stats', {})
                    
                    # Update counters
                    total_files_scanned = max(
                        total_files_scanned,
                        stats.get('scan_stats', {}).get('files_scanned', 0)
                    )
                    total_files_skipped += stats.get('scan_stats', {}).get('skipped_files', 0)

                    # Process and deduplicate findings
                    for finding in findings:
                        finding_id = (
                            finding.get('file', ''),
                            finding.get('line_start', 0),
                            finding.get('line_end', 0),
                            finding.get('code_snippet', '')
                        )

                        if finding_id not in seen_findings:
                            seen_findings.add(finding_id)
                            finding['scan_source'] = scan_config['name']
                            merged_findings.append(finding)
                            severity = finding.get('severity', 'UNKNOWN').upper()
                            category = finding.get('category', 'unknown')
                            severity_counts[severity] += 1
                            category_counts[category] += 1

                except Exception as e:
                    error_msg = f"Error in {scan_config['name']} scan: {str(e)}"
                    logger.error(error_msg)
                    errors.append({
                        'config': scan_config['name'],
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })

            # Log finding counts
            logger.info(f"Found {len(merged_findings)} total findings")
            logger.info(f"Severity distribution: {dict(severity_counts)}")

            return {
                'findings': merged_findings,  
                'stats': {
                    'total_findings': len(merged_findings),
                    'severity_counts': dict(severity_counts),
                    'category_counts': dict(category_counts),
                    'scan_stats': {
                        'files_scanned': total_files_scanned,
                        'skipped_files': total_files_skipped,
                        'files_with_findings': len(set(f.get('file', '') for f in merged_findings))
                    },
                    'memory_usage_mb': psutil.Process().memory_info().rss / (1024 * 1024),
                    'scan_durations': self.scan_stats['scan_durations']
                },
                'errors': errors if errors else None,
                'language': self.detected_language
            }

        except Exception as e:
            logger.error(f"Critical error in scan execution: {str(e)}")
            if self._user_id and self._project_url:
                project_id = self._extract_project_id(self._project_url, None, use_cached=True)
                update_scan_progress(self._user_id, project_id, 'error', 0)
            
            return self._create_empty_result(error=str(e))

    def _process_scan_results(self, results: Dict) -> Dict:
        """Process and normalize scan results"""
        findings = results.get('results', [])
        stats = results.get('stats', {})
        paths = results.get('paths', {})
        parse_metrics = results.get('parse_metrics', {})
        
        processed_findings = []
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        
        total_files = stats.get('total', {}).get('files', 0)
        if not total_files:
            total_files = stats.get('total_files', 0)
        
        skipped = paths.get('skipped', [])
        skipped_count = len(skipped) if skipped else 0
        
        scanned = paths.get('scanned', [])
        files_scanned = len(scanned) if scanned else total_files - skipped_count
        
        files_with_findings = set()
        
        for finding in findings:
            file_path = finding.get('path', '')
            if file_path:
                files_with_findings.add(file_path)

            severity = finding.get('extra', {}).get('severity', 'INFO').upper()
            category = finding.get('extra', {}).get('metadata', {}).get('category', 'security')
            
            severity_counts[severity] += 1
            category_counts[category] += 1
            
            processed_findings.append({
                'id': finding.get('check_id'),
                'file': file_path,
                'line_start': finding.get('start', {}).get('line'),
                'line_end': finding.get('end', {}).get('line'),
                'code_snippet': finding.get('extra', {}).get('lines', ''),
                'message': finding.get('extra', {}).get('message', ''),
                'severity': severity,
                'category': category,
                'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                'fix_recommendations': finding.get('extra', {}).get('metadata', {}).get('fix', ''),
                'references': finding.get('extra', {}).get('metadata', {}).get('references', [])
            })

        scan_stats = {
            'total_files': total_files,
            'files_scanned': files_scanned,
            'files_with_findings': len(files_with_findings),
            'skipped_files': skipped_count,
            'partially_scanned': parse_metrics.get('partially_parsed_files', 0)
        }

        return {
            'findings': processed_findings,
            'stats': {
                'total_findings': len(processed_findings),
                'severity_counts': dict(severity_counts),
                'category_counts': dict(category_counts),
                'scan_stats': scan_stats,
                'memory_usage_mb': self.scan_stats.get('memory_usage_mb', 0)
            }
        }

    def _create_empty_result(self, error: Optional[str] = None) -> Dict:
        """Create empty result structure with optional error information"""
        return {
            'findings': [],
            'stats': {
                'total_findings': 0,
                'severity_counts': {
                    'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0
                },
                'category_counts': {},
                'scan_stats': self.scan_stats,
                'memory_usage_mb': self.scan_stats.get('memory_usage_mb', 0)
            },
            'errors': [error] if error else []
        }

    def _extract_project_id(self, project_url: str, access_token: str = None, use_cached: bool = False) -> str:
        """Extract GitLab project ID from URL or path, with caching option"""
        
        # If using cached ID and we have a valid project URL, parse it from the URL
        # This is useful when we've already looked up the project ID but need it again without an API call
        if use_cached and hasattr(self, '_cached_project_id'):
            return self._cached_project_id
            
        try:
            # Handle both URL and path formats
            if project_url and 'gitlab.com' in project_url:
                path = project_url.split('gitlab.com/')[-1].rstrip('.git')
            elif project_url:
                path = project_url.lstrip('/')
            else:
                raise ValueError("Project URL is empty")
            
            # If we don't have an access token, just return the encoded path as the ID
            # This is useful for progress tracking where we just need a consistent ID
            if not access_token:
                return path.replace('/', '%2F')
            
            # Make API call to get project ID using OAuth token
            url = f"https://gitlab.com/api/v4/projects/{path.replace('/', '%2F')}"
            headers = {'Authorization': f'Bearer {access_token}'}
            
            logger.info(f"Fetching project ID for path: {path}")
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                project_data = response.json()
                project_id = str(project_data['id'])
                logger.info(f"Successfully got project ID: {project_id}")
                
                # Cache the project ID for future use
                self._cached_project_id = project_id
                return project_id
                
            logger.error(f"Failed to get project ID. Status: {response.status_code}, Response: {response.text}")
            raise ValueError(f"Failed to get project ID for {path}. Status: {response.status_code}")
            
        except Exception as e:
            logger.error(f"Error extracting project ID: {str(e)}")
            raise ValueError(f"Invalid GitLab project URL or path: {str(e)}")

    async def scan_repository(self, project_url: str, access_token: str, user_id: str) -> Dict:
        """Main method to scan a repository with multiple configurations based on language"""
        try:
            # Store project URL and user ID for progress tracking
            self.set_scan_info(project_url, user_id)
            
            # Extract project ID for progress tracking
            project_id = self._extract_project_id(project_url, access_token)
            
            # Update progress to initializing
            update_scan_progress(user_id, project_id, 'initializing', 0)
            
            # Check repository size and language in a single API call
            size_info = await self._check_repository_size(int(project_id), access_token)
            update_scan_progress(user_id, project_id, 'cloning', 20)
                
            # Clone repository
            repo_dir = await self._clone_repository(project_url, access_token)
            update_scan_progress(user_id, project_id, 'analyzing', 40)

            # Run multiple scans based on detected language
            scan_results = await self.run_multiple_semgrep_scans(repo_dir)
            update_scan_progress(user_id, project_id, 'processing', 70)

            # Get all findings
            all_findings = scan_results.get('findings', [])
            logger.info(f"Found {len(all_findings)} total findings")

            # Prepare reranking data
            selected_findings = all_findings
            if len(all_findings) > 50:
                # If we have more than 50 findings, prioritize by severity for reranking
                error_findings = [f for f in all_findings if f.get('severity', '').upper() == 'CRITICAL']
                high_findings = [f for f in all_findings if f.get('severity', '').upper() == 'HIGH']
                medium_findings = [f for f in all_findings if f.get('severity', '').upper() == 'MEDIUM']
                low_findings = [f for f in all_findings if f.get('severity', '').upper() == 'LOW']
                info_findings = [f for f in all_findings if f.get('severity', '').upper() == 'INFO']
                
                # Add findings in priority order up to 50
                selected_findings = []
                remaining = 50
                
                for severity_findings in [error_findings, high_findings, medium_findings, low_findings, info_findings]:
                    if remaining > 0:
                        to_add = severity_findings[:remaining]
                        selected_findings.extend(to_add)
                        remaining -= len(to_add)
            
            # Add IDs to findings if needed
            for idx, finding in enumerate(selected_findings, 1):
                if 'ID' not in finding:
                    finding['ID'] = idx
            
            # Prepare complete results data
            results_data = {
                'findings': all_findings,
                'stats': scan_results.get('stats', {}),
                'metadata': {
                    'repository_url': project_url,
                    'project_id': project_id,
                    'user_id': user_id,
                    'scan_start': self.scan_stats['start_time'].isoformat(),
                    'scan_end': datetime.now().isoformat(),
                    'scan_duration_seconds': (datetime.now() - self.scan_stats['start_time']).total_seconds(),
                    'language': self.detected_language
                },
                'summary': {
                    'total_findings': len(all_findings),
                    'severity_counts': scan_results.get('stats', {}).get('severity_counts', {}),
                    'category_counts': scan_results.get('stats', {}).get('category_counts', {}),
                    'files_scanned': scan_results.get('stats', {}).get('scan_stats', {}).get('files_scanned', 0),
                    'files_with_findings': scan_results.get('stats', {}).get('scan_stats', {}).get('files_with_findings', 0),
                    'skipped_files': scan_results.get('stats', {}).get('scan_stats', {}).get('skipped_files', 0),
                    'partially_scanned': scan_results.get('stats', {}).get('scan_stats', {}).get('partially_scanned', 0)
                }
            }
            
            # Update progress to reranking
            update_scan_progress(user_id, project_id, 'reranking', 85)
            
            # Update database with full results
            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(GitLabAnalysisResult).get(self.analysis_id)
                    if analysis:
                        analysis.results = results_data
                        analysis.rerank = selected_findings 
                        analysis.status = 'completed'
                        analysis.completed_at = datetime.now()
                        self.db_session.commit()
                        logger.info(f"Updated analysis results in database with ID: {analysis.id}")
                except Exception as e:
                    self.db_session.rollback()
                    logger.error(f"Failed to update analysis results: {str(e)}")
            
            # Update progress to completed
            update_scan_progress(user_id, project_id, 'completed', 100)
            
            return {
                'success': True,
                'data': {
                    'project_url': project_url,
                    'project_id': project_id,
                    'user_id': user_id,
                    'timestamp': datetime.now().isoformat(),
                    'findings': all_findings,
                    'summary': results_data['summary'],
                    'metadata': results_data['metadata'],
                    'repository_info': {
                        'size_mb': size_info['size_mb'],
                        'primary_language': size_info['language'],
                        'default_branch': size_info['default_branch'],
                        'visibility': size_info['visibility'],
                        'star_count': size_info['star_count'],
                        'fork_count': size_info['fork_count']
                    }
                }
            }
                
        except Exception as e:
            logger.error(f"Scan repository error: {str(e)}")
            
            # Update progress to error
            try:
                if user_id and project_id:
                    update_scan_progress(user_id, project_id, 'error', 0)
            except Exception as pe:
                logger.error(f"Error updating progress: {str(pe)}")
            
            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(GitLabAnalysisResult).get(self.analysis_id)
                    if analysis:
                        analysis.status = 'error'
                        analysis.error = str(e)
                        analysis.completed_at = datetime.now()
                        self.db_session.commit()
                except Exception as db_e:
                    logger.error(f"Failed to store error record: {str(db_e)}")
                    self.db_session.rollback()
            
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'SCAN_ERROR',
                    'type': type(e).__name__,
                    'timestamp': datetime.now().isoformat()
                }
            }