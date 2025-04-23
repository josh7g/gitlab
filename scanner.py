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
import base64
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from collections import defaultdict
import re
from models import AnalysisResult
import time
import urllib.parse
from progress_tracking import update_scan_progress
from typing import List, Dict, Tuple, Optional
from urllib.parse import quote 


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


async def get_full_file_content(
    session: aiohttp.ClientSession, 
    repo_url: str, 
    file_path: str, 
    token: str,
    max_retries: int = 3,
    base_delay: float = 1.0
) -> Optional[str]:
    """
    Fetch full file content from GitHub
    
    Args:
        session: aiohttp client session
        repo_url: GitHub repository URL
        file_path: Path to the file
        token: GitHub authentication token
        max_retries: Maximum number of retry attempts
        base_delay: Base delay between retries (will be exponentially increased)
    
    Returns:
        Optional[str]: File content if successful, None otherwise
    """
    try:
        logger.info(f"Attempting to fetch file content for: {file_path}")
        
        # Extract actual file path using regex to remove temp directory prefix
        temp_dir_pattern = r'^/tmp/scanner_[^/]+/repo_\d{8}_\d{6}/'
        actual_path = re.sub(temp_dir_pattern, '', file_path)
        
        # Normalize repository URL
        repo_parts = repo_url.rstrip('.git').split('github.com/')[-1].split('/')
        if len(repo_parts) != 2:
            raise ValueError(f"Invalid repository URL format: {repo_url}")
        
        owner, repo = repo_parts
        
        # Handle potential URL-unsafe characters in the file path
        safe_path = quote(actual_path, safe='')
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{safe_path}"
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'SecurityScanner'
        }
        
        logger.info(f"GitHub API URL: {api_url}")
        
        retry_count = 0
        last_error = None

        while retry_count < max_retries:
            try:
                async with session.get(api_url, headers=headers) as response:
                    status = response.status
                    logger.info(f"GitHub API Response Status: {status}")
                    
                    if status == 200:
                        data = await response.json()
                        if 'content' in data:
                            content = base64.b64decode(data['content']).decode('utf-8')
                            logger.info(f"Successfully fetched content for {actual_path}")
                            return content
                        else:
                            logger.warning(f"No content field in GitHub response for {actual_path}")
                            return None
                            
                    elif status == 404:
                        logger.warning(f"File not found: {actual_path}")
                        return None
                        
                    elif status == 403:
                        error_data = await response.json()
                        if 'message' in error_data and 'rate limit' in error_data['message'].lower():
                            retry_delay = base_delay * (2 ** retry_count)
                            logger.warning(f"Rate limited. Waiting {retry_delay}s before retry {retry_count + 1}/{max_retries}")
                            await asyncio.sleep(retry_delay)
                            retry_count += 1
                            continue
                        else:
                            logger.error(f"Access denied: {error_data.get('message', 'Unknown error')}")
                            return None
                            
                    elif status in {502, 503, 504}:
                        retry_delay = base_delay * (2 ** retry_count)
                        logger.warning(f"Gateway error {status}. Retrying in {retry_delay}s ({retry_count + 1}/{max_retries})")
                        await asyncio.sleep(retry_delay)
                        retry_count += 1
                        continue
                        
                    else:
                        error_text = await response.text()
                        logger.error(f"Unexpected GitHub API error ({status}): {error_text}")
                        return None

            except aiohttp.ClientError as e:
                last_error = e
                retry_delay = base_delay * (2 ** retry_count)
                logger.warning(f"Network error: {str(e)}. Retrying in {retry_delay}s ({retry_count + 1}/{max_retries})")
                await asyncio.sleep(retry_delay)
                retry_count += 1
                continue

        if last_error:
            logger.error(f"Failed to fetch file content after {max_retries} retries: {str(last_error)}")
        
        return None

    except Exception as e:
        logger.error(f"Unexpected error fetching file content: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return None
    

async def process_findings_with_rag(
    session: aiohttp.ClientSession, 
    findings: List[Dict], 
    user_id: str, 
    repo_url: str, 
    installation_token: str,
    batch_size: int = 5
) -> Tuple[List[Dict], List[Dict]]:
    """
    Process findings with RAG API.
    
    Args:
        session: aiohttp client session
        findings: List of findings to process
        user_id: User identifier
        repo_url: GitHub repository URL
        installation_token: GitHub installation token
        batch_size: Number of files to process in each batch
        
    Returns:
        Tuple[List[Dict], List[Dict]]: (RAG responses, findings)
    """
    try:
        logger.info(f"Starting RAG processing for {len(findings)} findings")
        RAG_API_URL = os.getenv('RAG_API_URL')
        if not RAG_API_URL:
            logger.warning("RAG_API_URL not configured, skipping RAG processing")
            return [], findings  # Return original findings if RAG not available
            
        # Group findings by file for efficient processing
        file_findings = {}
        for finding in findings:
            file_path = finding.get('file')
            if file_path:
                if file_path not in file_findings:
                    file_findings[file_path] = []
                file_findings[file_path].append(finding)
        
        logger.info(f"Unique files with findings to process: {len(file_findings)}")

        # Process files in batches
        total_size = 0
        rag_responses = []
        RETRYABLE_STATUS_CODES = {502, 503, 504}
        PERMANENT_ERROR_CODES = {400, 401, 403}
        max_retries = 3
        base_retry_delay = 2
        
        for i in range(0, len(file_findings), batch_size):
            batch_files = list(file_findings.keys())[i:i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1} of {len(file_findings)//batch_size + 1}")
            
            batch_payload = []
            batch_size_bytes = 0
            
            # Prepare batch payload
            for file_path in batch_files:
                logger.info(f"Fetching content for file: {file_path}")
                file_content = await get_full_file_content(
                    session, 
                    repo_url, 
                    file_path, 
                    installation_token
                )
                
                if file_content:
                    content_size = len(file_content.encode('utf-8'))
                    total_size += content_size
                    batch_size_bytes += content_size
                    
                    logger.info(f"File {file_path} size: {content_size/1024:.2f} KB")
                    
                    batch_payload.append({
                        "user_id": user_id,
                        "file": file_content,
                        "reponame": repo_url.split('github.com/')[-1].rstrip('.git'),
                        "filename": file_path
                    })
                else:
                    logger.warning(f"Failed to fetch content for file: {file_path}")

            if batch_payload:
                logger.info(f"Sending batch of {len(batch_payload)} files to RAG API")
                logger.info(f"Batch size: {batch_size_bytes/1024:.2f} KB")
                
                # Retry loop for RAG API calls
                for retry in range(max_retries):
                    try:
                        retry_delay = base_retry_delay * (retry + 1)
                        
                        async with session.post(
                            RAG_API_URL,
                            json=batch_payload,
                            timeout=30
                        ) as response:
                            logger.info(f"RAG API Response Status: {response.status}")
                            
                            if response.status == 200:
                                result = await response.json()
                                new_responses = result.get("results", [])
                                logger.info(f"Successfully processed {len(new_responses)} files through RAG API")
                                rag_responses.extend(new_responses)
                                break
                                
                            elif response.status in RETRYABLE_STATUS_CODES:
                                error_text = await response.text()
                                if retry < max_retries - 1:
                                    logger.warning(
                                        f"RAG API returned {response.status}, attempt {retry + 1}/{max_retries}. "
                                        f"Retrying in {retry_delay} seconds..."
                                    )
                                    await asyncio.sleep(retry_delay)
                                    continue
                                else:
                                    logger.error(f"RAG API failed after all retries. Status: {response.status}, Error: {error_text}")
                                    
                            elif response.status in PERMANENT_ERROR_CODES:
                                error_text = await response.text()
                                logger.error(f"RAG API permanent error (status {response.status}): {error_text}")
                                break
                                
                            else:
                                error_text = await response.text()
                                logger.error(f"RAG API unexpected error (status {response.status}): {error_text}")
                                if retry < max_retries - 1:
                                    await asyncio.sleep(retry_delay)
                                    continue
                                
                    except asyncio.TimeoutError:
                        logger.warning(f"RAG API timeout, attempt {retry + 1}/{max_retries}")
                        if retry < max_retries - 1:
                            await asyncio.sleep(retry_delay)
                            continue
                        logger.error("RAG API timeout after all retries")
                        
                    except Exception as e:
                        logger.error(f"RAG API request failed: {str(e)}")
                        logger.error(f"Full error: {traceback.format_exc()}")
                        if retry < max_retries - 1:
                            await asyncio.sleep(retry_delay)
                            continue
                        break

                # Small delay between batches
                await asyncio.sleep(1)

        logger.info(f"RAG processing completed. Files processed: {len(rag_responses)}")
        logger.info(f"Total size processed: {total_size/1024:.2f} KB")
        
        return rag_responses, findings  # Always return original findings

    except Exception as e:
        logger.error(f"Error in process_findings_with_rag: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return [], findings


@dataclass
class ScanConfig:
    """Configuration for repository scanning with improved timeout handling"""
    # File size limits
    max_file_size_mb: int = 50
    max_total_size_mb: int = 600
    max_memory_mb: int = 3000
    chunk_size_mb: int = 60
    max_files_per_chunk: int = 100
    
    # Timeout configuration based on ruleset size
    timeout_map: Dict[str, int] = field(default_factory=lambda: {
        "ci": 1200,             # 20 minutes for CI
        "security-audit": 540,  # 9 minutes
        "owasp-top-ten": 600,  # 10 minutes
        "supply-chain": 300,   # 5 minutes
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

class SecurityScanner:
    def __init__(self, config: ScanConfig = ScanConfig(), 
                 db_session: Optional[Session] = None, 
                 analysis_id: Optional[int] = None):
        self.config = config
        self.db_session = db_session
        self.analysis_id = analysis_id
        self.temp_dir = None
        self.repo_dir = None
        self._session = None
        self.detected_language = None
        self._repo_url = None
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

    def set_scan_info(self, repo_url: str, user_id: str):
        self._repo_url = repo_url
        self._user_id = user_id

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
        if language in ["csharp", "cs", "dotnet", "net"]:
            language = "c#"

        # Add language-specific configs if available
        if language in self.config.language_configs:
            configs.extend(self.config.language_configs[language])
            logger.info(f"Added {language}-specific configs")
        else:
            logger.warning(f"No specific configs available for language: {language}")

        logger.info(f"Total configs to run: {len(configs)} ({[c['name'] for c in configs]})")
        return configs

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
            repo_url = getattr(self, '_repo_url', '')  
            user_id = getattr(self, '_user_id', '')  
            repo_name = repo_url.split('github.com/')[-1].rstrip('.git')
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
                    update_scan_progress(user_id, repo_name, 'analyzing', progress)
                    
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
                'findings': merged_findings,  # Important: Ensure this is never empty if we have findings
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
            if self._user_id and self._repo_url:
                repo_name = self._repo_url.split('github.com/')[-1].rstrip('.git')
                update_scan_progress(self._user_id, repo_name, 'error', 0)
            
            return self._create_empty_result(error=str(e))
    
    async def _check_repository_size(self, repo_url: str, token: str) -> Dict:
        """Check repository size and metadata using GitHub API"""
        if not self._session:
            raise RuntimeError("Scanner session not initialized")
            
        try:
            if not token:
                raise ValueError("GitHub token is required")

            # Parse repository URL
            if 'github.com/' not in repo_url:
                raise ValueError(f"Invalid GitHub URL: {repo_url}")
                
            path_part = repo_url.split('github.com/')[-1].replace('.git', '')
            if '/' not in path_part:
                raise ValueError(f"Invalid repository path: {path_part}")
                
            owner, repo = path_part.split('/')
            logger.info(f"Checking repository: {owner}/{repo}")
            
            # Query GitHub API
            api_url = f"https://api.github.com/repos/{owner}/{repo}"
            headers = {
                'Authorization': f'Bearer {token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'SecurityScanner'
            }
            
            async with self._session.get(api_url, headers=headers) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise ValueError(f"GitHub API error ({response.status}): {error_text}")
                
                data = await response.json()
                size_mb = data.get('size', 0) / 1024
                self.detected_language = data.get('language')  # Store detected language
                
                logger.info(f"Repository size: {size_mb:.2f}MB")
                logger.info(f"Detected language: {self.detected_language}")
                logger.info(f"Default branch: {data.get('default_branch', 'main')}")
                
                return {
                    'size_mb': size_mb,
                    'is_compatible': size_mb <= self.config.max_total_size_mb,
                    'language': self.detected_language,
                    'default_branch': data.get('default_branch', 'main'),
                    'visibility': data.get('visibility', 'unknown'),
                    'fork_count': data.get('forks_count', 0),
                    'star_count': data.get('stargazers_count', 0),
                    'created_at': data.get('created_at'),
                    'updated_at': data.get('updated_at')
                }
                
        except Exception as e:
            logger.error(f"Repository size check failed: {str(e)}")
            raise

    async def _clone_repository(self, repo_url: str, token: str) -> Path:
        """Clone repository with size validation and optimizations"""
        try:
            # Verify repository size
            size_info = await self._check_repository_size(repo_url, token)
            if not size_info['is_compatible']:
                raise ValueError(
                    f"Repository size ({size_info['size_mb']:.2f}MB) exceeds "
                    f"limit of {self.config.max_total_size_mb}MB"
                )

            # Prepare clone directory
            self.repo_dir = self.temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            auth_url = repo_url.replace('https://', f'https://x-access-token:{token}@')
            
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

    def _process_scan_results(self, results: Dict) -> Dict:
        """Process and normalize scan results"""
        findings = results.get('results', [])
        stats = results.get('stats', {})
        paths = results.get('paths', {})
        parse_metrics = results.get('parse_metrics', {})
        
        processed_findings = []
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
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
            'total_files': stats.get('total', {}).get('files', 0),
            'files_scanned': len(paths.get('scanned', [])),
            'files_with_findings': len(files_with_findings),
            'skipped_files': len(paths.get('skipped', [])),
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
                'memory_usage_mb': self.scan_stats['memory_usage_mb']
            },
            'errors': [error] if error else []
        }

    async def scan_repository(self, repo_url: str, installation_token: str, user_id: str, multi_scan: bool = True) -> Dict:
        try:
            self.set_scan_info(repo_url, user_id)
            repo_name = repo_url.split('github.com/')[-1].rstrip('.git')

            from progress_tracking import clear_scan_progress
            clear_scan_progress(user_id, repo_name)
            
            update_scan_progress(user_id, repo_name, 'initializing', 0)
            AI_RERANK_URL = os.getenv('RERANK_API_URL')
            if not AI_RERANK_URL:
                raise ValueError("RERANK_API_URL not configured")
            
            size_info = await self._check_repository_size(repo_url, installation_token)
            update_scan_progress(user_id, repo_name, 'cloning', 0)
                
            # Initial scan
            scan_results = await self.run_multiple_semgrep_scans(self.repo_dir) if multi_scan else await self._run_semgrep_scan(self.repo_dir, self.config.scan_configs[0])
            update_scan_progress(user_id, repo_name, 'processing', 0)

            # Get all findings
            all_findings = scan_results.get('findings', [])
            logger.info(f"Found {len(all_findings)} total findings")

            # Initialize variables
            rag_responses = []
            selected_findings = []

            # Select findings based on total count
            if len(all_findings) <= 50:
                selected_findings = all_findings.copy()  # Make a copy to avoid reference issues
                logger.info(f"Processing all {len(selected_findings)} findings (under 50 threshold)")
            else:
                # Use severity-based selection logic for larger sets
                error_findings = [f for f in all_findings if f.get('severity', '').upper() == 'ERROR']
                warning_findings = [f for f in all_findings if f.get('severity', '').upper() == 'WARNING']
                info_findings = [f for f in all_findings if f.get('severity', '').upper() == 'INFO']
                
                # Add findings in priority order up to 50
                remaining = 50
                for severity_findings in [error_findings, warning_findings, info_findings]:
                    if remaining > 0:
                        to_add = severity_findings[:remaining]
                        selected_findings.extend(to_add)
                        remaining -= len(to_add)
                logger.info(f"Selected {len(selected_findings)} findings based on severity prioritization")

            # Process through RAG API if we have any findings
            if len(selected_findings) > 0:  # Explicit length check
                logger.info(f"Processing {len(selected_findings)} findings through RAG")
                async with aiohttp.ClientSession() as session:
                    rag_responses, selected_findings = await process_findings_with_rag(
                        session=session,
                        findings=selected_findings,
                        user_id=user_id,
                        repo_url=repo_url,
                        installation_token=installation_token,
                        batch_size=10
                    )
                logger.info(f"Received {len(rag_responses)} RAG responses")
            else:
                logger.info("No findings to process through RAG")

            # Prepare reranking data
            rerank_data = {
                'findings': [{
                    "ID": idx + 1,
                    "file": finding["file"],
                    "code_snippet": finding["code_snippet"],
                    "message": finding["message"],
                    "severity": finding["severity"]
                } for idx, finding in enumerate(selected_findings)],
                'metadata': {
                    'repository': repo_url.split('github.com/')[-1].rstrip('.git'),
                    'user_id': user_id,
                    'timestamp': datetime.utcnow().isoformat(),
                    'scan_id': self.analysis_id,
                    'rag_processed': bool(rag_responses),
                    'rag_responses': rag_responses
                }
            }

            # Handle reranking
            reordered_findings = selected_findings.copy()  # Start with a copy of selected findings
            if len(selected_findings) > 0:  # Explicit length check
                logger.info(f"Sending {len(selected_findings)} findings for reranking")
                async with aiohttp.ClientSession() as session:
                    try:
                        async with session.post(AI_RERANK_URL, json=rerank_data) as response:
                            if response.status == 200:
                                rerank_response = await response.json()
                                logger.info(f"Reranking Response: {json.dumps(rerank_response, indent=2)}")
                                reranked_ids = extract_ids_from_llm_response(rerank_response, selected_findings)
                                
                                if reranked_ids:
                                    findings_map = {idx + 1: finding for idx, finding in enumerate(selected_findings)}
                                    reordered_findings = [findings_map[id] for id in reranked_ids if id in findings_map]
                                    logger.info(f"Successfully reordered {len(reordered_findings)} findings")
                                else:
                                    logger.warning("Using original finding order as reranking returned no valid IDs")
                    except Exception as e:
                        logger.error(f"Reranking request failed: {str(e)}")
                        logger.info("Falling back to original finding order")
            else:
                logger.info("No findings to rerank")

            
            results_data = {
                'findings': all_findings,
                'stats': scan_results.get('stats', {}),
                'metadata': {
                    'repository_url': repo_url,
                    'user_id': user_id,
                    'scan_start': self.scan_stats['start_time'].isoformat(),
                    'scan_end': datetime.now().isoformat(),
                    'scan_duration_seconds': (datetime.now() - self.scan_stats['start_time']).total_seconds(),
                    'rag_processed': bool(rag_responses),
                    'rag_responses_count': len(rag_responses),
                    'selected_findings_count': len(selected_findings),
                    'total_findings_count': len(all_findings)
                }
            }

            # Update database
            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(AnalysisResult).get(self.analysis_id)
                    if analysis:
                        analysis.results = results_data  # All findings
                        analysis.rerank = reordered_findings  # Selected findings with consistent structure
                        analysis.status = 'completed'
                        analysis.completed_at = datetime.now()
                        self.db_session.commit()
                        logger.info(f"Successfully stored in database - results: {len(all_findings)}, rerank: {len(reordered_findings)}")
                except Exception as e:
                    self.db_session.rollback()
                    logger.error(f"Database update failed: {str(e)}")

            update_scan_progress(user_id, repo_name, 'completed', 100)

            return {
                'success': True,
                'data': results_data
            }

        except Exception as e:
            logger.error(f"Scan repository error: {str(e)}")
            update_scan_progress(user_id, repo_name, 'error', 0)
            
            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(AnalysisResult).get(self.analysis_id)
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
            self.temp_dir = Path(tempfile.mkdtemp(prefix='scanner_'))
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
    

def deduplicate_findings(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Remove duplicate findings from scan results"""
    if not scan_results.get('success') or 'data' not in scan_results:
        return scan_results

    findings = scan_results['data'].get('findings', [])
    if not findings:
        return scan_results
    
    seen_findings = set()
    deduplicated_findings = []
    
    for finding in findings:
        finding_signature = (
            finding.get('file', ''),
            finding.get('line_start', 0),
            finding.get('line_end', 0),
            finding.get('category', ''),
            finding.get('severity', ''),
            finding.get('code_snippet', '')
        )
        
        if finding_signature not in seen_findings:
            seen_findings.add(finding_signature)
            deduplicated_findings.append(finding)
    
    scan_results['data']['findings'] = deduplicated_findings
    scan_results['data']['summary']['total_findings'] = len(deduplicated_findings)
    
    return scan_results

def extract_ids_from_llm_response(response_data: Union[Dict, List, str], original_findings: List[Dict] = None) -> Optional[List[int]]:
    """
    Extract IDs from LLM response text.
    
    Args:
        response_data: Response from reranking API
        original_findings: Original list of findings (for reference)
        
    Returns:
        Optional[List[int]]: List of reranked IDs or None if extraction fails
    """
    try:
        logger.info(f"Processing reranking response: {json.dumps(response_data, indent=2)}")
        
        # Handle dictionary response
        if isinstance(response_data, dict):
            # Check for llm_response field
            if 'llm_response' in response_data:
                response = response_data['llm_response']
                logger.info(f"LLM Response content: {response}")
                
                if not response or response == '[]':
                    logger.warning("Empty llm_response, falling back to original order")
                    return list(range(1, len(original_findings) + 1)) if original_findings else None
                    
                if isinstance(response, list):
                    return response
                    
                array_match = re.search(r'\[([\d,\s]+)\]', str(response))
                if array_match:
                    id_string = array_match.group(1)
                    return [int(id.strip()) for id in id_string.split(',')]
        
        # Handle list response
        elif isinstance(response_data, list):
            if not response_data:
                logger.warning("Empty list response")
                return list(range(1, len(original_findings) + 1)) if original_findings else None
            return response_data
        
        logger.warning("Could not extract IDs from response")
        return list(range(1, len(original_findings) + 1)) if original_findings else None
        
    except Exception as e:
        logger.error(f"Error extracting IDs from LLM response: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return list(range(1, len(original_findings) + 1)) if original_findings else None
    

async def scan_repository_handler(
    repo_url: str,
    installation_token: str,
    user_id: str,
    multi_scan: bool = True,
    db_session: Optional[Session] = None,
    analysis_record: Optional[AnalysisResult] = None  
) -> Dict:
    """Handler function for web routes with enhanced input validation"""
    logger.info(f"Starting scan request for repository: {repo_url}")
    
    if not all([repo_url, installation_token, user_id]):
        return {
            'success': False,
            'error': {
                'message': 'Missing required parameters',
                'code': 'INVALID_PARAMETERS'
            }
        }

    if not repo_url.startswith(('https://github.com/', 'git@github.com:')):
        return {
            'success': False,
            'error': {
                'message': 'Invalid repository URL format',
                'code': 'INVALID_REPOSITORY_URL',
                'details': 'Only GitHub repositories are supported'
            }
        }

    try:
        # Use existing analysis record if provided
       
        analysis = analysis_record
        
        # Clear existing progress data for this scan
        repo_name = repo_url.split('github.com/')[-1].rstrip('.git')
        from progress_tracking import clear_scan_progress
        clear_scan_progress(user_id, repo_name)
        
        config = ScanConfig()
        async with SecurityScanner(config, db_session, analysis.id if analysis else None) as scanner:
            try:
                size_info = await scanner._check_repository_size(repo_url, installation_token)
                if not size_info['is_compatible']:
                    if analysis:
                        analysis.status = 'failed'
                        analysis.error = 'Repository too large for analysis'
                        db_session.commit()
                    return {
                        'success': False,
                        'error': {
                            'message': 'Repository too large for analysis',
                            'code': 'REPOSITORY_TOO_LARGE',
                            'details': {
                                'size_mb': size_info['size_mb'],
                                'limit_mb': config.max_total_size_mb,
                                'recommendation': 'Consider analyzing specific directories or branches'
                            }
                        }
                    }
                
                # Clone repository
                repo_dir = await scanner._clone_repository(repo_url, installation_token)
                
                try:
                    results = await scanner.scan_repository(
                        repo_url,
                        installation_token,
                        user_id,
                        multi_scan=multi_scan
                    )
                finally:
                    # Ensure we clean up the repository directory
                    if repo_dir and repo_dir.exists():
                        shutil.rmtree(repo_dir)
                
                if results.get('success'):
                    results['data']['repository_info'] = {
                        'size_mb': size_info['size_mb'],
                        'primary_language': size_info['language'],
                        'default_branch': size_info['default_branch'],
                        'visibility': size_info['visibility'],
                        'fork_count': size_info['fork_count'],
                        'star_count': size_info['star_count'],
                        'created_at': size_info['created_at'],
                        'updated_at': size_info['updated_at']
                    }
                
                return results

            except Exception as e:
                error_msg = f"Scan error: {str(e)}"
                logger.error(error_msg)
                if analysis:
                    analysis.status = 'error'
                    analysis.error = error_msg
                    db_session.commit()
                return {
                    'success': False,
                    'error': {
                        'message': str(e),
                        'code': 'SCAN_ERROR',
                        'type': type(e).__name__,
                        'timestamp': datetime.now().isoformat()
                    }
                }

    except Exception as e:
        error_msg = f"Handler error: {str(e)}"
        logger.error(error_msg)
        if analysis:
            analysis.status = 'error'
            analysis.error = error_msg
            db_session.commit()
        return {
            'success': False,
            'error': {
                'message': 'Unexpected error in scan handler',
                'code': 'INTERNAL_ERROR',
                'details': str(e),
                'type': type(e).__name__,
                'timestamp': datetime.now().isoformat()
            }
        }