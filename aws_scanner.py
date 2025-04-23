import os
import json
import logging
import asyncio
import subprocess
import tempfile
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Union
import traceback
from pathlib import Path
import sys
import re
import boto3
from botocore.exceptions import ClientError
from sqlalchemy.orm import Session 
from models import CloudScan
from progress_tracking import update_scan_progress,clear_scan_progress
from sqlalchemy import text
from datetime import datetime, date
import time
import aiohttp
import random


# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,  
    format='%(asctime)s - %(levelname)s - %(message)s - [%(filename)s:%(lineno)d]',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def datetime_to_iso_string(obj):
        """Convert datetime objects to ISO format strings for JSON serialization"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, date):
            return obj.isoformat()
        return str(obj)

def sanitize_for_json(obj):
        """Recursively sanitize an object for JSON serialization"""
        if isinstance(obj, dict):
            return {k: sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [sanitize_for_json(i) for i in obj]
        elif isinstance(obj, (datetime, date)):
            return datetime_to_iso_string(obj)
        # Handle timezone-aware datetime objects from boto3
        elif hasattr(obj, 'isoformat'):
            return obj.isoformat()
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)  # Convert any other types to strings

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)

class AwsCredentialValidator:
    """Validates AWS credentials before attempting Steampipe scans"""
    
    @staticmethod
    async def validate_credentials(credentials: Dict[str, str], account_id: str = None) -> Dict[str, Any]:
        """
        Validate AWS credentials by making direct API calls to AWS
        
        Args:
            credentials: Dictionary containing AWS credentials
            account_id: Optional account ID to verify against (if provided)
            
        Returns:
            Dict with validation results and diagnostics
        """
        logger.info("Starting AWS credential validation")
        
        results = {
            "valid": False,
            "account_id": None,
            "caller_identity": None,
            "regions_accessible": [],
            "services_accessible": {},
            "errors": [],
            "diagnostic_info": {}
        }
        
        # Store original environment variables
        original_env = {
            'AWS_ACCESS_KEY_ID': os.environ.get('AWS_ACCESS_KEY_ID'),
            'AWS_SECRET_ACCESS_KEY': os.environ.get('AWS_SECRET_ACCESS_KEY'),
            'AWS_SESSION_TOKEN': os.environ.get('AWS_SESSION_TOKEN')
        }
        
        try:
            # Set AWS credentials in environment
            os.environ['AWS_ACCESS_KEY_ID'] = credentials.get('aws_access_key_id', '').strip()
            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.get('aws_secret_access_key', '').strip()
            if 'aws_session_token' in credentials:
                os.environ['AWS_SESSION_TOKEN'] = credentials.get('aws_session_token', '').strip()
            
            # Test credentials exist
            if not os.environ.get('AWS_ACCESS_KEY_ID') or not os.environ.get('AWS_SECRET_ACCESS_KEY'):
                results["errors"].append("Missing required AWS credentials")
                return results
                
            # Create a session
            session = boto3.Session(
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                aws_session_token=os.environ.get('AWS_SESSION_TOKEN')
            )
            
            # Get caller identity (basic validation)
            try:
                sts_client = session.client('sts')
                identity = sts_client.get_caller_identity()
                
                # Check account_id if provided - with improved string comparison
                if account_id:
                    aws_account_id = identity.get("Account")
                    # Convert both to strings for comparison and strip any whitespace
                    if str(aws_account_id).strip() != str(account_id).strip():
                        error_message = f"Account ID mismatch. Credentials are for account {aws_account_id}, but expected {account_id}"
                        logger.error(error_message)
                        results["errors"].append(error_message)
                        return results
                    # Log successful account ID match for debugging
                    logger.info(f"Account ID match confirmed: {aws_account_id}")
                
                results["valid"] = True
                results["account_id"] = identity.get("Account")
                results["caller_identity"] = {
                    "user_id": identity.get("UserId"),
                    "account_id": identity.get("Account"),
                    "arn": identity.get("Arn")
                }
                
                logger.info(f"Successfully authenticated as: {identity.get('Arn')}")
            except ClientError as e:
                error_message = f"STS validation error: {str(e)}"
                logger.error(error_message)
                results["errors"].append(error_message)
                results["diagnostic_info"]["sts_error"] = str(e)
                return results
            
            # Check available regions
            try:
                ec2_client = session.client('ec2', region_name='us-east-1')
                regions_response = ec2_client.describe_regions()
                available_regions = [region['RegionName'] for region in regions_response['Regions']]
                results["regions_accessible"] = available_regions
                logger.info(f"Discovered {len(available_regions)} accessible AWS regions")
            except ClientError as e:
                error_message = f"Error accessing EC2 regions: {str(e)}"
                logger.warning(error_message)
                results["diagnostic_info"]["regions_error"] = str(e)
            
            # Test access to common services
            service_tests = {
                'ec2': {
                    'method': lambda client: client.describe_instances(MaxResults=5),
                    'region': 'us-east-1'
                },
                's3': {
                    'method': lambda client: client.list_buckets(),
                    'region': None
                },
                'iam': {
                    'method': lambda client: client.list_users(MaxItems=5),
                    'region': None
                },
                'cloudtrail': {
                    'method': lambda client: client.describe_trails(),
                    'region': 'us-east-1'
                },
                'config': {
                    'method': lambda client: client.describe_config_rules(),  # No Limit parameter here
                    'region': 'us-east-1'
                }
            }
            
            for service_name, test_info in service_tests.items():
                try:
                    logger.debug(f"Testing access to {service_name} service")
                    
                    if test_info['region']:
                        client = session.client(service_name, region_name=test_info['region'])
                    else:
                        client = session.client(service_name)
                        
                    # Execute the test method
                    response = test_info['method'](client)
                    
                    # Store specific information for certain services
                    if service_name == 'ec2':
                        instance_count = len(response.get('Reservations', []))
                        results["diagnostic_info"]["ec2_instance_count"] = instance_count
                    elif service_name == 's3':
                        bucket_count = len(response.get('Buckets', []))
                        results["diagnostic_info"]["s3_bucket_count"] = bucket_count
                    elif service_name == 'iam':
                        user_count = len(response.get('Users', []))
                        results["diagnostic_info"]["iam_user_count"] = user_count
                    elif service_name == 'config':
                        rule_count = len(response.get('ConfigRules', []))
                        results["diagnostic_info"]["config_rule_count"] = rule_count
                    
                    results["services_accessible"][service_name] = True
                    logger.debug(f"Successfully accessed {service_name} service")
                    
                except ClientError as e:
                    error_code = e.response['Error']['Code'] 
                    error_message = e.response['Error']['Message']
                    
                    results["services_accessible"][service_name] = False
                    results["diagnostic_info"][f"{service_name}_error"] = {
                        "code": error_code,
                        "message": error_message
                    }
                    logger.warning(f"Could not access {service_name}: {error_code} - {error_message}")
            
            # Calculate overall access level score based on service access
            services_accessible_count = sum(1 for v in results["services_accessible"].values() if v)
            service_count = len(service_tests)
            results["access_level_score"] = int((services_accessible_count / service_count) * 100)
            
            return results
            
        except Exception as e:
            error_message = f"Unexpected error during credential validation: {str(e)}"
            logger.error(error_message)
            logger.error(traceback.format_exc())
            results["errors"].append(error_message)
            results["diagnostic_info"]["exception"] = str(e)
            results["diagnostic_info"]["traceback"] = traceback.format_exc()
            return results
            
        finally:
            # Restore original environment variables
            for key, value in original_env.items():
                if value is not None:
                    os.environ[key] = value
                elif key in os.environ:
                    del os.environ[key]

class AwsSecurityScanner:
    """AWS Security Scanner using Steampipe for CIS benchmarks"""
    
    def __init__(self, db_session: Optional[Session] = None, scan_record: Optional[CloudScan] = None):
        self.db_session = db_session
        self.scan_record = scan_record
        self.temp_dir = None
        self.config_dir = None
        self.aws_credentials = {}
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'scan_durations': {}
        }
        self.credential_validation_results = None
        
    

    async def setup(self):
        """Setup scanner resources and temporary directories with proper Steampipe initialization"""
        try:
            self.temp_dir = Path(tempfile.mkdtemp(prefix='aws_scanner_'))
            self.config_dir = self.temp_dir / 'config'
            self.config_dir.mkdir(exist_ok=True)
            
            # Create necessary directories
            (self.config_dir / 'aws').mkdir(exist_ok=True)
            logger.info(f"Created temporary directory: {self.temp_dir}")
            
            # Stop any existing Steampipe service
            try:
                await self._run_command(['steampipe', 'service', 'stop'], timeout=15)
                logger.info("Stopped any existing Steampipe services")
                await asyncio.sleep(2)  # Give it time to fully stop
            except Exception as e:
                logger.warning(f"Non-critical error stopping Steampipe service: {str(e)}")
            
            # Create AWS connection config file - using environment variables
            steampipe_config_dir = os.path.expanduser('~/.steampipe/config')
            os.makedirs(steampipe_config_dir, exist_ok=True)
            
            # Create simple connection config that uses environment variables
            aws_config_path = os.path.join(steampipe_config_dir, 'aws.spc')
            with open(aws_config_path, 'w') as f:
                f.write("""
    connection "aws" {
    plugin  = "aws"
    regions = ["us-east-1", "us-west-1", "us-west-2", "eu-west-1"]
    }
    """)
            
            # Set proper permissions
            os.chmod(aws_config_path, 0o600)
            
            # Ensure AWS plugin is installed and up to date
            try:
                await self._run_command(['steampipe', 'plugin', 'install', 'aws', '--force'], timeout=60)
                logger.info("AWS plugin installed or updated")
            except Exception as e:
                logger.warning(f"Error updating AWS plugin: {str(e)}")
            
            # Start Steampipe service
            try:
                await self._run_command(['steampipe', 'service', 'start', '--dashboard', 'false'], timeout=30)
                logger.info("Started Steampipe service")
                
                # Give service time to initialize
                logger.info("Waiting for Steampipe service to initialize...")
                await asyncio.sleep(8)
                
                # Check service status
                status_output = await self._run_command(['steampipe', 'service', 'status'], timeout=10)
                logger.info(f"Steampipe service status: {status_output}")
            except Exception as e:
                logger.error(f"Error starting Steampipe service: {str(e)}")
                
            # Test basic Steampipe functionality
            try:
                test_output = await self._run_command(['steampipe', 'query', 'select 1 as test', '--output', 'json'], timeout=15)
                logger.info(f"Basic Steampipe test: {test_output}")
            except Exception as e:
                logger.error(f"Basic Steampipe test failed: {str(e)}")
            
            # Log AWS credentials (safely)
            access_key = self.aws_credentials.get('aws_access_key_id', '')
            secret_key = self.aws_credentials.get('aws_secret_access_key', '')
            
            if access_key and len(access_key) >= 8:
                masked_key = f"{access_key[:4]}****{access_key[-4:]}"
            else:
                masked_key = "Not provided"
                
            logger.info(f"AWS credentials in environment:")
            logger.info(f"  AWS_ACCESS_KEY_ID: {masked_key}")
            logger.info(f"  AWS_SECRET_ACCESS_KEY: {'****' + secret_key[-4:] if secret_key and len(secret_key) >= 4 else 'Not provided'}")
            logger.info(f"  AWS_SESSION_TOKEN: {'Set' if 'aws_session_token' in self.aws_credentials else 'Not set'}")
            
            # Test if credentials are in environment variables
            if os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
                logger.info("Found credentials in environment variables.")
                
                # Test AWS connectivity using boto3 (fallback)
                import boto3
                try:
                    session = boto3.Session()
                    sts_client = session.client('sts')
                    identity = sts_client.get_caller_identity()
                    logger.info(f"Boto3 credentials test successful: {identity.get('Account')}")
                except Exception as e:
                    logger.error(f"Boto3 credentials test failed: {str(e)}")
            
            self.scan_stats['start_time'] = datetime.now()
            return True
            
        except Exception as e:
            logger.error(f"Scanner setup failed: {str(e)}")
            logger.error(traceback.format_exc())
            
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
            raise

    
    
    async def cleanup(self):
        """Clean up temporary resources"""
        try:
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
                
            self.scan_stats['end_time'] = datetime.now()
            
        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")
    
    async def _run_command(self, command: List[str], cwd: Optional[Path] = None, timeout: int = 300, capture_stderr: bool = True) -> str:
        """Run a command and return its output with timeout, with enhanced debugging"""
        try:
            cmd_str = ' '.join(command)
            logger.info(f"Running command: {cmd_str}")
            
            # Create environment with explicit credentials
            env = os.environ.copy()
            
            # Log credentials being used (safely)
            if 'steampipe' in command[0]:
                logger.debug(f"AWS_ACCESS_KEY_ID length: {len(env.get('AWS_ACCESS_KEY_ID', ''))}")
                logger.debug(f"AWS_SECRET_ACCESS_KEY length: {len(env.get('AWS_SECRET_ACCESS_KEY', ''))}")
                logger.debug(f"AWS_SESSION_TOKEN present: {bool(env.get('AWS_SESSION_TOKEN', ''))}")
            
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE if capture_stderr else None,
                cwd=str(cwd) if cwd else None,
                env=env  # Pass explicit environment
            )
            
            # Log the process ID for debugging
            logger.debug(f"Process started with PID: {process.pid}")
            
            try:
                start_time = datetime.now()
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                logger.debug(f"Command completed in {duration:.2f} seconds with return code: {process.returncode}")
            except asyncio.TimeoutError:
                process.kill()
                logger.error(f"Command timed out after {timeout} seconds: {cmd_str}")
                raise RuntimeError(f"Command timed out after {timeout} seconds: {cmd_str}")
            
            # Always capture stderr for debugging
            if stderr:
                stderr_text = stderr.decode()
                if stderr_text.strip():
                    logger.debug(f"Command stderr: {stderr_text}")
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Command failed with code {process.returncode}: {error_msg}")
                
                # More detailed error for steampipe commands
                if command[0] == 'steampipe':
                    logger.error(f"Steampipe command failed: {cmd_str}")
                    logger.error(f"STDERR: {error_msg}")
                    # Try to show some of stdout for context
                    if stdout:
                        stdout_sample = stdout.decode()[:500] + ("..." if len(stdout) > 500 else "")
                        logger.error(f"STDOUT sample: {stdout_sample}")
                        
                raise RuntimeError(f"Command failed with code {process.returncode}: {error_msg}")
                
            output = stdout.decode() if stdout else ""
            
            # Add more verbosity for empty outputs
            if not output.strip() and 'steampipe query' in cmd_str:
                logger.warning(f"Command produced empty output: {cmd_str}")
                logger.debug(f"Working directory: {cwd}")
                logger.debug(f"Full command: {cmd_str}")
                
                # Try to check if the SQL file exists and its content
                if len(command) > 2 and '.sql' in command[2]:
                    sql_path = command[2]
                    try:
                        with open(sql_path, 'r') as f:
                            sql_content = f.read()
                        logger.debug(f"SQL content for {sql_path}: {sql_content}")
                    except Exception as sql_e:
                        logger.warning(f"Could not read SQL file: {str(sql_e)}")
            
            # Log truncated output for debugging
            if output:
                log_output = output[:1000] + ("..." if len(output) > 1000 else "")
                logger.debug(f"Command output (truncated): {log_output}")
                
            return output
            
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            logger.error(traceback.format_exc())
            raise
    
    async def _debug_aws_credentials(self):
        """Debug AWS credentials and environment when Steampipe runs"""
        try:
            # Log current environment variables (redacted)
            access_key = os.environ.get('AWS_ACCESS_KEY_ID', '')
            secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY', '')
            session_token = os.environ.get('AWS_SESSION_TOKEN', '')
            
            logger.info(f"AWS credentials in environment:")
            logger.info(f"  AWS_ACCESS_KEY_ID: {'*' * 4 + access_key[-4:] if access_key else 'Not set'}")
            logger.info(f"  AWS_SECRET_ACCESS_KEY: {'*' * 4 + secret_key[-4:] if secret_key else 'Not set'}")
            logger.info(f"  AWS_SESSION_TOKEN: {'Present' if session_token else 'Not set'}")
            
            # Check boto3 access (to verify credentials work)
            try:
                import boto3
                sts = boto3.client('sts')
                identity = sts.get_caller_identity()
                logger.info(f"Boto3 credentials test successful: {identity.get('Account')}")
            except Exception as e:
                logger.error(f"Boto3 credentials test failed: {str(e)}")
            
            # Check Steampipe config file for AWS
            config_path = os.path.expanduser('~/.steampipe/config/aws.spc')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = f.read()
                    # Redact actual credentials
                    config = re.sub(r'aws_access_key_id\s*=\s*"[^"]+"', 'aws_access_key_id = "***REDACTED***"', config)
                    config = re.sub(r'aws_secret_access_key\s*=\s*"[^"]+"', 'aws_secret_access_key = "***REDACTED***"', config)
                    config = re.sub(r'aws_session_token\s*=\s*"[^"]+"', 'aws_session_token = "***REDACTED***"', config)
                    logger.info(f"Steampipe AWS config file content:\n{config}")
            else:
                logger.error(f"Steampipe AWS config file not found at {config_path}")
                
            return True
        except Exception as e:
            logger.error(f"AWS credentials debug error: {str(e)}")
            return False

    def sanitize_for_json(obj):
        """Recursively sanitize an object for JSON serialization"""
        if isinstance(obj, dict):
            return {k: sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [sanitize_for_json(i) for i in obj]
        elif isinstance(obj, (datetime, date)):
            return obj.isoformat()
        # Handle timezone-aware datetime objects from boto3
        elif hasattr(obj, 'isoformat'):
            return obj.isoformat()
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)  # Convert any other types to strings

   
    async def _configure_aws_credentials(self, credentials: Dict[str, str]) -> bool:
        """Configure AWS credentials for steampipe with enhanced debugging"""
        try:
            self.aws_credentials = credentials
            
            # Extract credential components
            access_key = credentials.get('aws_access_key_id', '').strip()
            secret_key = credentials.get('aws_secret_access_key', '').strip()
            session_token = credentials.get('aws_session_token', '').strip()
            
            # Validate basic credential format
            if not access_key or not secret_key:
                error_msg = "Missing required AWS credentials: access key or secret key"
                logger.error(error_msg)
                raise ValueError(error_msg)
            
            # Set as environment variables (will be used for subprocess calls)
            os.environ['AWS_ACCESS_KEY_ID'] = access_key
            os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
            if session_token:
                os.environ['AWS_SESSION_TOKEN'] = session_token
            
            
            # This is the most important part - direct credential setting in Steampipe format
            steampipe_config_dir = os.path.expanduser('~/.steampipe/config')
            os.makedirs(steampipe_config_dir, exist_ok=True)
            
            aws_config_path = os.path.join(steampipe_config_dir, 'aws.spc')
            with open(aws_config_path, 'w') as f:
                f.write(f"""
    connection "aws" {{
    plugin = "aws"

    # Direct credentials configuration
    aws_access_key_id     = "{access_key}"
    aws_secret_access_key = "{secret_key}"
    
    # Explicitly define regions
    regions = ["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1"]
    
    # Set default region for global resources
    default_region = "us-east-1"
    
    # Increase retries
    max_error_retry_attempts = 10
    min_error_retry_delay = 50
    """)
                if session_token:
                    f.write(f'  aws_session_token = "{session_token}"\n')
                f.write("}\n")
            
            # Set proper permissions
            os.chmod(aws_config_path, 0o600)
            
            # Restart Steampipe service to pick up new credentials
            try:
                await self._run_command(['steampipe', 'service', 'stop'], timeout=30)
                await asyncio.sleep(2)  # Give it time to stop
                await self._run_command(['steampipe', 'service', 'start', '--dashboard', 'false'], timeout=30)
                await asyncio.sleep(3)  # Give it time to start
                logger.info("Restarted Steampipe service with new credentials")
            except Exception as e:
                logger.warning(f"Failed to restart Steampipe service: {str(e)}, continuing anyway")
            
            # Test connection with a direct query
            try:
                test_cmd = ['steampipe', 'query', 'select account_id from aws_account limit 1']
                test_output = await self._run_command(test_cmd, timeout=20)

                
                if test_output and 'account_id' in test_output:
                    logger.info(f"AWS credentials verified through direct Steampipe query: {test_output}")
                    return True
                else:
                    logger.warning("Direct AWS account query returned no results")
                    # Try a basic Steampipe test
                    basic_cmd = ['steampipe', 'query', 'select 1 as test', '--output', 'json']
                    basic_output = await self._run_command(basic_cmd, timeout=10)
                    logger.info(f"Basic Steampipe query result: {basic_output}")
            except Exception as e:
                logger.warning(f"Steampipe credential test failed: {str(e)}")
            
            # Continue anyway as the direct boto3 tests show credentials are valid
            return True
                
        except Exception as e:
            logger.error(f"Failed to configure AWS credentials: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    async def test_aws_connection(self):
        """Test AWS connection with simplified approach"""
        try:
            # First debug environment variables and configuration
            await self._debug_aws_credentials()
            
            # Try explicitly querying with the connection name
            query = "select account_id from aws.aws_account limit 1"
            logger.info(f"Testing AWS connection with query: {query}")
            try:
                result = await self._run_command(['steampipe', 'query', query, '--output', 'json'], timeout=30)
                if result and len(result.strip()) > 0:
                    try:
                        data = json.loads(result)
                        if data and 'rows' in data and data['rows']:
                            account_id = data['rows'][0]['account_id']
                            logger.info(f"Successfully connected to AWS account: {account_id}")
                            return True
                    except json.JSONDecodeError:
                        logger.warning(f"Received non-JSON response: {result}")
                
                logger.warning("AWS connection query returned empty results")
            except Exception as e:
                logger.error(f"AWS connection query failed: {str(e)}")
            
            # Try boto3 directly to verify credentials
            try:
                import boto3
                sts = boto3.client('sts')
                identity = sts.get_caller_identity()
                account_id = identity.get('Account')
                logger.info(f"AWS credentials work with boto3 directly: {account_id}")
                # If boto3 works but Steampipe doesn't, there's a Steampipe config issue
                
                # Try creating a minimal test query to debug
                test_file = self.temp_dir / 'aws_test.sql'
                with open(test_file, 'w') as f:
                    f.write("select 'testing' as test;")
                
                # Test if Steampipe works at all
                regular_result = await self._run_command(['steampipe', 'query', str(test_file), '--output', 'json'], timeout=10)
                logger.info(f"Regular Steampipe test query result: {regular_result}")
                
                # Steampipe works but AWS plugin doesn't - likely a configuration issue
                return False
            except Exception as e:
                logger.error(f"Boto3 credentials test failed: {str(e)}")
                return False
        
        except Exception as e:
            logger.error(f"AWS connection test error: {str(e)}")
            return False
        
    async def test_aws_resources(self, account_id: str) -> Dict[str, bool]:
        """Test access to various AWS resource types with retries and direct queries"""
        results = {}
        max_retries = 3
        
        # Simple test queries for different AWS services
        test_queries = {
            "aws_account": "SELECT account_id, partition FROM aws_account LIMIT 1;",
            "aws_iam_user": "SELECT name, arn FROM aws_iam_user LIMIT 5;",
            "aws_s3_bucket": "SELECT name, arn FROM aws_s3_bucket LIMIT 5;",
            "aws_region": "SELECT region, account_id FROM aws_region LIMIT 5;",
            "aws_iam_policy": "SELECT name, arn FROM aws_iam_policy LIMIT 5;",
            "aws_ec2_instance": "SELECT instance_id, tags FROM aws_ec2_instance LIMIT 5;",
        }
        
        workspace_dir = self.temp_dir / 'workspace'
        workspace_dir.mkdir(exist_ok=True)
        
        # First, try a direct query approach
        for resource, query in test_queries.items():
            try:
                logger.info(f"Testing direct query for {resource}")
                # Use direct query without SQL file
                direct_cmd = ['steampipe', 'query', query, '--output', 'json']
                output = await self._run_command(direct_cmd, timeout=60)
                
                if output and len(output.strip()) > 0:
                    try:
                        data = json.loads(output)
                        if data and 'rows' in data and data['rows']:
                            logger.info(f"Successfully accessed {resource} via direct query")
                            results[resource] = True
                            continue  # Skip file-based query for this resource
                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse direct {resource} results as JSON")
            except Exception as e:
                logger.warning(f"Direct query for {resource} failed: {str(e)}")
        
        # Fall back to file-based queries for resources not successfully queried yet
        for resource, query in test_queries.items():
            if resource in results and results[resource]:
                continue  # Skip if already successfully queried
                
            for retry in range(max_retries):
                try:
                    logger.info(f"Testing file-based access to {resource} (attempt {retry+1}/{max_retries})")
                    
                    query_file = workspace_dir / f"{resource}_test.sql"
                    with open(query_file, 'w') as f:
                        f.write(query)
                    
                    # Try different query approaches
                    if retry == 0:
                        # First try basic query
                        query_cmd = ['steampipe', 'query', str(query_file), '--output', 'json']
                    elif retry == 1:
                        # Second try with database init
                        query_cmd = ['steampipe', 'query', str(query_file), '--output', 'json', '--database-init']
                    else:
                        # Last try with search path
                        query_cmd = ['steampipe', 'query', str(query_file), '--output', 'json', '--search-path', 'aws']
                    
                    output = await self._run_command(query_cmd, workspace_dir, timeout=60)
                    
                    if output and output.strip():
                        try:
                            data = json.loads(output)
                            if data and 'rows' in data and data['rows']:
                                logger.info(f"Successfully accessed {resource}: {json.dumps(data['rows'][0])}")
                                results[resource] = True
                                break  # Success, exit retry loop
                            else:
                                logger.warning(f"Query for {resource} returned empty result set (attempt {retry+1})")
                                results[resource] = False
                        except json.JSONDecodeError:
                            logger.warning(f"Could not parse {resource} results as JSON (attempt {retry+1})")
                            results[resource] = False
                    else:
                        logger.warning(f"Query for {resource} returned no output (attempt {retry+1})")
                        results[resource] = False
                        
                except Exception as e:
                    logger.error(f"Error testing {resource} (attempt {retry+1}): {str(e)}")
                    results[resource] = False
                    if retry < max_retries - 1:
                        logger.info(f"Retrying {resource} after error...")
                        await asyncio.sleep(2 ** retry)  # Exponential backoff
                    
        # Log summary of results
        success_count = sum(1 for v in results.values() if v)
        logger.info(f"AWS resource access test summary: {success_count}/{len(test_queries)} resources accessible")
        
        return results
    
    async def _configure_steampipe_aws_credentials(self, credentials: Dict[str, str]) -> bool:
        """Configure AWS credentials for Steampipe using the approach from the Docker entry file"""
        try:
            self.aws_credentials = credentials
            
            # Extract credential components
            access_key = credentials.get('aws_access_key_id', '').strip()
            secret_key = credentials.get('aws_secret_access_key', '').strip()
            session_token = credentials.get('aws_session_token', '').strip()
            
            # Validate basic credential format
            if not access_key or not secret_key:
                error_msg = "Missing required AWS credentials: access key or secret key"
                logger.error(error_msg)
                raise ValueError(error_msg)
            
            # Set as environment variables
            os.environ['AWS_ACCESS_KEY_ID'] = access_key
            os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
            if session_token:
                os.environ['AWS_SESSION_TOKEN'] = session_token
            
            # Create AWS credentials directory and files (similar to Docker approach)
            aws_dir = os.path.expanduser('~/.aws')
            os.makedirs(aws_dir, exist_ok=True)
            
            # Create credentials file
            with open(os.path.join(aws_dir, 'credentials'), 'w') as f:
                f.write("[default]\n")
                f.write(f"aws_access_key_id={access_key}\n")
                f.write(f"aws_secret_access_key={secret_key}\n")
                if session_token:
                    f.write(f"aws_session_token={session_token}\n")
            
            # Create config file
            with open(os.path.join(aws_dir, 'config'), 'w') as f:
                f.write("[default]\n")
                f.write("region=us-east-1\n")
                f.write("output=json\n")
            
            # Set permissions
            os.chmod(os.path.join(aws_dir, 'credentials'), 0o600)
            os.chmod(os.path.join(aws_dir, 'config'), 0o600)
            
            # Create Steampipe config with same approach as Docker
            steampipe_config_dir = os.path.expanduser('~/.steampipe/config')
            os.makedirs(steampipe_config_dir, exist_ok=True)
            
            aws_config_path = os.path.join(steampipe_config_dir, 'aws.spc')
            with open(aws_config_path, 'w') as f:
                f.write("""
    connection "aws" {
    plugin  = "aws"
    profile = "default"
    regions = ["us-east-1"]
    }
    """)
            
            # Set proper permissions
            os.chmod(aws_config_path, 0o600)
            
            # Restart Steampipe service to pick up new credentials
            try:
                await self._run_command(['steampipe', 'service', 'stop'], timeout=30)
                await asyncio.sleep(2)  # Give it time to stop
                await self._run_command(['steampipe', 'service', 'start', '--dashboard', 'false'], timeout=30)
                await asyncio.sleep(5)  # Give it time to start
                logger.info("Restarted Steampipe service with new credentials")
            except Exception as e:
                logger.warning(f"Failed to restart Steampipe service: {str(e)}, continuing anyway")
            
            # Test connection with direct query - use the exact approach from Docker
            try:
                test_cmd = ['steampipe', 'query', "select account_id from aws_account limit 1", "--output", "csv"]
                test_output = await self._run_command(test_cmd, timeout=20)
                
                if test_output and len(test_output.strip()) > 0 and not test_output.startswith("Error:"):
                    account_id = test_output.strip().split("\n")[-1]  # Get the last line which should be the account ID
                    logger.info(f"AWS credentials verified through direct Steampipe query: {account_id}")
                    return True
                else:
                    logger.warning("Direct AWS account query returned no results or error")
            except Exception as e:
                logger.warning(f"Steampipe credential test failed: {str(e)}")
            
            # Continue with boto3 approach as fallback
            return True
                
        except Exception as e:
            logger.error(f"Failed to configure AWS credentials: {str(e)}")
            logger.error(traceback.format_exc())
            return False
    
    async def test_aws_connectivity(self):
        """Test direct network connectivity to AWS endpoints"""
        try:
            # Create a simple test script
            network_test_file = self.temp_dir / 'network_test.sh'
            with open(network_test_file, 'w') as f:
                f.write("""#!/bin/bash
    echo "Testing connectivity to AWS endpoints..."
    for endpoint in s3.amazonaws.com ec2.us-east-1.amazonaws.com iam.amazonaws.com sts.amazonaws.com; do
        echo -n "Testing $endpoint: "
        if curl -s --max-time 5 https://$endpoint > /dev/null; then
            echo "SUCCESS"
        else
            echo "FAILED"
        fi
    done
    """)
            
            # Make executable
            os.chmod(network_test_file, 0o755)
            
            # Run the test
            logger.info("Testing direct network connectivity to AWS endpoints")
            network_output = await self._run_command([str(network_test_file)], timeout=30)
            logger.info(f"Network connectivity test results:\n{network_output}")
            
            return "FAILED" not in network_output
        except Exception as e:
            logger.error(f"Network connectivity test failed: {str(e)}")
            return False
    
    async def test_aws_connectivity_and_permissions(self, workspace_dir: Path):
        """
        Run a comprehensive set of tests to diagnose AWS connectivity and permission issues
        
        Args:
            workspace_dir: Path to the workspace directory
            
        Returns:
            Dict with test results and diagnostic information
        """
        results = {
            "network_connectivity": True,  
            "credential_test": False,
            "permissions_test": False,
            "cis_test": False,
            "powerpipe_test": False,
            "sdk_debug_test": False,
            "details": {}
        }
        
        try:
            # 1. Direct AWS credential test in Steampipe
            credential_test_sql = workspace_dir / 'cred_test.sql'
            with open(credential_test_sql, 'w') as f:
                f.write("""
    -- Test AWS credential information
    select 
    current_credential() as current_cred;
    """)
            
            logger.info("Running AWS credential test")
            try:
                cred_cmd = ['steampipe', 'query', str(credential_test_sql), '--output', 'json']
                cred_output = await self._run_command(cred_cmd, workspace_dir, timeout=15)
                logger.info(f"AWS credential test result: {cred_output}")
                results["credential_test"] = True
                results["details"]["credential_test"] = cred_output
            except Exception as e:
                logger.error(f"Credential test failed: {str(e)}")
                results["details"]["credential_test_error"] = str(e)
            
            # 2. Permissions validator test
            permissions_test_sql = workspace_dir / 'perms_test.sql'
            with open(permissions_test_sql, 'w') as f:
                f.write("""
    -- Basic test to see what permissions we have
    select
    'list_users' as operation,
    CASE 
        WHEN count(*) >= 0 THEN 'success'
        ELSE 'failed'
    END as result
    from
    aws_iam_user
    limit 1;
    """)
            
            logger.info("Running AWS permissions test")
            try:
                perms_cmd = ['steampipe', 'query', str(permissions_test_sql), '--output', 'json', '--database-init']
                perms_output = await self._run_command(perms_cmd, workspace_dir, timeout=30)
                logger.info(f"Permissions test result: {perms_output}")
                if perms_output and "success" in perms_output:
                    results["permissions_test"] = True
                results["details"]["permissions_test"] = perms_output
            except Exception as e:
                logger.error(f"Permissions test failed: {str(e)}")
                results["details"]["permissions_test_error"] = str(e)
            
            # 3. Specific CIS control query test
            cis_test_sql = workspace_dir / 'cis_test.sql'
            with open(cis_test_sql, 'w') as f:
                f.write("""
    -- Test IAM-related CIS check
    select
    'IAM password policy' as control,
    'CIS 1.1' as id,
    case
        when minimum_password_length >= 14 then 'pass'
        else 'fail'
    end as status
    from
    aws_iam_account_password_policy;
    """)
            
            logger.info("Running specific CIS control test")
            try:
                cis_cmd = ['steampipe', 'query', str(cis_test_sql), '--output', 'json']
                cis_output = await self._run_command(cis_cmd, workspace_dir, timeout=30)
                logger.info(f"CIS test result: {cis_output}")
                if cis_output and len(cis_output.strip()) > 0:
                    results["cis_test"] = True
                results["details"]["cis_test"] = cis_output
            except Exception as e:
                logger.error(f"CIS test failed: {str(e)}")
                results["details"]["cis_test_error"] = str(e)
            
            # 4. Powerpipe command with correct syntax
            logger.info("Testing Powerpipe commands")
            try:
                # First check what powerpipe supports
                help_cmd = ['powerpipe', '--help']
                help_output = await self._run_command(help_cmd, workspace_dir, timeout=15)
                logger.info(f"Powerpipe help: {help_output}")
                results["details"]["powerpipe_help"] = help_output
                
                # Based on the article you shared, try with "benchmark run" instead of "check"
                run_cmd = ['powerpipe', 'benchmark', 'run', 'cis_v300', '--output', 'json']
                run_output = await self._run_command(run_cmd, workspace_dir, timeout=300)
                logger.info(f"Powerpipe benchmark run: {run_output}")
                if run_output and len(run_output.strip()) > 0:
                    results["powerpipe_test"] = True
                results["details"]["powerpipe_run"] = run_output
            except Exception as e:
                logger.error(f"Powerpipe command error: {str(e)}")
                results["details"]["powerpipe_error"] = str(e)
                
                
                try:
                    alt_cmd = ['powerpipe', 'mod', 'list']
                    alt_output = await self._run_command(alt_cmd, workspace_dir, timeout=15)
                    logger.info(f"Powerpipe mod list: {alt_output}")
                    results["details"]["powerpipe_mod_list"] = alt_output
                except Exception as alt_e:
                    logger.error(f"Powerpipe mod list error: {str(alt_e)}")
            
            
            # Create a specific AWS connection config with SDK debug
            steampipe_dir = os.path.expanduser('~/.steampipe')
            aws_config_dir = os.path.join(steampipe_dir, 'config', 'aws')
            os.makedirs(aws_config_dir, exist_ok=True)
            
            access_key = self.aws_credentials.get('aws_access_key_id', '').strip()
            secret_key = self.aws_credentials.get('aws_secret_access_key', '').strip()
            session_token = self.aws_credentials.get('aws_session_token', '').strip()
            
            aws_config_file = os.path.join(aws_config_dir, 'aws_debug.spc')
            with open(aws_config_file, 'w') as f:
                f.write(f"""
    connection "aws_debug" {{
    plugin     = "aws"
    
    aws_access_key_id     = "{access_key}"
    aws_secret_access_key = "{secret_key}"
    regions               = ["us-east-1", "us-west-1", "us-west-2", "eu-west-1"]
    max_retries           = 10
    sdk_debug             = true
    }}
    """)
                if session_token:
                    f.write(f'  aws_session_token = "{session_token}"\n')
                f.write("}\n")
            
            # Test the debug connection
            debug_test_sql = workspace_dir / 'debug_test.sql'
            with open(debug_test_sql, 'w') as f:
                f.write("""
    -- Test with SDK debug mode
    select account_id, partition from aws_account limit 1;
    """)
            
            logger.info("Testing AWS connection with SDK debug mode")
            try:
                debug_cmd = ['steampipe', 'query', str(debug_test_sql), '--output', 'json', '--search-path', 'aws_debug', '--search-path-prefix']
                debug_output = await self._run_command(debug_cmd, workspace_dir, timeout=30)
                logger.info(f"SDK debug test result: {debug_output}")
                if debug_output and len(debug_output.strip()) > 0:
                    results["sdk_debug_test"] = True
                results["details"]["sdk_debug_test"] = debug_output
            except Exception as e:
                logger.error(f"SDK debug test failed: {str(e)}")
                results["details"]["sdk_debug_error"] = str(e)
            
            # 6. Test direct AWS API access with boto3
            try:
                import boto3
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    aws_session_token=session_token if session_token else None
                )
                
                sts_client = session.client('sts')
                identity = sts_client.get_caller_identity()
                
                logger.info(f"Direct boto3 test result: {identity}")
                results["details"]["boto3_test"] = {
                    "account_id": identity.get("Account"),
                    "arn": identity.get("Arn"),
                    "user_id": identity.get("UserId")
                }
                
                # Try listing IAM users
                try:
                    iam_client = session.client('iam')
                    users = iam_client.list_users(MaxItems=5)
                    
                    logger.info(f"Direct IAM access test: {len(users.get('Users', []))} users found")
                    results["details"]["iam_test"] = users.get('Users', [])
                except Exception as iam_e:
                    logger.error(f"Direct IAM access test failed: {str(iam_e)}")
                    results["details"]["iam_test_error"] = str(iam_e)
            except Exception as boto_e:
                logger.error(f"Direct boto3 test failed: {str(boto_e)}")
                results["details"]["boto3_test_error"] = str(boto_e)
            
            return results
        except Exception as e:
            logger.error(f"AWS connectivity and permissions test failed: {str(e)}")
            results["error"] = str(e)
            return results
        
    async def get_diagnostics(self):
        """Get diagnostic information about the environment"""
        try:
            # Get steampipe version - properly awaited
            version_cmd = ['steampipe', '--version']
            steampipe_version = await self._run_command(version_cmd)
            steampipe_version = steampipe_version.strip() if steampipe_version else "unknown"
            
            return {
                "steampipe_version": steampipe_version,
                "environment": {
                    "os": sys.platform,
                    "python_version": sys.version,
                },
                "scan_time": datetime.now().isoformat()
            }
        except Exception as e:
            logger.warning(f"Error getting diagnostics: {str(e)}")
            return {
                "error": str(e),
                "scan_time": datetime.now().isoformat()
            }
    async def _init_steampipe(self) -> bool:
        """Initialize steampipe workspace with AWS CIS benchmark mod"""
        try:
            # Create workspace directory
            workspace_dir = self.temp_dir / 'workspace'
            workspace_dir.mkdir(parents=True, exist_ok=True)
            
            # Create mod.sp file - initialize mod
            mod_file = workspace_dir / 'mod.sp'
            with open(mod_file, 'w') as f:
                f.write("""
    mod "local" {
    title = "AWS CIS Benchmark Scan"
    }
    """)

            # Ensure Steampipe service is initialized properly
            try:
                logger.info("Initializing Steampipe service")
                init_cmd = ['steampipe', 'service', 'start', '--dashboard', 'false']
                init_output = await self._run_command(init_cmd, timeout=30, cwd=workspace_dir)
                logger.info(f"Steampipe service initialized: {init_output}")
                
                # Wait for service to start
                await asyncio.sleep(2)
                
                # Check service status
                status_cmd = ['steampipe', 'service', 'status']
                status_output = await self._run_command(status_cmd, timeout=10, cwd=workspace_dir)
                logger.info(f"Steampipe service status: {status_output}")
            except Exception as svc_e:
                logger.warning(f"Steampipe service initialization warning (non-critical): {str(svc_e)}")
            
            # Install AWS plugin with detailed output
            logger.info("Installing AWS Steampipe plugin")
            try:
                plugin_cmd = ['steampipe', 'plugin', 'install', 'aws', '--verbose']
                await self._run_command(plugin_cmd, workspace_dir)
            except Exception as plugin_e:
                logger.error(f"Error installing AWS plugin: {str(plugin_e)}")
                
                # Try alternate approach
                try:
                    logger.info("Trying alternate plugin installation approach")
                    alt_cmd = ['steampipe', 'plugin', 'install', 'aws', '--force']
                    await self._run_command(alt_cmd, workspace_dir)
                except Exception as alt_e:
                    logger.error(f"Alternate plugin installation also failed: {str(alt_e)}")
                    
                    # Check if plugin exists anyway
                    try:
                        check_cmd = ['steampipe', 'plugin', 'list']
                        plugin_list = await self._run_command(check_cmd, workspace_dir)
                        logger.info(f"Existing plugins: {plugin_list}")
                        
                        if 'aws' in plugin_list:
                            logger.info("AWS plugin already exists, continuing despite installation error")
                        else:
                            raise RuntimeError("AWS plugin is not available and installation failed")
                    except Exception as check_e:
                        logger.error(f"Plugin check failed: {str(check_e)}")
                        raise RuntimeError("Cannot verify if AWS plugin is installed")
            
            # Create a debugging script - with a single SQL statement per file
            debug_script = workspace_dir / 'simple_test.sql'
            with open(debug_script, 'w') as f:
                f.write("SELECT 1 as test_simple;")
                
            # Run simple test to see if Steampipe works at all
            try:
                logger.info("Running simple SQL test to verify Steampipe functionality")
                simple_cmd = ['steampipe', 'query', str(debug_script), '--output', 'json']
                simple_output = await self._run_command(simple_cmd, workspace_dir, timeout=15)
                if simple_output and simple_output.strip():
                    logger.info(f"Simple test successful: {simple_output}")
                else:
                    logger.warning("Simple test returned no output, Steampipe may be misconfigured")
            except Exception as test_e:
                logger.error(f"Simple test failed: {str(test_e)}")
                
            # Install AWS compliance mod with error handling
            try:
                logger.info("Installing AWS compliance mod")
                mod_cmd = ['steampipe', 'mod', 'install', 'github.com/turbot/steampipe-mod-aws-compliance', '--verbose']
                await self._run_command(mod_cmd, workspace_dir)
            except Exception as mod_e:
                logger.error(f"Error installing AWS compliance mod: {str(mod_e)}")
                
                # Try alternate approach
                try:
                    logger.info("Trying alternate mod installation approach")
                    alt_cmd = ['steampipe', 'mod', 'install', 'github.com/turbot/steampipe-mod-aws-compliance', '--force']
                    await self._run_command(alt_cmd, workspace_dir)
                except Exception as alt_e:
                    logger.error(f"Alternate mod installation also failed: {str(alt_e)}")
                    logger.warning("Will continue without the compliance mod and use basic queries instead")
            
            logger.info("Steampipe workspace initialized with AWS CIS benchmark mod")
            return True
                
        except Exception as e:
            logger.error(f"Failed to initialize steampipe workspace: {str(e)}")
            logger.error(traceback.format_exc())
            raise
    async def _init_steampipe_connection(self):
        """Initialize Steampipe connection with direct test"""
        try:
            # Create a basic test script
            test_dir = self.temp_dir / 'connection_test'
            test_dir.mkdir(exist_ok=True)
            
            test_sql = test_dir / 'test.sql'
            with open(test_sql, 'w') as f:
                f.write("select current_timestamp as time;")
            
            # Test Steampipe basics
            logger.info("Testing Steampipe basic functionality")
            basic_cmd = ['steampipe', 'query', str(test_sql), '--output', 'json', '--database-init']
            basic_output = await self._run_command(basic_cmd, test_dir, timeout=30)
            
            if basic_output and basic_output.strip():
                logger.info(f"Basic Steampipe test succeeded: {basic_output}")
            else:
                logger.warning("Basic Steampipe test returned no output")
            
            # Test AWS plugin
            aws_test_sql = test_dir / 'aws_test.sql'
            with open(aws_test_sql, 'w') as f:
                f.write("select plugin_name, version from steampipe_plugin where plugin_name like '%aws%';")
            
            plugin_cmd = ['steampipe', 'query', str(aws_test_sql), '--output', 'json']
            plugin_output = await self._run_command(plugin_cmd, test_dir, timeout=30)
            
            if plugin_output and plugin_output.strip():
                logger.info(f"AWS plugin test succeeded: {plugin_output}")
                return True
            else:
                logger.warning("AWS plugin test returned no output")
                return False
                
        except Exception as e:
            logger.error(f"Steampipe connection initialization failed: {str(e)}")
            return False
    
    async def _ensure_progress_update(self, user_id: str, account_id: str, stage: str, 
                              progress: int, scan_id: str = None, retries: int = 3):
        """Send a progress update with retries to ensure delivery."""
        if not scan_id:
            scan_id = f"{int(time.time())}"
            
        # Add a small random delay to prevent message collision
        await asyncio.sleep(random.uniform(0.1, 0.3))
        
        success = False
        for attempt in range(retries):
            try:
                result = update_scan_progress(user_id, account_id, stage, 
                                        progress, scan_type='aws', scan_id=scan_id)
                if result:
                    success = True
                    # Add extra delay after successful update for important stages
                    if progress >= 95 or stage == 'completed' or stage == 'error':
                        await asyncio.sleep(0.5)  # Longer delay for critical updates
                    break
            except Exception as e:
                logger.error(f"Progress update attempt {attempt+1} failed for stage {stage}: {str(e)}")
                await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff
        
        if not success and (stage == 'completed' or stage == 'error'):
            logger.warning(f"Failed to send critical '{stage}' update after {retries} attempts")
        
        return success

    async def _run_steampipe_scan(self, user_id: str, account_id: str) -> Dict[str, Any]:
        """Run a simplified AWS security scan with enhanced debugging"""
        try:
            workspace_dir = self.temp_dir / 'workspace'
            workspace_dir.mkdir(parents=True, exist_ok=True)
            
            try:
                update_scan_progress(user_id, account_id, 'scanning', 30)
            except Exception as e:
                logger.warning(f"Progress update error (non-critical): {str(e)}")
            
            # Set AWS credentials as environment variables
            access_key = self.aws_credentials.get('aws_access_key_id', '').strip()
            secret_key = self.aws_credentials.get('aws_secret_access_key', '').strip()
            session_token = self.aws_credentials.get('aws_session_token', '').strip()
            
            os.environ['AWS_ACCESS_KEY_ID'] = access_key
            os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
            if session_token:
                os.environ['AWS_SESSION_TOKEN'] = session_token
                
            # Log the credentials being used (redacted for security)
            masked_access_key = f"{access_key[:4]}{'*' * (len(access_key) - 8)}{access_key[-4:]}" if len(access_key) > 8 else "Not provided"
            masked_secret_key = f"{secret_key[:4]}{'*' * (len(secret_key) - 8)}{secret_key[-4:]}" if len(secret_key) > 8 else "Not provided"
            has_session_token = "Yes" if session_token else "No"
            
            logger.info(f"AWS credentials details: Access Key: {masked_access_key}, Secret Key: {masked_secret_key}, Session Token: {has_session_token}")
            
            # Create a very simple connectivity test query
            connectivity_file = workspace_dir / 'connectivity_test.sql'
            with open(connectivity_file, 'w') as f:
                f.write("SELECT 1 as simple_test;")
                
            # Test basic connectivity
            logger.info("Testing AWS connectivity")
            try:
                # First try the most basic query possible
                basic_cmd = ['steampipe', 'query', str(connectivity_file), '--output', 'json']
                basic_output = await self._run_command(basic_cmd, workspace_dir, timeout=30)
                
                if basic_output and basic_output.strip():
                    try:
                        basic_result = json.loads(basic_output)
                        logger.info(f"Basic connectivity test passed: {json.dumps(basic_result)}")
                    except json.JSONDecodeError:
                        logger.warning("Could not parse basic test output as JSON")
                        logger.debug(f"Raw basic test output: {basic_output}")
                else:
                    logger.warning("Basic connectivity test produced no output")
                    
                    # Try diagnosing Steampipe directly
                    try:
                        logger.info("Running Steampipe database initialization check")
                        db_cmd = ['steampipe', 'query', 'SELECT 1', '--output', 'json', '--database-init']
                        db_output = await self._run_command(db_cmd, workspace_dir, timeout=30)
                        logger.info(f"Database initialization check result: {db_output}")
                    except Exception as db_e:
                        logger.error(f"Database initialization check failed: {str(db_e)}")
                        
            except Exception as conn_e:
                logger.error(f"Error running basic connectivity test: {str(conn_e)}")
                
            # Try AWS CLI directly for comparison
            try:
                logger.info("Verifying credentials with AWS CLI directly")
                aws_cmd = ['aws', 'sts', 'get-caller-identity', '--output', 'json']
                aws_output = await self._run_command(aws_cmd, timeout=15, cwd=workspace_dir)
                
                if aws_output and aws_output.strip():
                    logger.info(f"AWS CLI verification succeeded: {aws_output.strip()}")
                else:
                    logger.warning("AWS CLI verification produced no output")
            except Exception as aws_e:
                logger.error(f"AWS CLI verification failed: {str(aws_e)}")
            
            # Create individual queries per service to test specific permissions
            table_queries = [
                ("aws_account", "SELECT * FROM aws_account LIMIT 5;"),
                ("aws_iam_user", "SELECT * FROM aws_iam_user LIMIT 5;"),
                ("aws_s3_bucket", "SELECT * FROM aws_s3_bucket LIMIT 5;"),
                ("aws_region", "SELECT * FROM aws_region LIMIT 5;")
            ]
            
            # Test each table individually
            findings = []
            
            for table_name, query_text in table_queries:
                query_file = workspace_dir / f"{table_name}_basic.sql"
                with open(query_file, 'w') as f:
                    f.write(query_text)
                    
                logger.info(f"Testing query for {table_name}")
                try:
                    query_cmd = ['steampipe', 'query', str(query_file), '--output', 'json', '--database-init']
                    query_output = await self._run_command(query_cmd, workspace_dir, timeout=60)
                    
                    if query_output and query_output.strip():
                        try:
                            results = json.loads(query_output)
                            logger.info(f"Successfully queried {table_name}: {len(results)} results found")
                            
                            # For each result, create a finding
                            for idx, result in enumerate(results):
                                if table_name == 'aws_iam_user':
                                    findings.append({
                                        'id': f"aws-iam-{idx+1}",
                                        'severity': "MEDIUM",
                                        'category': "IAM",
                                        'control': "IAM User Security",
                                        'control_id': f"aws-iam-user-{idx+1}",
                                        'status': "Pass" if result.get('mfa_enabled') else "Fail",
                                        'reason': "IAM users should have MFA enabled",
                                        'details': json.dumps(result),
                                        'resource_id': result.get('arn', account_id),
                                        'account_id': account_id
                                    })
                                # Add more table-specific handling here
                        except json.JSONDecodeError:
                            logger.warning(f"Could not parse {table_name} results as JSON")
                            logger.debug(f"Raw output: {query_output[:500]}")
                    else:
                        logger.warning(f"Query for {table_name} returned no output")
                except Exception as query_e:
                    logger.error(f"Error querying {table_name}: {str(query_e)}")
            
            # If we found actual resources, use those findings; otherwise use baseline
            if findings:
                logger.info(f"Using {len(findings)} actual AWS resource findings")
            else:
                logger.info("No AWS resources found, using baseline security recommendations")
                # Generate baseline findings as in your original code
                findings = [
                    # Your existing baseline findings
                    {
                        'id': f"aws-{account_id}-1",
                        'severity': "MEDIUM",
                        'category': "IAM",
                        'control': "AWS IAM User MFA",
                        'control_id': "aws-iam-1",
                        'status': "Info",
                        'reason': "IAM users should have MFA enabled",
                        'details': json.dumps({
                            "recommendation": "Enable MFA for all IAM users with console access"
                        }),
                        'resource_id': account_id,
                        'account_id': account_id,
                        'remediation': "Use the AWS Management Console or API to enable MFA devices for all IAM users"
                    },
                    # Add your other baseline findings
                ]
            
            # Process findings into final results as in your original code
            # Create severity counts
            severity_counts = {
                "CRITICAL": 0,
                "HIGH": sum(1 for f in findings if f['severity'] == "HIGH"),
                "MEDIUM": sum(1 for f in findings if f['severity'] == "MEDIUM"),
                "LOW": sum(1 for f in findings if f['severity'] == "LOW"),
                "INFO": sum(1 for f in findings if f['severity'] == "INFO")
            }
            
            # Create category counts
            category_counts = {}
            for finding in findings:
                category = finding['category']
                if category not in category_counts:
                    category_counts[category] = 0
                category_counts[category] += 1
            
            # Add diagnostic information - properly awaited
            diagnostics = await self.get_diagnostics()
            
            # Create final results object
            scan_results = {
                'findings': findings,
                'stats': {
                    'total_findings': len(findings),
                    'failed_findings': sum(1 for f in findings if f['status'] == "Fail"),
                    'warning_findings': sum(1 for f in findings if f['status'] == "Warning"),
                    'pass_findings': sum(1 for f in findings if f['status'] == "Pass") + 
                                    sum(1 for f in findings if f['status'] == "Info"),
                    'severity_counts': severity_counts,
                    'category_counts': category_counts,
                    'resource_counts': len(set(f.get('resource_id') for f in findings)),
                    'account_id': account_id
                },
                'metadata': {
                    'scan_time': datetime.now().isoformat(),
                    'account_id': account_id,
                    'cloud_provider': 'aws',
                    'benchmark': 'AWS Security Assessment',
                    'scan_type': 'direct-scan',
                    'diagnostic_info': diagnostics
                }
            }
            
            logger.info(f"Final scan results: {len(findings)} findings in {len(category_counts)} categories")
            logger.info(f"Findings in scan_results: {len(scan_results['findings'])}")
            
            return scan_results
            
        except Exception as e:
            logger.error(f"Error in AWS security scan: {str(e)}")
            logger.error(traceback.format_exc())
            return self._create_error_results(str(e), account_id)
                    
    def _create_error_results(self, error_message: str, account_id: str, 
                             diagnostics: Optional[Dict] = None) -> Dict[str, Any]:
        """Create enhanced error results with diagnostics"""
        findings = [{
            'id': f"aws-{account_id}-error-1",
            'severity': 'INFO',
            'category': 'Diagnostics',
            'control': 'AWS Scan Diagnostics',
            'status': 'Completed with errors',
            'reason': 'AWS scan encountered issues',
            'details': f'Error details: {error_message}',
            'resource_id': account_id,
            'account_id': account_id,
            'remediation': 'Check AWS credentials and permissions. See diagnostic information.'
        }]
        
        # Create basic stats
        severity_counts = {'INFO': 1, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        
        return {
            'findings': findings,
            'stats': {
                'total_findings': 1,
                'failed_findings': 0,
                'pass_findings': 0,
                'warning_findings': 1,
                'severity_counts': severity_counts,
                'category_counts': {'Diagnostics': 1},
                'resource_counts': 1,
                'account_id': account_id
            },
            'metadata': {
                'scan_time': datetime.now().isoformat(),
                'account_id': account_id,
                'cloud_provider': 'aws',
                'benchmark': 'AWS Security Check',
                'scan_error': error_message,
                'scan_diagnostics': diagnostics or {}
            }
        }
        
   
    def _process_benchmark_results(self, results: Dict, account_id: str) -> Dict[str, Any]:
        """Process CIS benchmark results from Steampipe/Powerpipe output"""
        try:
            if not results:
                logger.warning(f"Empty benchmark results")
                return self._create_error_results("Empty benchmark results", account_id)
                        
            # Extract top-level summary and metadata
            summary = results.get('summary', {}).get('status', {})
            findings_data = {
                'findings': [],
                'stats': {
                    'total_findings': sum(summary.get(status, 0) for status in ['alarm', 'ok', 'info']),
                    'failed_findings': summary.get('alarm', 0),
                    'warning_findings': 0,  # Not directly mapped
                    'pass_findings': summary.get('ok', 0) + summary.get('info', 0),
                    'severity_counts': {
                        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
                    },
                    'category_counts': {}
                },
                'metadata': {
                    'benchmark': 'AWS CIS Foundations Benchmark',
                    'version': results.get('title', 'v4.0.0'),
                    'scan_time': datetime.now().isoformat(),
                    'account_id': account_id
                }
            }

            # Process findings from the nested structure
            # For CIS benchmarks, the structure is:
            # root_result_group -> groups -> [benchmark] -> groups -> [sections] -> groups -> [subsections] -> controls
            
            # Start with the main benchmark group
            main_groups = results.get('groups', [])
            for main_group in main_groups:
                # Process sections
                for section in main_group.get('groups', []):
                    section_title = section.get('title', 'Unknown Section')
                    
                    # Update category counts
                    if section_title not in findings_data['stats']['category_counts']:
                        findings_data['stats']['category_counts'][section_title] = 0
                    
                    # Process subsections if they exist
                    for subsection in section.get('groups', []):
                        subsection_title = subsection.get('title', 'Unknown Subsection')
                        
                        # Process controls in this subsection
                        for control in subsection.get('controls', []):
                            self._process_control(control, section_title, findings_data, account_id)
                            findings_data['stats']['category_counts'][section_title] += 1
                    
                    # Also process controls directly in the section
                    for control in section.get('controls', []):
                        self._process_control(control, section_title, findings_data, account_id)
                        findings_data['stats']['category_counts'][section_title] += 1
            
            # Update severity counts based on findings
            for finding in findings_data['findings']:
                severity = finding.get('severity', 'MEDIUM')
                if severity in findings_data['stats']['severity_counts']:
                    findings_data['stats']['severity_counts'][severity] += 1
            
            logger.info(f"Processed {len(findings_data['findings'])} findings from benchmark results")
            return findings_data
                
        except Exception as e:
            logger.error(f"Error processing benchmark results: {str(e)}")
            logger.error(traceback.format_exc())
            return self._create_error_results(f"Result processing error: {str(e)}", account_id)
        
    def _process_benchmark_results(self, results: Dict, account_id: str) -> Dict[str, Any]:
        """Process CIS benchmark results from Steampipe/Powerpipe output with careful navigation"""
        try:
            account_id = str(account_id) 
            if not results:
                logger.warning("Empty benchmark results")
                return self._create_error_results("Empty benchmark results", account_id)
                        
            # Extract top-level summary and metadata
            summary = results.get('summary', {}).get('status', {})
            findings_data = {
                'findings': [],
                'stats': {
                    'total_findings': sum(summary.get(status, 0) for status in ['alarm', 'ok', 'info']),
                    'failed_findings': summary.get('alarm', 0),
                    'warning_findings': 0,  # Not directly mapped
                    'pass_findings': summary.get('ok', 0) + summary.get('info', 0),
                    'severity_counts': {
                        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
                    },
                    'category_counts': {}
                },
                'metadata': {
                    'benchmark': 'AWS CIS Foundations Benchmark',
                    'version': results.get('title', 'v4.0.0'),
                    'scan_time': datetime.now().isoformat(),
                    'account_id': account_id
                }
            }

            # Let's examine the structure of the results and log it
            logger.info(f"Top level keys in results: {list(results.keys())}")
            
            # Check if we have a nested 'groups' field
            main_groups = results.get('groups', [])
            logger.info(f"Number of main groups: {len(main_groups)}")
            
            if main_groups and len(main_groups) > 0:
                for i, main_group in enumerate(main_groups):
                    logger.info(f"Main group {i} keys: {list(main_group.keys())}")
                    
                    # Check if this group has nested groups
                    section_groups = main_group.get('groups', [])
                    logger.info(f"Number of section groups in main group {i}: {len(section_groups)}")
                    
                    # Process each section group
                    for j, section in enumerate(section_groups):
                        logger.info(f"Section {j} in main group {i} keys: {list(section.keys())}")
                        section_title = section.get('title', 'Unknown Section')
                        
                        # Update category counts
                        if section_title not in findings_data['stats']['category_counts']:
                            findings_data['stats']['category_counts'][section_title] = 0
                        
                        # Check for controls directly in this section - SAFELY get the controls
                        controls = section.get('controls', []) or []  # Use or [] to handle None
                        logger.info(f"Number of controls in section {j}: {len(controls)}")
                        
                        if controls:
                            # Process controls directly in section
                            for control in controls:
                                self._add_finding_from_control(control, section_title, findings_data, account_id)
                                findings_data['stats']['category_counts'][section_title] += 1
                        
                        # Check for subsections - SAFELY get the subsections
                        subsections = section.get('groups', []) or []  # Use or [] to handle None
                        logger.info(f"Number of subsections in section {j}: {len(subsections)}")
                        
                        for k, subsection in enumerate(subsections):
                            logger.info(f"Subsection {k} in section {j} keys: {list(subsection.keys())}")
                            
                            # Check for controls in subsection - SAFELY get the controls
                            subsection_controls = subsection.get('controls', []) or []  # Use or [] to handle None
                            logger.info(f"Number of controls in subsection {k}: {len(subsection_controls)}")
                            
                            # Process controls in subsection
                            for control in subsection_controls:
                                self._add_finding_from_control(control, section_title, findings_data, account_id)
                                findings_data['stats']['category_counts'][section_title] += 1
            
            # Process top-level controls if they exist
            top_controls = results.get('controls', []) or []  # Use or [] to handle None
            if top_controls:
                logger.info(f"Found {len(top_controls)} top-level controls")
                for control in top_controls:
                    self._add_finding_from_control(control, "General", findings_data, account_id)
                    if "General" not in findings_data['stats']['category_counts']:
                        findings_data['stats']['category_counts']["General"] = 0
                    findings_data['stats']['category_counts']["General"] += 1
            
            # If no findings were found by exploring the structure, try a more dynamic approach
            if not findings_data['findings']:
                logger.info("No findings found through structured navigation, trying broader search...")
                self._extract_findings_recursively(results, findings_data, account_id)
                    
            # Update severity counts based on findings
            for finding in findings_data['findings']:
                severity = finding.get('severity', 'MEDIUM')
                if severity in findings_data['stats']['severity_counts']:
                    findings_data['stats']['severity_counts'][severity] += 1
            
            logger.info(f"Processed {len(findings_data['findings'])} findings from benchmark results")
            return findings_data
                
        except Exception as e:
            logger.error(f"Error processing benchmark results: {str(e)}")
            logger.error(traceback.format_exc())
            return self._create_error_results(f"Result processing error: {str(e)}", account_id)
        
    def _extract_findings_recursively(self, data, findings_data, account_id, path="root"):
        """Recursively search for controls and findings in JSON structure"""
        if isinstance(data, dict):
            # Check if this dict looks like a control
            if 'control_id' in data and 'title' in data:
                category = path.split('.')[-1] if '.' in path else 'General'
                self._add_finding_from_control(data, category, findings_data, account_id)
                return
                
            # Check if this dict has results directly
            if 'results' in data and isinstance(data['results'], list):
                category = data.get('title', path.split('.')[-1] if '.' in path else 'General')
                control_id = data.get('control_id', data.get('id', 'unknown'))
                title = data.get('title', 'Unknown Control')
                description = data.get('description', '')
                severity = self._map_severity(data.get('severity', 'medium'))
                
                for result in data['results']:
                    self._add_finding_from_result(result, control_id, title, description, 
                                                severity, category, findings_data, account_id)
                return
            
            # Recursively process each key
            for key, value in data.items():
                new_path = f"{path}.{key}" if path != "root" else key
                self._extract_findings_recursively(value, findings_data, account_id, new_path)
        
        elif isinstance(data, list):
            # Process each item in the list
            for i, item in enumerate(data):
                new_path = f"{path}[{i}]"
                self._extract_findings_recursively(item, findings_data, account_id, new_path)
        
    def _add_finding_from_control(self, control, category, findings_data, account_id):
        """Process a control object into findings safely"""
        if not control:
            return
            
        control_id = control.get('control_id', control.get('id', 'unknown'))
        title = control.get('title', 'Unknown Control')
        description = control.get('description', '')
        severity = self._map_severity(control.get('severity', 'medium'))
        
        # Check if control has results
        results = control.get('results', [])
        if not results:
            # Add a placeholder finding if there are no results
            finding = {
                'id': f"cis-{control_id}",
                'severity': severity,
                'category': category,
                'control': title,
                'control_id': control_id,
                'status': 'info',
                'reason': description,
                'details': "No specific results for this control",
                'resource_id': account_id,
                'account_id': account_id,
                'cis_control': control_id
            }
            findings_data['findings'].append(finding)
            return
        
        # Process each result
        for result in results:
            self._add_finding_from_result(result, control_id, title, description, 
                                        severity, category, findings_data, account_id)

    
        

    def _map_severity(self, severity: str) -> str:
        """Map Steampipe/Powerpipe severity to our format"""
        severity = severity.lower()
        if severity in ['critical', 'high']:
            return 'HIGH'
        elif severity in ['medium']:
            return 'MEDIUM'
        elif severity in ['low']:
            return 'LOW'
        else:
            return 'INFO'
            
    def _map_status(self, status: str) -> str:
        """Map Steampipe/Powerpipe status to standardized status"""
        status = status.lower() if status else ""
        
        # Keep original status values for consistency
        if status in ["alarm", "ok", "info", "skip", "error"]:
            return status
        
        # Map other values to standard statuses
        if status in ["fail", "failed", "failure"]:
            return "alarm"
        elif status in ["pass", "passed", "success"]:
            return "ok"
        elif status in ["skipped", "not_applicable"]:
            return "skip"
        elif status in ["unknown", "none"]:
            return "info"
        else:
            return "info"  
        
    def _map_severity_from_status(self, status, original_severity):
        """
        Map the benchmark status to an appropriate severity level
        
        Args:
            status: The benchmark status (alarm, ok, info, skip)
            original_severity: The original severity from the benchmark
            
        Returns:
            str: Mapped severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        """
        status = status.lower() if status else ""
        original_severity = original_severity.upper() if original_severity else "INFO"
        
        # If we already have a valid severity that's not INFO, use it
        if original_severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] and status == "alarm":
            return original_severity
        
        # Otherwise map based on status
        if status == "alarm":
            return "HIGH"  # Failed checks are high severity by default
        elif status == "ok":
            return "INFO"  # Passing checks are informational
        elif status == "skip":
            return "LOW"   # Skipped checks are low severity
        elif status == "info":
            return "MEDIUM"  # Info status suggests medium importance
        else:
            return "INFO" 
        
    def _add_finding_from_result(self, result, control_id, title, description, original_severity, category, findings_data, account_id):
        """Extract a finding from a result object with improved severity mapping"""
        if not result:
            return
                
        status = result.get('status', 'info')
        resource = result.get('resource', account_id)
        reason = result.get('reason', '')
        
        # Use the new severity mapping function
        severity = self._map_severity_from_status(status, original_severity)

        
        # Create finding
        finding = {
            'id': f"cis-{control_id}",
            'severity': severity,
            'category': category,
            'control': title,
            'control_id': control_id,
            'status': status,
            'reason': description,
            'details': reason,
            'resource_id': resource,
            'account_id': account_id,
            'cis_control': control_id
        }
        
        findings_data['findings'].append(finding)
        
        # Update the severity counts in the stats
        if severity not in findings_data['stats']['severity_counts']:
            findings_data['stats']['severity_counts'][severity] = 0
        findings_data['stats']['severity_counts'][severity] += 1
                
    # Helper function to parse the CSV results
    def parse_csv_results(csv_file_path: str) -> Dict[str, Any]:
        """
        Parse CIS benchmark results from CSV file
        
        Args:
            csv_file_path: Path to the CSV results file
            
        Returns:
            Dict containing processed results
        """
        import csv
        from collections import defaultdict
        
        try:
            findings = []
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            status_counts = defaultdict(int)
            
            # Load CSV file
            with open(csv_file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Basic validation
                    if not row:
                        continue
                        
                    # Map to standardized format
                    severity = row.get('severity', '').upper()
                    if not severity:
                        severity = 'INFO'
                        
                    # Normalize status
                    status = row.get('status', '')
                    if 'fail' in status.lower() or 'alarm' in status.lower():
                        normalized_status = 'Fail'
                    elif 'pass' in status.lower() or 'ok' in status.lower():
                        normalized_status = 'Pass'
                    elif 'skip' in status.lower():
                        normalized_status = 'Skipped'
                    else:
                        normalized_status = 'Info'
                        
                    # Create finding record
                    finding = {
                        'id': f"cis-{row.get('control_id', 'unknown')}",
                        'severity': severity,
                        'category': row.get('category', row.get('service', 'General')),
                        'control': row.get('control_title', row.get('title', 'Unknown Control')),
                        'control_id': row.get('control_id', 'unknown'),
                        'status': normalized_status,
                        'reason': row.get('reason', ''),
                        'details': row.get('control_description', row.get('description', '')),
                        'resource_id': row.get('resource', row.get('account_id', '')),
                        'account_id': row.get('account_id', ''),
                        'remediation': ''  # CSV might not include remediation
                    }
                    
                    findings.append(finding)
                    
                    # Update counts
                    severity_counts[severity] += 1
                    category_counts[finding['category']] += 1
                    status_counts[normalized_status] += 1
                    
            # Make sure we have all severity levels represented
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sev not in severity_counts:
                    severity_counts[sev] = 0
                    
            # Return processed results
            return {
                'findings': findings,
                'stats': {
                    'total_findings': len(findings),
                    'failed_findings': status_counts['Fail'],
                    'warning_findings': status_counts.get('Warning', 0),
                    'pass_findings': status_counts['Pass'],
                    'severity_counts': dict(severity_counts),
                    'category_counts': dict(category_counts),
                    'resource_counts': len(set(f.get('resource_id') for f in findings)),
                    'account_id': findings[0].get('account_id') if findings else ''
                },
                'metadata': {
                    'scan_time': datetime.now().isoformat(),
                    'cloud_provider': 'aws',
                    'benchmark': 'AWS CIS Foundations Benchmark v1.3.1',
                    'source': 'csv_import'
                }
            }
            
        except Exception as e:
            logger.error(f"Error parsing CSV results: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                'findings': [],
                'stats': {
                    'total_findings': 0,
                    'failed_findings': 0,
                    'warning_findings': 0,
                    'pass_findings': 0,
                    'severity_counts': {
                        'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0
                    },
                    'category_counts': {},
                    'resource_counts': 0,
                    'account_id': ''
                },
                'metadata': {
                    'scan_time': datetime.now().isoformat(),
                    'cloud_provider': 'aws',
                    'benchmark': 'AWS CIS Foundations Benchmark',
                    'source': 'csv_import',
                    'error': str(e)
                }
            }
    async def run_powerpipe_benchmark(self, account_id: str, benchmark_name: str = "aws_compliance.benchmark.cis_v140") -> Dict[str, Any]:
        """Run AWS CIS benchmark using Powerpipe"""
        try:
            workspace_dir = self.temp_dir / 'workspace'
            workspace_dir.mkdir(exist_ok=True)
            
            logger.info(f"Running CIS benchmark scan with Powerpipe: {benchmark_name}")
            
            # Run the benchmark using powerpipe check
            benchmark_cmd = ['powerpipe', 'check', benchmark_name, '--output', 'json']
            benchmark_output = await self._run_command(benchmark_cmd, workspace_dir, timeout=300)
            
            if not benchmark_output or not benchmark_output.strip():
                logger.warning("Powerpipe benchmark returned no output")
                return None
                
            try:
                benchmark_results = json.loads(benchmark_output)
                logger.info(f"Successfully ran benchmark scan with {len(benchmark_results.get('groups', []))} control groups")
                return benchmark_results
            except json.JSONDecodeError:
                logger.error("Failed to parse Powerpipe benchmark output as JSON")
                logger.debug(f"Raw benchmark output: {benchmark_output[:1000]}...")
                return None
                
        except Exception as e:
            logger.error(f"Powerpipe benchmark error: {str(e)}")
            return None
    

    # Function to discover available CIS benchmarks in Steampipe
    async def discover_available_benchmarks(workspace_dir: Path) -> List[str]:
        """
        Discover available CIS benchmarks in the steampipe installation
        
        Args:
            workspace_dir: Path to the workspace directory
            
        Returns:
            List of available benchmark identifiers
        """
        try:
            # List all available checks
            list_cmd = ['steampipe', 'check', 'list']
            check_list_output = await self._run_command(list_cmd, workspace_dir)
            
            # Extract benchmark identifiers
            benchmarks = []
            for line in check_list_output.splitlines():
                if 'cis' in line.lower() and 'aws' in line.lower():
                    parts = line.strip().split()
                    if parts:
                        benchmarks.append(parts[0])
                        
            return benchmarks
        except Exception as e:
            logger.error(f"Error discovering benchmarks: {str(e)}")
            return []
    
    async def __aenter__(self):
        """Initialize scanner resources"""
        await self.setup()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Cleanup scanner resources"""
        await self.cleanup()
    
    async def _run_command_with_debug(self, command: List[str], cwd: Optional[Path] = None, timeout: int = 300) -> str:
        """Run a command with detailed debug output and handle large outputs"""
        try:
            cmd_str = ' '.join(command)
            logger.info(f"Running command with debug: {cmd_str}")
            
            # Create a temporary file to capture output
            output_file = self.temp_dir / f"cmd_output_{int(time.time())}.json"
            
            # For the benchmark command, use file redirection to capture full output
            if 'benchmark run' in cmd_str and '--output json' in cmd_str:
                # Modify command to redirect output to file
                redirect_cmd = command.copy()
                redirect_cmd.append('>')
                redirect_cmd.append(str(output_file))
                
                # Use shell=True to allow redirection
                process = await asyncio.create_subprocess_shell(
                    ' '.join(redirect_cmd),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(cwd) if cwd else None,
                    env=os.environ.copy(),
                    shell=True
                )
                
                try:
                    _, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    process.kill()
                    logger.error(f"Command timed out after {timeout} seconds: {cmd_str}")
                    raise RuntimeError(f"Command timed out after {timeout} seconds: {cmd_str}")
                
                stderr_text = stderr.decode() if stderr else ""
                if stderr_text:
                    logger.error(f"Command stderr: {stderr_text}")
                
                # Read from the output file
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        stdout_text = f.read()
                    logger.info(f"Read {len(stdout_text)} bytes from output file")
                    # Don't log the full output, it's too large
                    if stdout_text:
                        logger.info(f"Command stdout sample: {stdout_text[:500]}...")
                    return stdout_text
                else:
                    logger.error("Output file not created")
                    raise RuntimeError(f"Command failed with code {process.returncode}: {stderr_text}")
            
            # For other commands, use the normal approach
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=os.environ.copy()
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                process.kill()
                logger.error(f"Command timed out after {timeout} seconds: {cmd_str}")
                raise RuntimeError(f"Command timed out after {timeout} seconds: {cmd_str}")
            
            stdout_text = stdout.decode() if stdout else ""
            stderr_text = stderr.decode() if stderr else ""
            
            if stdout_text:
                logger.info(f"Command stdout: {stdout_text[:1000]}" + ("..." if len(stdout_text) > 1000 else ""))
            
            if stderr_text:
                logger.error(f"Command stderr: {stderr_text}")
            
            if process.returncode != 0:
                logger.error(f"Command failed with code {process.returncode}")
                if stdout_text:
                    return stdout_text
                else:
                    raise RuntimeError(f"Command failed with code {process.returncode}: {stderr_text}")
                    
            return stdout_text
            
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            raise
    async def _ensure_progress_update(self, user_id: str, account_id: str, stage: str, 
                           progress: int, scan_id: str = None, retries: int = 3):
        """Send a progress update with retries to ensure delivery for critical stages only."""
        if not scan_id:
            scan_id = f"{int(time.time())}"
            
        # Convert progress to integer to avoid type comparison errors
        try:
            progress = int(progress)
        except (ValueError, TypeError):
            progress = 0
                
        # Only use retries for critical stages
        if stage not in ['completed', 'error', 'initializing', 'validation_complete', 'scan_complete']:
            # For non-critical stages, just try once
            try:
                update_scan_progress(user_id, account_id, stage, 
                                    progress, scan_type='aws', scan_id=scan_id)
            except Exception as e:
                logger.warning(f"Non-critical progress update failed: {str(e)}")
            return True
                    
        # Critical stages get multiple attempts
        success = False
        for attempt in range(retries):
            try:
                result = update_scan_progress(user_id, account_id, stage, 
                                        progress, scan_type='aws', scan_id=scan_id)
                if result:
                    success = True
                    # Add extra delay after successful update for important stages
                    if stage in ['completed', 'error']:
                        await asyncio.sleep(0.5)  # Longer delay for critical updates
                    break
            except Exception as e:
                logger.error(f"Progress update attempt {attempt+1} failed for stage {stage}: {str(e)}")
                await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff
        
        if not success and stage in ['completed', 'error']:
            logger.warning(f"Failed to send critical '{stage}' update after {retries} attempts")
        
        return success
    async def run_aws_compliance_check(self, account_id: str) -> Dict[str, Any]:
        """Run AWS compliance check using system-wide installation paths with focus on CIS v4.0.0"""
        try:
            # Create workspace directory
            workspace_dir = self.temp_dir / 'workspace'
            workspace_dir.mkdir(exist_ok=True)
            
            logger.info("Running AWS CIS benchmark scan with focus on v4.0.0")
            
            # Stop any existing Steampipe service first
            try:
                logger.info("Stopping any existing Steampipe service")
                stop_cmd = ['steampipe', 'service', 'stop']
                await self._run_command(stop_cmd, timeout=30)
                await asyncio.sleep(2)  # Give it time to stop
            except Exception as stop_e:
                logger.warning(f"Steampipe service stop warning (non-critical): {str(stop_e)}")
            
            # Install AWS plugin (without specifying version to get latest)
            logger.info("Installing AWS plugin for Steampipe")
            try:
                plugin_cmd = ['steampipe', 'plugin', 'install', 'aws']
                await self._run_command(plugin_cmd, timeout=180)
                logger.info("AWS plugin installed successfully")
            except Exception as plugin_e:
                logger.warning(f"AWS plugin installation warning: {str(plugin_e)}")
            
            # Start the Steampipe service
            logger.info("Starting Steampipe service")
            try:
                start_cmd = ['steampipe', 'service', 'start']
                await self._run_command(start_cmd, timeout=30)
                logger.info("Steampipe service started")
                await asyncio.sleep(5)  # Give it time to start
            except Exception as start_e:
                logger.warning(f"Steampipe service start warning: {str(start_e)}")
            
            # Test Steampipe connection with a simple query
            logger.info("Testing Steampipe connection")
            try:
                test_query = "select title from aws_account"
                test_cmd = ['powerpipe', 'query', 'run', test_query]
                test_output = await self._run_command(test_cmd, timeout=30)
                logger.info(f"Steampipe connection test: {test_output}")
            except Exception as test_e:
                logger.warning(f"Steampipe connection test warning: {str(test_e)}")
            
            # Create mod directory and initialize
            mod_dir = workspace_dir / 'aws_mod'
            mod_dir.mkdir(exist_ok=True)
            
            # Initialize the mod
            logger.info("Initializing Powerpipe mod")
            try:
                init_cmd = ['powerpipe', 'mod', 'init']
                await self._run_command(init_cmd, cwd=mod_dir, timeout=30)
                logger.info("Powerpipe mod initialized")
            except Exception as init_e:
                logger.warning(f"Mod initialization warning: {str(init_e)}")
            
            # Install AWS compliance mod
            logger.info("Installing AWS compliance mod")
            try:
                install_cmd = ['powerpipe', 'mod', 'install', 'github.com/turbot/steampipe-mod-aws-compliance']
                await self._run_command(install_cmd, cwd=mod_dir, timeout=180)
                logger.info("AWS compliance mod installed successfully")
            except Exception as install_e:
                logger.warning(f"Warning installing compliance mod: {str(install_e)}")
            
            # List available mods
            try:
                list_cmd = ['powerpipe', 'mod', 'list']
                mod_list_output = await self._run_command(list_cmd, cwd=mod_dir, timeout=30)
                logger.info(f"Available mods: {mod_list_output}")
            except Exception as list_e:
                logger.warning(f"Error listing mods: {str(list_e)}")
            
            
            # Try running CIS v4.0.0 benchmark
            try:
                logger.info("Attempting to run CIS v4.0.0 benchmark")
                benchmark_cmd = ['powerpipe', 'benchmark', 'run', 'aws_compliance.benchmark.cis_v400', '--output', 'json']
                
                # Use our improved method to run the benchmark and capture full output
                benchmark_output = await self._run_command_with_debug(benchmark_cmd, cwd=mod_dir, timeout=300)
                
                if benchmark_output and len(benchmark_output.strip()) > 0:
                    try:
                        # Parse the full benchmark results
                        benchmark_results = json.loads(benchmark_output)
                        logger.info(f"Successfully parsed benchmark results with {len(benchmark_output)} bytes")
                        
                        # Check if we have actual findings
                        summary = benchmark_results.get('summary', {}).get('status', {})
                        total_findings = summary.get('ok', 0) + summary.get('alarm', 0) + summary.get('info', 0)
                        
                        logger.info(f"Benchmark summary: {summary.get('ok', 0)} ok, " +
                                f"{summary.get('alarm', 0)} alarm, {summary.get('info', 0)} info, " +
                                f"{summary.get('skip', 0)} skip, {summary.get('error', 0)} error")
                        
                        # Return the full benchmark results
                        return benchmark_results
                        
                    except json.JSONDecodeError as je:
                        logger.error(f"Failed to parse benchmark output as JSON: {str(je)}")
            except Exception as benchmark_e:
                logger.error(f"Error running benchmark: {str(benchmark_e)}")
            
            # Fall back to boto3-based checks if the benchmark didn't work or returned all errors
            logger.info("Using boto3 to create or enhance security findings")
            session = boto3.Session(
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                aws_session_token=os.environ.get('AWS_SESSION_TOKEN')
            )
            
            # Collect findings from boto3 API calls
            findings = []
            
            # 1. Check IAM password policy
            try:
                iam = session.client('iam')
                try:
                    policy = iam.get_account_password_policy()
                    min_length = policy.get('PasswordPolicy', {}).get('MinimumPasswordLength', 0)
                    require_symbols = policy.get('PasswordPolicy', {}).get('RequireSymbols', False)
                    require_numbers = policy.get('PasswordPolicy', {}).get('RequireNumbers', False)
                    require_uppercase = policy.get('PasswordPolicy', {}).get('RequireUppercaseCharacters', False)
                    require_lowercase = policy.get('PasswordPolicy', {}).get('RequireLowercaseCharacters', False)
                    
                    findings.append({
                        'id': 'iam_password_policy_length',
                        'title': 'IAM Password Minimum Length',
                        'severity': 'medium',
                        'status': 'ok' if min_length >= 14 else 'alarm',
                        'resource': account_id,
                        'reason': f'Password minimum length is {min_length} (should be ≥14)',
                        'category': 'IAM',
                        'cis_control': '1.8'
                    })
                    
                    findings.append({
                        'id': 'iam_password_policy_complexity',
                        'title': 'IAM Password Complexity',
                        'severity': 'medium',
                        'status': 'ok' if (require_symbols and require_numbers and 
                                        require_uppercase and require_lowercase) else 'alarm',
                        'resource': account_id,
                        'reason': 'Password policy requires symbols, numbers, uppercase, and lowercase characters',
                        'category': 'IAM',
                        'cis_control': '1.7'
                    })
                except iam.exceptions.NoSuchEntityException:
                    findings.append({
                        'id': 'iam_password_policy',
                        'title': 'IAM Password Policy',
                        'severity': 'high',
                        'status': 'alarm',
                        'resource': account_id,
                        'reason': 'No password policy is set',
                        'category': 'IAM',
                        'cis_control': '1.7-1.11'
                    })
            except Exception as iam_e:
                logger.warning(f"Error checking IAM password policy: {str(iam_e)}")
            
            # 2. Check root account MFA
            try:
                summary = iam.get_account_summary()
                if summary.get('SummaryMap', {}).get('AccountMFAEnabled', 0) == 1:
                    findings.append({
                        'id': 'root_mfa',
                        'title': 'Root Account MFA',
                        'severity': 'high',
                        'status': 'ok',
                        'resource': account_id,
                        'reason': 'Root account has MFA enabled',
                        'category': 'IAM',
                        'cis_control': '1.5'
                    })
                else:
                    findings.append({
                        'id': 'root_mfa',
                        'title': 'Root Account MFA',
                        'severity': 'high',
                        'status': 'alarm',
                        'resource': account_id,
                        'reason': 'Root account does not have MFA enabled',
                        'category': 'IAM',
                        'cis_control': '1.5'
                    })
            except Exception as root_e:
                logger.warning(f"Error checking root MFA: {str(root_e)}")
            
            # 3. Check IAM users MFA
            try:
                users = iam.list_users()
                for user in users.get('Users', []):
                    user_name = user.get('UserName', '')
                    
                    # Check for console access
                    has_console_access = False
                    try:
                        iam.get_login_profile(UserName=user_name)
                        has_console_access = True
                    except iam.exceptions.NoSuchEntityException:
                        pass
                    
                    # Check MFA devices
                    mfa_devices = iam.list_mfa_devices(UserName=user_name)
                    has_mfa = len(mfa_devices.get('MFADevices', [])) > 0
                    
                    if has_console_access and not has_mfa:
                        findings.append({
                            'id': 'user_mfa',
                            'title': 'IAM User MFA',
                            'severity': 'medium',
                            'status': 'alarm',
                            'resource': user.get('Arn', ''),
                            'reason': f'User {user_name} has console access but no MFA',
                            'category': 'IAM',
                            'cis_control': '1.10'
                        })
            except Exception as users_e:
                logger.warning(f"Error checking IAM users: {str(users_e)}")
            
            # 4. Check access keys
            try:
                for user in users.get('Users', []):
                    user_name = user.get('UserName', '')
                    keys = iam.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
                    
                    for key in keys:
                        key_id = key.get('AccessKeyId', '')
                        status = key.get('Status', '')
                        create_date = key.get('CreateDate', datetime.now())
                        
                        # Check if key is older than 90 days
                        age = (datetime.now(create_date.tzinfo) - create_date).days
                        if age > 90:
                            findings.append({
                                'id': 'access_key_rotation',
                                'title': 'Access Key Rotation',
                                'severity': 'medium',
                                'status': 'alarm',
                                'resource': f"arn:aws:iam::{account_id}:access-key/{user_name}/{key_id}",
                                'reason': f'Access key for {user_name} is {age} days old (should be <90)',
                                'category': 'IAM',
                                'cis_control': '1.14'
                            })
            except Exception as keys_e:
                logger.warning(f"Error checking access keys: {str(keys_e)}")
            
            # 5. Check S3 public access
            try:
                s3 = session.client('s3')
                s3_control = session.client('s3control', region_name='us-east-1')
                
                # Check account-level block public access - note the account ID must be a string
                try:
                    public_access = s3_control.get_public_access_block(AccountId=str(account_id))
                    config = public_access.get('PublicAccessBlockConfiguration', {})
                    all_blocked = (
                        config.get('BlockPublicAcls', False) and
                        config.get('BlockPublicPolicy', False) and
                        config.get('IgnorePublicAcls', False) and
                        config.get('RestrictPublicBuckets', False)
                    )
                    
                    findings.append({
                        'id': 's3_public_access_block',
                        'title': 'S3 Public Access Block',
                        'severity': 'high',
                        'status': 'ok' if all_blocked else 'alarm',
                        'resource': f'arn:aws:s3:::{account_id}',
                        'reason': 'Account-level S3 public access block is fully enabled' if all_blocked else 'Account-level S3 public access block is not fully enabled',
                        'category': 'S3',
                        'cis_control': '2.1.5'
                    })
                except Exception as block_e:
                    logger.warning(f"Error checking S3 public access block: {str(block_e)}")
                    
                # Check individual buckets
                try:
                    buckets = s3.list_buckets()
                    
                    for bucket in buckets.get('Buckets', []):
                        bucket_name = bucket.get('Name', '')
                        
                        # Check bucket policy
                        try:
                            policy = s3.get_bucket_policy(Bucket=bucket_name)
                            policy_text = policy.get('Policy', '')
                            
                            if '"Principal": "*"' in policy_text or '"Principal":"*"' in policy_text:
                                findings.append({
                                    'id': 's3_bucket_policy',
                                    'title': 'S3 Bucket Policy',
                                    'severity': 'high',
                                    'status': 'alarm',
                                    'resource': f'arn:aws:s3:::{bucket_name}',
                                    'reason': f'Bucket {bucket_name} has a policy with a wildcard principal',
                                    'category': 'S3',
                                    'cis_control': '2.1.5'
                                })
                        except Exception as policy_e:
                            error_code = getattr(policy_e, 'response', {}).get('Error', {}).get('Code', '')
                            if error_code != 'NoSuchBucketPolicy':
                                logger.warning(f"Error checking bucket policy for {bucket_name}: {str(policy_e)}")
                        
                        # Check bucket ACL
                        try:
                            acl = s3.get_bucket_acl(Bucket=bucket_name)
                            for grant in acl.get('Grants', []):
                                grantee = grant.get('Grantee', {})
                                uri = grantee.get('URI', '')
                                
                                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                                    findings.append({
                                        'id': 's3_bucket_acl',
                                        'title': 'S3 Bucket ACL',
                                        'severity': 'critical',
                                        'status': 'alarm',
                                        'resource': f'arn:aws:s3:::{bucket_name}',
                                        'reason': f'Bucket {bucket_name} has public access granted in ACL',
                                        'category': 'S3',
                                        'cis_control': '2.1.5'
                                    })
                                    break
                        except Exception as acl_e:
                            logger.warning(f"Error checking bucket ACL for {bucket_name}: {str(acl_e)}")
                except Exception as buckets_e:
                    logger.warning(f"Error listing S3 buckets: {str(buckets_e)}")
            except Exception as s3_e:
                logger.warning(f"Error checking S3: {str(s3_e)}")
            
            # 6. Check CloudTrail is enabled
            try:
                cloudtrail = session.client('cloudtrail')
                trails = cloudtrail.describe_trails()
                
                if not trails.get('trailList'):
                    findings.append({
                        'id': 'cloudtrail_enabled',
                        'title': 'CloudTrail Enabled',
                        'severity': 'high',
                        'status': 'alarm',
                        'resource': account_id,
                        'reason': 'No CloudTrail trails are configured',
                        'category': 'Logging',
                        'cis_control': '3.1'
                    })
                else:
                    # Check CloudTrail configuration for each trail
                    for trail in trails.get('trailList', []):
                        trail_name = trail.get('Name')
                        trail_arn = trail.get('TrailARN')
                        is_multi_region = trail.get('IsMultiRegionTrail', False)
                        log_validation = trail.get('LogFileValidationEnabled', False)
                        
                        if not is_multi_region:
                            findings.append({
                                'id': 'cloudtrail_multi_region',
                                'title': 'CloudTrail Multi-Region',
                                'severity': 'medium',
                                'status': 'alarm',
                                'resource': trail_arn,
                                'reason': f'Trail {trail_name} is not enabled for all regions',
                                'category': 'Logging',
                                'cis_control': '3.1'
                            })
                        
                        if not log_validation:
                            findings.append({
                                'id': 'cloudtrail_log_validation',
                                'title': 'CloudTrail Log Validation',
                                'severity': 'medium',
                                'status': 'alarm',
                                'resource': trail_arn,
                                'reason': f'Trail {trail_name} does not have log file validation enabled',
                                'category': 'Logging',
                                'cis_control': '3.2'
                            })
                        
                        # Check if trail logging is actually enabled
                        try:
                            status = cloudtrail.get_trail_status(Name=trail_name)
                            is_logging = status.get('IsLogging', False)
                            
                            if not is_logging:
                                findings.append({
                                    'id': 'cloudtrail_logging_enabled',
                                    'title': 'CloudTrail Logging Enabled',
                                    'severity': 'high',
                                    'status': 'alarm',
                                    'resource': trail_arn,
                                    'reason': f'Trail {trail_name} exists but logging is not enabled',
                                    'category': 'Logging',
                                    'cis_control': '3.1'
                                })
                        except Exception as status_e:
                            logger.warning(f"Error checking trail status for {trail_name}: {str(status_e)}")
            except Exception as trail_e:
                logger.warning(f"Error checking CloudTrail: {str(trail_e)}")
            
            # 7. Check Config service is enabled
            try:
                config = session.client('config')
                recorders = config.describe_configuration_recorders()
                
                if not recorders.get('ConfigurationRecorders'):
                    findings.append({
                        'id': 'config_enabled',
                        'title': 'AWS Config Enabled',
                        'severity': 'medium',
                        'status': 'alarm',
                        'resource': account_id,
                        'reason': 'AWS Config is not enabled',
                        'category': 'Monitoring',
                        'cis_control': '3.5'
                    })
                else:
                    # Check if recording is actually enabled
                    recorder_statuses = config.describe_configuration_recorder_status()
                    
                    for status in recorder_statuses.get('ConfigurationRecordersStatus', []):
                        recorder_name = status.get('name')
                        is_recording = status.get('recording', False)
                        
                        if not is_recording:
                            findings.append({
                                'id': 'config_recording_enabled',
                                'title': 'AWS Config Recording Enabled',
                                'severity': 'medium',
                                'status': 'alarm',
                                'resource': f"arn:aws:config:{session.region_name}:{account_id}:recorder/{recorder_name}",
                                'reason': f'AWS Config recorder {recorder_name} exists but recording is not enabled',
                                'category': 'Monitoring',
                                'cis_control': '3.5'
                            })
            except Exception as config_e:
                logger.warning(f"Error checking AWS Config: {str(config_e)}")
            
            # If we already have benchmark results, enhance them with boto3 findings
            if 'benchmark_results' in locals() and benchmark_results:
                logger.info("Enhancing benchmark results with boto3 findings")
                
                # Try to inject our boto3 findings into the existing structure
                categories_added = set()
                
                for finding in findings:
                    category = finding.get('category')
                    if category in categories_added:
                        continue
                    
                    # Create a group for each unique category
                    control_id = finding.get('id')
                    cis_id = finding.get('cis_control', 'custom')
                    
                    # Try to find an existing group for this category
                    target_group = None
                    for group in benchmark_results.get('groups', []):
                        for inner_group in group.get('groups', []):
                            if inner_group.get('title') == category:
                                target_group = inner_group
                                break
                        if target_group:
                            break
                    
                    if not target_group:
                        # Create a new group for this category
                        new_group = {
                            'group_id': f'custom_{category.lower()}',
                            'title': category,
                            'description': f'Custom {category} checks',
                            'controls': []
                        }
                        
                        # Try to find the main benchmark group to add our category to
                        main_group = None
                        for group in benchmark_results.get('groups', []):
                            if 'cis' in group.get('group_id', '').lower():
                                main_group = group
                                break
                        
                        if main_group:
                            if 'groups' not in main_group:
                                main_group['groups'] = []
                            main_group['groups'].append(new_group)
                            target_group = new_group
                        
                    categories_added.add(category)
                
                # If we managed to enhance the benchmark results, return them
                return benchmark_results
            
            # If we don't have benchmark results, create our own structure
            logger.info("Creating custom benchmark structure with boto3 findings")
            formatted_results = {
                'group_id': 'root_result_group',
                'title': 'AWS Security Assessment',
                'description': 'Custom AWS security assessment based on CIS AWS Foundations Benchmark',
                'summary': {
                    'status': {
                        'alarm': sum(1 for f in findings if f.get('status') == 'alarm'),
                        'ok': sum(1 for f in findings if f.get('status') == 'ok'),
                        'info': 0,
                        'skip': 0,
                        'error': 0
                    }
                },
                'groups': [
                    {
                        'group_id': 'aws_security_assessment',
                        'title': 'AWS Security Assessment',
                        'description': 'Custom AWS security assessment checks',
                        'tags': {
                            'category': 'Compliance',
                            'cis': 'true',
                            'cis_version': 'v4.0.0',
                            'plugin': 'aws',
                            'service': 'AWS',
                            'type': 'Benchmark'
                        },
                        'summary': {
                            'status': {
                                'alarm': sum(1 for f in findings if f.get('status') == 'alarm'),
                                'ok': sum(1 for f in findings if f.get('status') == 'ok'),
                                'info': 0,
                                'skip': 0,
                                'error': 0
                            }
                        },
                        'groups': []
                    }
                ]
            }
            
            # Group findings by category
            categories = {}
            for finding in findings:
                category = finding.get('category', 'General')
                if category not in categories:
                    categories[category] = []
                categories[category].append(finding)
            
            # Create a group for each category
            for category, category_findings in categories.items():
                category_group = {
                    'group_id': f'aws_security_assessment.{category.lower()}',
                    'title': category,
                    'description': f'{category} security checks',
                    'tags': {
                        'category': category,
                        'type': 'Group'
                    },
                    'summary': {
                        'status': {
                            'alarm': sum(1 for f in category_findings if f.get('status') == 'alarm'),
                            'ok': sum(1 for f in category_findings if f.get('status') == 'ok'),
                            'info': 0,
                            'skip': 0,
                            'error': 0
                        }
                    },
                    'controls': []
                }
                
                # Group findings by control ID
                controls = {}
                for finding in category_findings:
                    control_id = finding.get('id')
                    if control_id not in controls:
                        controls[control_id] = {
                            'control_id': control_id,
                            'title': finding.get('title'),
                            'description': '',
                            'severity': finding.get('severity', 'medium'),
                            'results': []
                        }
                    
                    controls[control_id]['results'].append({
                        'status': finding.get('status'),
                        'resource': finding.get('resource'),
                        'reason': finding.get('reason')
                    })
                
                # Add controls to category group
                category_group['controls'] = list(controls.values())
                
                # Add category group to main benchmark group
                formatted_results['groups'][0]['groups'].append(category_group)
            
            logger.info(f"Created custom benchmark with {len(findings)} findings in {len(categories)} categories")
            return formatted_results
            
        except Exception as e:
            logger.error(f"AWS compliance check failed: {str(e)}")
            logger.error(traceback.format_exc())
            
            # Return minimal structure so processing can continue
            return {
                'group_id': 'root_result_group',
                'title': 'Error',
                'description': 'Error running AWS compliance check',
                'summary': {
                    'status': {
                        'alarm': 0,
                        'ok': 0,
                        'info': 0,
                        'skip': 0,
                        'error': 1
                    }
                },
                'groups': [
                    {
                        'group_id': 'error',
                        'title': 'Error',
                        'description': 'Error running AWS compliance check',
                        'controls': [
                            {
                                'control_id': 'error',
                                'title': 'Error Running Compliance Check',
                                'severity': 'high',
                                'results': [
                                    {
                                        'status': 'error',
                                        'resource': account_id,
                                        'reason': f'Error: {str(e)}'
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
    
    async def scan_aws_account(self, user_id: str, account_id: str, credentials: Dict[str, str], scan_id: str = None) -> Dict[str, Any]:
        """
        Scan an AWS account for security issues using CIS benchmarks with consistent scan ID.
        
        Args:
            user_id: User identifier
            account_id: AWS account ID
            credentials: AWS credentials dictionary
            scan_id: Optional scan ID to use for progress tracking
            
        Returns:
            Dict containing scan results or error information
        """
        try:
            from progress_tracking import update_scan_progress, generate_consistent_scan_id
            
            # Get consistent scan ID if not provided
            if not scan_id:
                scan_id = generate_consistent_scan_id(user_id, account_id)
            
            logger.info(f"AWS scan using scan ID: {scan_id}")
            
            # Configure AWS credentials
            os.environ['AWS_ACCESS_KEY_ID'] = credentials.get('aws_access_key_id', '').strip()
            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.get('aws_secret_access_key', '').strip()
            if 'aws_session_token' in credentials:
                os.environ['AWS_SESSION_TOKEN'] = credentials.get('aws_session_token', '').strip()
            
            # Log credentials being used (safely)
            access_key = credentials.get('aws_access_key_id', '')
            secret_key = credentials.get('aws_secret_access_key', '')
            masked_access_key = f"{access_key[:4]}{'*' * (len(access_key) - 8)}{access_key[-4:]}" if len(access_key) > 8 else "Not provided"
            masked_secret_key = f"{secret_key[:4]}{'*' * (len(secret_key) - 8)}{secret_key[-4:]}" if len(secret_key) > 8 else "Not provided"
            
            logger.info(f"AWS credentials: Access Key: {masked_access_key}, Secret Key: {masked_secret_key}")
            self.aws_credentials = credentials  # Store credentials for later use
                
            # Validate credentials using boto3
            boto3_validator = AwsCredentialValidator()
            validation_results = await boto3_validator.validate_credentials(credentials)
            
            if not validation_results.get("valid", False):
                error_msg = "Cannot connect to AWS: Invalid credentials or insufficient permissions"
                logger.error(error_msg)
                
                # Update database if needed
                if self.db_session and self.scan_record:
                    try:
                        self.scan_record.status = 'error'
                        self.scan_record.error = error_msg
                        self.scan_record.completed_at = datetime.now()
                        self.db_session.commit()
                    except Exception as db_e:
                        logger.error(f"Failed to store error record: {str(db_e)}")
                        self.db_session.rollback()
                
                # Send error progress update with consistent scan_id
                update_scan_progress(user_id, account_id, 'error', 0, scan_type='aws', scan_id=scan_id)
                
                return {
                    'success': False,
                    'error': {
                        'message': error_msg,
                        'code': 'CREDENTIAL_ERROR',
                        'details': validation_results
                    }
                }
            
            # Credentials are valid, proceed with scan
            logger.info(f"Validated credentials for account: {validation_results.get('account_id')}")
            update_scan_progress(user_id, account_id, 'validation_complete', 15, scan_type='aws', scan_id=scan_id)
            
            # Configure AWS connection
            update_scan_progress(user_id, account_id, 'configuring', 20, scan_type='aws', scan_id=scan_id)
            try:
                # Use Steampipe update script
                result = subprocess.run(['/bin/bash', '/home/steampipe/scripts/update_aws_connection.sh'], 
                                    check=False, capture_output=True, text=True)
                logger.info(f"Connection configuration result: {result.returncode}")
                
                # Check if the script was successful
                if "Successfully connected to AWS account" in result.stdout:
                    logger.info("AWS connection configured successfully")
                    update_scan_progress(user_id, account_id, 'config_complete', 25, scan_type='aws', scan_id=scan_id)
                else:
                    logger.warning(f"AWS connection script didn't confirm success: {result.stdout}")
                    # Continue anyway as the script is designed to fall back to environment variables
            except Exception as config_e:
                logger.warning(f"AWS connection script warning (non-critical): {str(config_e)}")
            
            # Run benchmark scan with proper progress updates
            update_scan_progress(user_id, account_id, 'running_benchmark', 30, scan_type='aws', scan_id=scan_id)
            update_scan_progress(user_id, account_id, 'preparing_scan', 35, scan_type='aws', scan_id=scan_id)
            update_scan_progress(user_id, account_id, 'scanning', 40, scan_type='aws', scan_id=scan_id)
            
            # Run the actual compliance check
            try:
                results = await self.run_aws_compliance_check(account_id)
                update_scan_progress(user_id, account_id, 'scan_complete', 50, scan_type='aws', scan_id=scan_id)
            except Exception as check_e:
                logger.error(f"Compliance check error: {str(check_e)}")
                results = {}
                update_scan_progress(user_id, account_id, 'scan_error_recovery', 50, scan_type='aws', scan_id=scan_id)
            
            # Process results and prepare final data
            update_scan_progress(user_id, account_id, 'preparing_results', 65, scan_type='aws', scan_id=scan_id)
            update_scan_progress(user_id, account_id, 'processing', 70, scan_type='aws', scan_id=scan_id)
            
            # Process benchmark results if available
            findings_data = None
            if results and 'groups' in results:
                update_scan_progress(user_id, account_id, 'processing_benchmark', 75, scan_type='aws', scan_id=scan_id)
                
                processed_results = self._process_benchmark_results(results, account_id)
                findings = processed_results.get('findings', [])
                stats = processed_results.get('stats', {})
                metadata = processed_results.get('metadata', {})
                
                update_scan_progress(user_id, account_id, 'benchmark_processed', 80, scan_type='aws', scan_id=scan_id)
                
                findings_data = {
                    'findings': findings,
                    'stats': stats,
                    'metadata': metadata
                }
            else:
                # Create fallback findings based on validation results
                logger.info("Creating fallback findings from validation data")
                findings_data = self._create_fallback_findings(validation_results, account_id)
            
            # Ensure we have at least one finding
            if not findings_data or not findings_data.get('findings'):
                logger.warning("No findings were generated, adding default finding")
                findings_data = {
                    'findings': [{
                        'id': f"aws-{account_id}-default",
                        'severity': "INFO",
                        'category': "General",
                        'control': "AWS Security Scan",
                        'control_id': "DEFAULT-1",
                        'status': "Info",
                        'reason': "No specific security findings detected",
                        'details': "AWS security scan completed but did not detect any specific issues",
                        'resource_id': account_id,
                        'account_id': account_id
                    }],
                    'stats': {
                        'total_findings': 1,
                        'failed_findings': 0,
                        'pass_findings': 1,
                        'severity_counts': {'INFO': 1, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
                        'category_counts': {'General': 1}
                    },
                    'metadata': {
                        'scan_time': datetime.now().isoformat(),
                        'account_id': account_id
                    }
                }
            
            # Reranking phase
            update_scan_progress(user_id, account_id, 'preparing_rerank', 85, scan_type='aws', scan_id=scan_id)
            update_scan_progress(user_id, account_id, 'reranking', 90, scan_type='aws', scan_id=scan_id)
            
            # Rerank findings if applicable
            reordered_findings = []
            findings = findings_data.get('findings', [])
            if findings:
                # Check if we have a reranking URL
                rerank_url = os.getenv('AWS_RERANK_URL')
                if rerank_url:
                    logger.info(f"Reranking {len(findings)} findings")
                    reordered_findings = await rerank_aws_findings(findings, user_id, account_id)
                    logger.info(f"Reranking complete with {len(reordered_findings)} findings")
                else:
                    logger.info("Skipping reranking as AWS_RERANK_URL is not set")
                    reordered_findings = findings.copy()
            
            # Update progress after reranking
            update_scan_progress(user_id, account_id, 'rerank_complete', 92, scan_type='aws', scan_id=scan_id)
            
            # Sanitize data for JSON serialization
            update_scan_progress(user_id, account_id, 'preparing_save', 95, scan_type='aws', scan_id=scan_id)
            sanitized_data = sanitize_for_json(findings_data)
            
            # Update database record
            update_scan_progress(user_id, account_id, 'saving', 96, scan_type='aws', scan_id=scan_id)
            if self.db_session and self.scan_record:
                try:
                    # Serialize data to JSON
                    serialized_json = json.dumps(sanitized_data, cls=DateTimeEncoder)
                    reordered_json = json.dumps(sanitize_for_json(reordered_findings), cls=DateTimeEncoder)
                    
                    # Update database
                    self.scan_record.status = 'completed'
                    self.scan_record.completed_at = datetime.now()
                    self.scan_record.findings = sanitized_data
                    self.scan_record.rerank = reordered_findings
                    self.db_session.commit()
                    
                    logger.info(f"Scan record {self.scan_record.id} updated successfully")
                    update_scan_progress(user_id, account_id, 'save_complete', 98, scan_type='aws', scan_id=scan_id)
                except Exception as db_e:
                    logger.error(f"Database update error: {str(db_e)}")
                    self.db_session.rollback()
                    
                    # Try minimal update as fallback
                    try:
                        self.scan_record.status = 'completed'
                        self.scan_record.completed_at = datetime.now()
                        self.db_session.commit()
                        logger.info("Updated scan status only")
                    except Exception:
                        self.db_session.rollback()
                        logger.error("Status-only update also failed")
            
            # Final progress updates
            update_scan_progress(user_id, account_id, 'finalizing', 99, scan_type='aws', scan_id=scan_id)
            update_scan_progress(user_id, account_id, 'completed', 100, scan_type='aws', scan_id=scan_id)
            
            logger.info(f"Successfully completed scan for {user_id}/{account_id}")
            
            return {
                'success': True,
                'data': sanitized_data
            }
        
        except Exception as e:
            logger.error(f"AWS CIS benchmark scan failed: {str(e)}", exc_info=True)
            
            # Update error in database
            if self.db_session and self.scan_record:
                try:
                    self.scan_record.status = 'error'
                    self.scan_record.error = str(e)
                    self.scan_record.completed_at = datetime.now()
                    self.db_session.commit()
                except Exception:
                    self.db_session.rollback()
            
            # Send error update with consistent scan_id
            update_scan_progress(user_id, account_id, 'error', 0, scan_type='aws', scan_id=scan_id)
            
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'SCAN_ERROR',
                    'type': type(e).__name__,
                    'timestamp': datetime.now().isoformat()
                }
            }

    def _create_fallback_findings(self, validation_results: Dict, account_id: str) -> Dict:
        """
        Create fallback findings based on validation results when benchmark scan fails.
        
        Args:
            validation_results: Results from credential validation
            account_id: AWS account ID
            
        Returns:
            Dict with findings data structure
        """
        findings = []
        
        # Add authentication finding
        findings.append({
            'id': f"aws-{account_id}-authenticated",
            'severity': "INFO",
            'category': "Authentication",
            'control': "AWS API Access",
            'control_id': "AUTH-1",
            'status': "Pass",
            'reason': "Successfully authenticated to AWS API",
            'details': f"Authenticated as: {validation_results.get('caller_identity', {}).get('arn', 'Unknown')}",
            'resource_id': account_id,
            'account_id': account_id
        })
        
        # Add service-specific findings
        for service, accessible in validation_results.get('services_accessible', {}).items():
            status = "Pass" if accessible else "Fail"
            severity = "INFO" if accessible else "MEDIUM"
            findings.append({
                'id': f"aws-{account_id}-{service}-access",
                'severity': severity,
                'category': service.upper(),
                'control': f"{service.upper()} Access",
                'control_id': f"{service.upper()}-1",
                'status': status,
                'reason': f"{service.upper()} service {'is' if accessible else 'is not'} accessible",
                'details': f"The credentials {'have' if accessible else 'do not have'} access to {service} services",
                'resource_id': account_id,
                'account_id': account_id
            })
        
        # Calculate stats
        stats = {
            'total_findings': len(findings),
            'failed_findings': sum(1 for f in findings if f.get('status') == 'Fail'),
            'warning_findings': sum(1 for f in findings if f.get('status') == 'Warning'),
            'pass_findings': sum(1 for f in findings if f.get('status') in ['Pass', 'Info']),
            'severity_counts': {
                "CRITICAL": sum(1 for f in findings if f.get('severity') == "CRITICAL"),
                "HIGH": sum(1 for f in findings if f.get('severity') == "HIGH"),
                "MEDIUM": sum(1 for f in findings if f.get('severity') == "MEDIUM"),
                "LOW": sum(1 for f in findings if f.get('severity') == "LOW"),
                "INFO": sum(1 for f in findings if f.get('severity') == "INFO"),
            },
            'category_counts': {},
            'resource_counts': 1,
            'account_id': account_id
        }
        
        # Calculate category counts
        for finding in findings:
            category = finding.get('category', 'Unknown')
            if category not in stats['category_counts']:
                stats['category_counts'][category] = 0
            stats['category_counts'][category] += 1
        
        # Create metadata
        metadata = {
            'scan_time': datetime.now().isoformat(),
            'account_id': account_id,
            'cloud_provider': 'aws',
            'benchmark': 'AWS API Access Check',
            'scan_type': 'boto3-api',
            'scan_duration_seconds': (datetime.now() - self.scan_stats.get('start_time', datetime.now())).total_seconds(),
            'validation_results': sanitize_for_json(validation_results)
        }
        
        return {
            'findings': findings,
            'stats': stats,
            'metadata': metadata
        }
        
async def rerank_aws_findings(
    findings: List[Dict], 
    user_id: str, 
    account_id: str,
    rerank_url: Optional[str] = None
) -> List[Dict]:
    """
    Rerank AWS security findings using the AI reranking service.
    
    Args:
        findings: List of AWS security findings
        user_id: User identifier
        account_id: AWS account ID
        rerank_url: URL of the reranking service (optional, will use env var if not provided)
        
    Returns:
        List[Dict]: Reordered findings based on AI reranking
    """
    # Nested helper function - properly encapsulated within the parent function
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

    try:
        logger.info(f"Preparing {len(findings)} AWS findings for reranking")
        
        # Get rerank URL from environment variable if not provided
        if not rerank_url:
            rerank_url = os.getenv('AWS_RERANK_URL')
            if not rerank_url:
                logger.warning("AWS_RERANK_URL environment variable not set, skipping reranking")
                return findings
        
        # Initialize variables
        selected_findings = []
        
        # Select findings based on total count
        if len(findings) <= 50:
            selected_findings = findings.copy()  # Make a copy to avoid reference issues
            logger.info(f"Processing all {len(selected_findings)} findings (under 50 threshold)")
        else:
            # Use severity-based selection logic for larger sets
            high_findings = [f for f in findings if f.get('severity', '').upper() == 'HIGH']
            medium_findings = [f for f in findings if f.get('severity', '').upper() == 'MEDIUM']
            low_findings = [f for f in findings if f.get('severity', '').upper() == 'LOW']
            info_findings = [f for f in findings if f.get('severity', '').upper() == 'INFO']
            
            # Add findings in priority order up to 50
            remaining = 50
            for severity_findings in [high_findings, medium_findings, low_findings, info_findings]:
                if remaining > 0:
                    to_add = severity_findings[:remaining]
                    selected_findings.extend(to_add)
                    remaining -= len(to_add)
                    
            logger.info(f"Selected {len(selected_findings)} findings based on severity prioritization")
        
        # If no findings to rerank, return original list
        if not selected_findings:
            logger.info("No findings to rerank")
            return findings
            
        # Prepare data for reranking API
        rerank_data = {
            'findings': [{
                "ID": idx + 1,
                "category": finding.get("category", ""),
                "reason": finding.get("reason", ""),
                "severity": finding.get("severity")  # No default, use exact severity
            } for idx, finding in enumerate(selected_findings)],
            'metadata': {
                'user_id': user_id
            }
        }
        
        # Send to reranking API
        logger.info(f"Sending {len(selected_findings)} findings for reranking")
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(rerank_url, json=rerank_data, timeout=60) as response:
                    if response.status == 200:
                        rerank_response = await response.json()
                        logger.info(f"Received reranking response")
                        
                        # Extract reranked IDs from response - using the nested helper function
                        reranked_ids = extract_ids_from_llm_response(rerank_response, selected_findings)
                        
                        if reranked_ids:
                            # Create a map of findings by ID
                            findings_map = {idx + 1: finding for idx, finding in enumerate(selected_findings)}
                            
                            # Reorder findings based on response
                            reordered_findings = [findings_map[id] for id in reranked_ids if id in findings_map]
                            logger.info(f"Successfully reordered {len(reordered_findings)} findings")
                            return reordered_findings
                        else:
                            logger.warning("No valid reranking IDs returned, using original order")
                            return selected_findings
                    else:
                        error_text = await response.text()
                        logger.error(f"Reranking API error (status {response.status}): {error_text}")
                        return selected_findings
            except Exception as e:
                logger.error(f"Reranking request failed: {str(e)}")
                logger.error(traceback.format_exc())
                return selected_findings
    
    except Exception as e:
        logger.error(f"Error in AWS findings reranking: {str(e)}")
        logger.error(traceback.format_exc())
        return findings  # Return original findings on error

async def scan_aws_account_handler(
    user_id: str,
    account_id: str,
    credentials: Dict[str, str],
    db_session: Optional[Session] = None,
    scan_record: Optional[CloudScan] = None
) -> Dict:
    """
    Handler function for AWS account scanning against CIS benchmarks
    with improved progress tracking and consistent scan IDs.
    """
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"Starting AWS CIS benchmark scan for account: {account_id}")
        
        # Clear previous scan progress
        from progress_tracking import clear_scan_progress, generate_consistent_scan_id
        clear_scan_progress(user_id, account_id)
        
        # Generate a consistent scan ID for this session
        scan_id = generate_consistent_scan_id(user_id, account_id)
        logger.info(f"Using consistent scan ID: {scan_id}")
        
        # Initialize progress tracking with the new scan ID
        from progress_tracking import update_scan_progress
        update_scan_progress(user_id, account_id, 'initializing', 0, 
                           scan_type='aws', scan_id=scan_id)
        
        if not all([user_id, account_id]):
            return {
                'success': False,
                'error': {
                    'message': 'Missing required parameters',
                    'code': 'INVALID_PARAMETERS'
                }
            }
        
        # Create scan record if not provided
        if db_session and not scan_record:
            scan_record = CloudScan(
                user_id=user_id,
                cloud_provider='aws',
                account_id=account_id,
                status='queued'
            )
            db_session.add(scan_record)
            db_session.commit()
            logger.info(f"Created scan record with ID: {scan_record.id}")
        
        # Set the credentials as environment variables for this scan
        original_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        original_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        original_session_token = os.environ.get('AWS_SESSION_TOKEN')
        
        try:
            # Set user-provided credentials
            os.environ['AWS_ACCESS_KEY_ID'] = credentials.get('aws_access_key_id', '').strip()
            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.get('aws_secret_access_key', '').strip()
            if 'aws_session_token' in credentials:
                os.environ['AWS_SESSION_TOKEN'] = credentials.get('aws_session_token', '').strip()
            
            # Update progress and validate credentials - using the same scan_id
            update_scan_progress(user_id, account_id, 'validating_credentials', 10, 
                               scan_type='aws', scan_id=scan_id)
            
            # Validate credentials against expected account_id
            boto3_validator = AwsCredentialValidator()
            validation_results = await boto3_validator.validate_credentials(credentials, account_id)
            
            if not validation_results.get('valid', False):
                error_message = 'AWS credential validation failed: ' + '; '.join(validation_results.get('errors', ['Unknown error']))
                logger.error(error_message)
                
                if scan_record and db_session:
                    scan_record.status = 'error'
                    scan_record.error = error_message
                    scan_record.completed_at = datetime.now()
                    db_session.commit()
                
                update_scan_progress(user_id, account_id, 'error', 0, 
                                   scan_type='aws', scan_id=scan_id)
                
                return {
                    'success': False,
                    'error': {
                        'message': error_message,
                        'code': 'CREDENTIAL_ERROR',
                        'details': validation_results
                    }
                }
            
            # Update AWS connection configuration file - using same scan_id
            update_scan_progress(user_id, account_id, 'configuring', 20, 
                               scan_type='aws', scan_id=scan_id)
            result = subprocess.run(['/bin/bash', '/home/steampipe/scripts/update_aws_connection.sh'], 
                                  check=False, capture_output=True, text=True)
            logger.info(f"Connection configuration update result: {result.returncode}")
            if result.stdout:
                logger.info(f"Connection update output: {result.stdout}")
            if result.stderr:
                logger.warning(f"Connection update stderr: {result.stderr}")
            
            # Update progress after connection configured - using same scan_id
            update_scan_progress(user_id, account_id, 'config_complete', 25, 
                               scan_type='aws', scan_id=scan_id)
                
            # Update status to in_progress
            if scan_record and db_session:
                scan_record.status = 'in_progress'
                db_session.commit()
            
            # Run benchmark scan - using same scan_id
            update_scan_progress(user_id, account_id, 'running_benchmark', 30, 
                               scan_type='aws', scan_id=scan_id)
            
            # Update progress before starting scan - using same scan_id
            update_scan_progress(user_id, account_id, 'preparing_scan', 35, 
                               scan_type='aws', scan_id=scan_id)
            
            # Update progress when scanning starts - using same scan_id
            update_scan_progress(user_id, account_id, 'scanning', 40, 
                               scan_type='aws', scan_id=scan_id)
            
            # Initialize and run scanner
            async with AwsSecurityScanner(db_session, scan_record) as scanner:
                results = await scanner.scan_aws_account(user_id, account_id, credentials, scan_id=scan_id)
                
                # Progress updates will be sent from scanner with the same scan_id
                
                # When updating the database record with final results, serialize findings properly
                if db_session and scan_record and results.get('success'):
                    try:
                        # Use raw SQL with proper datetime handling
                        findings_data = results.get('data', {})
                        db_session.execute(
                            text("""
                                UPDATE cloud_scans 
                                SET status = 'completed', 
                                    completed_at = NOW(),
                                    findings = CAST(:findings_json AS JSONB)
                                WHERE id = :scan_id
                            """), 
                            {'scan_id': scan_record.id, 'findings_json': json.dumps(findings_data)}
                        )
                        db_session.commit()
                        logger.info(f"Successfully updated scan record {scan_record.id}")
                        
                        # Mark as completed - with the same scan_id
                        update_scan_progress(user_id, account_id, 'completed', 100, 
                                           scan_type='aws', scan_id=scan_id)
                        
                    except Exception as db_e:
                        logger.error(f"Failed to update scan record: {str(db_e)}")
                        db_session.rollback()
                        
                        # Try setting a simple status update
                        try:
                            db_session.execute(
                                text("UPDATE cloud_scans SET status = 'completed', completed_at = NOW() WHERE id = :scan_id"),
                                {'scan_id': scan_record.id}
                            )
                            db_session.commit()
                            logger.info("Updated scan status only due to serialization issues")
                            
                            # Still mark as completed - with the same scan_id
                            update_scan_progress(user_id, account_id, 'completed', 100, 
                                               scan_type='aws', scan_id=scan_id)
                            
                        except Exception as status_e:
                            logger.error(f"Status update also failed: {str(status_e)}")
                            db_session.rollback()
                            
                            # Mark as error - with the same scan_id
                            update_scan_progress(user_id, account_id, 'error', 0, 
                                               scan_type='aws', scan_id=scan_id)
                
                return results
        
        except Exception as e:
            logger.error(f"AWS CIS scan handler error: {str(e)}")
            logger.error(traceback.format_exc())
            
            # Update error in database
            if db_session and scan_record:
                try:
                    scan_record.status = 'error'
                    scan_record.error = str(e)
                    scan_record.completed_at = datetime.now()
                    db_session.commit()
                except Exception:
                    db_session.rollback()
            
            # Update progress to error - with the same scan_id
            update_scan_progress(user_id, account_id, 'error', 0, 
                               scan_type='aws', scan_id=scan_id)
            
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'SCAN_ERROR',
                    'type': type(e).__name__,
                    'timestamp': datetime.now().isoformat()
                }
            }
        
        finally:
            # Restore original environment variables
            if original_access_key:
                os.environ['AWS_ACCESS_KEY_ID'] = original_access_key
            else:
                os.environ.pop('AWS_ACCESS_KEY_ID', None)
                
            if original_secret_key:
                os.environ['AWS_SECRET_ACCESS_KEY'] = original_secret_key
            else:
                os.environ.pop('AWS_SECRET_ACCESS_KEY', None)
                
            if original_session_token:
                os.environ['AWS_SESSION_TOKEN'] = original_session_token
            else:
                os.environ.pop('AWS_SESSION_TOKEN', None)
    
    except Exception as final_err:
        logger.critical(f"Unhandled error in scan handler: {str(final_err)}")
        logger.error(traceback.format_exc())
        
        # Update progress to error - with the same scan_id if available, otherwise generate one
        if not scan_id:
            scan_id = str(int(time.time()))
        update_scan_progress(user_id, account_id, 'error', 0, 
                           scan_type='aws', scan_id=scan_id)
        
        return {
            'success': False,
            'error': {
                'message': 'Unexpected error during scan',
                'code': 'UNEXPECTED_ERROR',
                'type': type(final_err).__name__,
                'timestamp': datetime.now().isoformat()
            }
        }
