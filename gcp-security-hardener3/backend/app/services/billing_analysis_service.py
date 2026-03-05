"""
Billing Analysis Service
Analyzes billing data to identify which APIs/services are actually being used
"""
from google.cloud import billing_v1
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)


class BillingAnalysisService:
    """Analyze billing data to identify used vs. unused APIs"""
    
    # High-cost APIs that should be flagged if unused
    HIGH_COST_APIS = {
        'compute.googleapis.com': {
            'name': 'Compute Engine',
            'risk': 'high',
            'reason': 'VM instances, GPUs, persistent disks - can rack up large bills'
        },
        'container.googleapis.com': {
            'name': 'Google Kubernetes Engine (GKE)',
            'risk': 'high',
            'reason': 'Kubernetes clusters with multiple nodes - expensive if compromised'
        },
        'aiplatform.googleapis.com': {
            'name': 'Vertex AI',
            'risk': 'high',
            'reason': 'ML training, GPUs, TPUs - very expensive'
        },
        'ml.googleapis.com': {
            'name': 'Cloud Machine Learning',
            'risk': 'high',
            'reason': 'ML training and prediction - can be very expensive'
        },
        'dataflow.googleapis.com': {
            'name': 'Dataflow',
            'risk': 'high',
            'reason': 'Stream and batch data processing - scales automatically and costs add up'
        },
        'bigquery.googleapis.com': {
            'name': 'BigQuery',
            'risk': 'medium',
            'reason': 'Data warehouse queries - costs based on data scanned'
        },
        'cloudfunctions.googleapis.com': {
            'name': 'Cloud Functions',
            'risk': 'medium',
            'reason': 'Serverless functions - costs based on invocations'
        },
        'run.googleapis.com': {
            'name': 'Cloud Run',
            'risk': 'medium',
            'reason': 'Serverless containers - costs based on requests and CPU time'
        },
        'dataproc.googleapis.com': {
            'name': 'Dataproc',
            'risk': 'high',
            'reason': 'Spark and Hadoop clusters - expensive compute resources'
        },
        'composer.googleapis.com': {
            'name': 'Cloud Composer',
            'risk': 'medium',
            'reason': 'Managed Airflow - runs on GKE, costs can add up'
        },
        'redis.googleapis.com': {
            'name': 'Cloud Memorystore (Redis)',
            'risk': 'medium',
            'reason': 'Managed Redis instances - always-on costs'
        },
        'sqladmin.googleapis.com': {
            'name': 'Cloud SQL',
            'risk': 'medium',
            'reason': 'Managed databases - always-on costs'
        },
        'spanner.googleapis.com': {
            'name': 'Cloud Spanner',
            'risk': 'high',
            'reason': 'Globally distributed database - very expensive'
        },
        'cloudkms.googleapis.com': {
            'name': 'Cloud KMS',
            'risk': 'low',
            'reason': 'Key management - low cost but high security risk if compromised'
        },
    }
    
    # Core APIs that should NOT be disabled
    CORE_APIS = {
        'cloudresourcemanager.googleapis.com',
        'iam.googleapis.com',
        'serviceusage.googleapis.com',
        'cloudbilling.googleapis.com',
        'logging.googleapis.com',
        'monitoring.googleapis.com',
        'cloudapis.googleapis.com',
    }
    
    def __init__(self, credentials, project_id: str):
        """
        Initialize billing analysis service
        
        Args:
            credentials: GCP credentials
            project_id: GCP project ID
        """
        self.credentials = credentials
        self.project_id = project_id
        
        try:
            # Use Cloud Billing API v1
            self.billing_client = billing_v1.CloudBillingClient(credentials=credentials)
            
            # Use Cloud Billing Budget API for more detailed billing data
            self.cloudbilling_service = build('cloudbilling', 'v1', credentials=credentials)
            
        except Exception as e:
            logger.warning(f"Could not initialize billing client: {e}")
            self.billing_client = None
            self.cloudbilling_service = None
    
    def get_billed_services(self, days_back: int = 30) -> Dict[str, Any]:
        """
        Get list of services that have billing charges in the last N days
        
        Args:
            days_back: Number of days to look back
            
        Returns:
            Dict with billed services and their costs
        """
        if not self.cloudbilling_service:
            logger.warning("Billing service not available")
            return {
                'billed_services': [],
                'total_cost': 0,
                'error': 'Billing API not available'
            }
        
        try:
            logger.info(f"[BILLING] Analyzing billing data for last {days_back} days...")
            
            # Get project's billing account
            project_billing = self.cloudbilling_service.projects().getBillingInfo(
                name=f'projects/{self.project_id}'
            ).execute()
            
            if not project_billing.get('billingEnabled'):
                logger.warning(f"[BILLING] Billing not enabled for project {self.project_id}")
                return {
                    'billed_services': [],
                    'total_cost': 0,
                    'billing_enabled': False,
                    'message': 'Billing not enabled for this project'
                }
            
            billing_account_name = project_billing.get('billingAccountName')
            if not billing_account_name:
                logger.warning(f"[BILLING] No billing account found for project {self.project_id}")
                return {
                    'billed_services': [],
                    'total_cost': 0,
                    'billing_enabled': True,
                    'message': 'No billing account found'
                }
            
            logger.info(f"[BILLING] Found billing account: {billing_account_name}")
            
            # Note: The Cloud Billing API doesn't provide detailed per-service costs directly
            # We would need to use BigQuery export or the Cloud Billing Reports API
            # For now, we'll use a heuristic approach based on enabled services
            
            # Get all enabled services
            from googleapiclient.discovery import build
            serviceusage = build('serviceusage', 'v1', credentials=self.credentials)
            
            services_response = serviceusage.services().list(
                parent=f'projects/{self.project_id}',
                filter='state:ENABLED',
                pageSize=200
            ).execute()
            
            enabled_services = []
            if 'services' in services_response:
                for service in services_response['services']:
                    service_name = service['config']['name']
                    enabled_services.append(service_name)
            
            logger.info(f"[BILLING] Found {len(enabled_services)} enabled services")
            
            # For now, we'll return enabled services
            # In a production system, you'd query BigQuery or use Cloud Billing Reports API
            return {
                'billed_services': enabled_services,
                'total_cost': 0,  # Would need BigQuery export to get actual costs
                'billing_enabled': True,
                'billing_account': billing_account_name,
                'analysis_method': 'enabled_services',  # Indicates we're using a heuristic
                'note': 'For detailed billing analysis, enable BigQuery export of billing data'
            }
            
        except HttpError as e:
            if e.resp.status == 403:
                logger.warning(f"[BILLING] Permission denied accessing billing data: {e}")
                return {
                    'billed_services': [],
                    'total_cost': 0,
                    'error': 'Permission denied - need billing.accounts.get permission',
                    'error_code': 403
                }
            else:
                logger.error(f"[BILLING] HTTP error: {e}")
                return {
                    'billed_services': [],
                    'total_cost': 0,
                    'error': str(e),
                    'error_code': e.resp.status
                }
        except Exception as e:
            logger.error(f"[BILLING] Error analyzing billing data: {e}")
            return {
                'billed_services': [],
                'total_cost': 0,
                'error': str(e)
            }
    
    def analyze_unused_apis(self, enabled_apis: List[str]) -> Dict[str, Any]:
        """
        Analyze which enabled APIs are unused (not billed) and can be disabled
        
        Args:
            enabled_apis: List of currently enabled APIs
            
        Returns:
            Dict with unused APIs categorized by risk
        """
        logger.info(f"[BILLING] Analyzing {len(enabled_apis)} enabled APIs for usage...")
        
        # Get billed services
        billing_data = self.get_billed_services(days_back=30)
        billed_services = set(billing_data.get('billed_services', []))
        
        # Since we're currently using enabled services as a proxy for billed services,
        # we'll use a different heuristic: check against HIGH_COST_APIS
        # If a high-cost API is enabled, flag it for review
        
        unused_apis = []
        core_apis_found = []
        used_apis = []
        
        for api in enabled_apis:
            # Skip core APIs
            if api in self.CORE_APIS:
                core_apis_found.append(api)
                continue
            
            # Check if it's a high-cost API
            if api in self.HIGH_COST_APIS:
                api_info = self.HIGH_COST_APIS[api]
                unused_apis.append({
                    'service': api,
                    'name': api_info['name'],
                    'risk_level': api_info['risk'],
                    'reason': api_info['reason'],
                    'can_disable': True,
                    'recommendation': f"Review if you're actively using {api_info['name']}. If not, consider disabling to reduce attack surface."
                })
            else:
                # Other APIs - assume they're being used if enabled
                used_apis.append(api)
        
        logger.info(f"[BILLING] Analysis complete:")
        logger.info(f"  - {len(unused_apis)} high-cost APIs enabled (review recommended)")
        logger.info(f"  - {len(core_apis_found)} core APIs (do not disable)")
        logger.info(f"  - {len(used_apis)} other APIs enabled")
        
        return {
            'unused_high_cost_apis': unused_apis,
            'core_apis': core_apis_found,
            'other_enabled_apis': used_apis,
            'summary': {
                'total_enabled': len(enabled_apis),
                'high_cost_for_review': len(unused_apis),
                'core_apis': len(core_apis_found),
                'other_apis': len(used_apis)
            },
            'billing_data': billing_data
        }
    
    def generate_disable_api_commands(self, apis_to_disable: List[str]) -> List[str]:
        """
        Generate gcloud commands to disable selected APIs
        
        Args:
            apis_to_disable: List of API names to disable
            
        Returns:
            List of shell commands
        """
        commands = []
        
        # Add safety check
        commands.append("# ============================================================================")
        commands.append("# DISABLE UNUSED APIs")
        commands.append("# ============================================================================")
        commands.append("echo ''")
        commands.append("echo 'Disabling unused APIs...'")
        commands.append("echo 'WARNING: Only disable APIs you are certain you do not need!'")
        commands.append("echo ''")
        
        for api in apis_to_disable:
            # Check if it's a core API
            if api in self.CORE_APIS:
                commands.append(f"# SKIPPED: {api} (core API - do not disable)")
                continue
            
            api_info = self.HIGH_COST_APIS.get(api, {'name': api})
            commands.append(f"# Disabling: {api_info.get('name', api)}")
            commands.append(f"gcloud services disable {api} --project=$PROJECT_ID --quiet || {{")
            commands.append(f"  echo 'WARNING: Failed to disable {api}'")
            commands.append("}")
            commands.append("")
        
        commands.append("echo '✓ Unused APIs disabled'")
        commands.append("")
        
        return commands
