"""
API Enablement Service
Automatically checks and enables required GCP APIs before lockdown operations

This service ensures all necessary APIs are enabled without user intervention
"""
import logging
import time
from typing import List, Dict, Any, Optional
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class APIEnablementService:
    """Service for checking and enabling required GCP APIs"""
    
    # APIs required for full lockdown functionality
    REQUIRED_APIS = [
        {
            "name": "orgpolicy.googleapis.com",
            "display_name": "Organization Policy API",
            "required_for": ["API restrictions", "Network hardening", "Service account key protection", "Region lockdown"],
            "critical": True
        },
        {
            "name": "cloudresourcemanager.googleapis.com",
            "display_name": "Cloud Resource Manager API",
            "required_for": ["Organization membership check", "IAM operations"],
            "critical": True
        },
        {
            "name": "serviceusage.googleapis.com",
            "display_name": "Service Usage API",
            "required_for": ["API management", "Checking API status"],
            "critical": True
        },
        {
            "name": "compute.googleapis.com",
            "display_name": "Compute Engine API",
            "required_for": ["Network hardening", "GPU quota checks"],
            "critical": False
        },
        {
            "name": "billingbudgets.googleapis.com",
            "display_name": "Cloud Billing Budget API",
            "required_for": ["Billing kill switch", "Budget creation"],
            "critical": False
        },
        {
            "name": "logging.googleapis.com",
            "display_name": "Cloud Logging API",
            "required_for": ["Change management logging", "Audit trails"],
            "critical": False
        },
        {
            "name": "pubsub.googleapis.com",
            "display_name": "Cloud Pub/Sub API",
            "required_for": ["Kill switch notifications", "Alert system"],
            "critical": False
        }
    ]
    
    def __init__(self, credentials: Credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        self.service = None
        
    def _get_service_usage_client(self):
        """Get or create Service Usage API client"""
        if not self.service:
            self.service = build('serviceusage', 'v1', credentials=self.credentials)
        return self.service
    
    def check_api_status(self, api_name: str) -> Dict[str, Any]:
        """
        Check if a specific API is enabled
        
        Args:
            api_name: API name (e.g., 'orgpolicy.googleapis.com')
            
        Returns:
            Dict with 'enabled' boolean and 'state' string
        """
        try:
            service = self._get_service_usage_client()
            service_name = f"projects/{self.project_id}/services/{api_name}"
            
            result = service.services().get(name=service_name).execute()
            state = result.get('state', 'UNKNOWN')
            
            return {
                'api': api_name,
                'enabled': state == 'ENABLED',
                'state': state
            }
            
        except HttpError as e:
            if e.resp.status == 404:
                return {'api': api_name, 'enabled': False, 'state': 'NOT_FOUND'}
            logger.warning(f"Error checking API {api_name}: {e}")
            return {'api': api_name, 'enabled': False, 'state': 'ERROR', 'error': str(e)}
    
    def check_all_required_apis(self) -> Dict[str, Any]:
        """
        Check status of all required APIs
        
        Returns:
            Dict with summary and details for each API
        """
        logger.info("=" * 80)
        logger.info("CHECKING REQUIRED APIs")
        logger.info("=" * 80)
        
        results = []
        enabled_count = 0
        disabled_count = 0
        critical_disabled = []
        
        for api_config in self.REQUIRED_APIS:
            api_name = api_config['name']
            status = self.check_api_status(api_name)
            
            result = {
                **api_config,
                **status
            }
            results.append(result)
            
            if status['enabled']:
                enabled_count += 1
                logger.info(f"✓ {api_config['display_name']}: ENABLED")
            else:
                disabled_count += 1
                logger.warning(f"✗ {api_config['display_name']}: {status['state']}")
                if api_config['critical']:
                    critical_disabled.append(api_name)
        
        summary = {
            'total': len(self.REQUIRED_APIS),
            'enabled': enabled_count,
            'disabled': disabled_count,
            'critical_disabled': critical_disabled,
            'all_enabled': disabled_count == 0,
            'details': results
        }
        
        logger.info("=" * 80)
        logger.info(f"API Status: {enabled_count}/{len(self.REQUIRED_APIS)} enabled")
        if critical_disabled:
            logger.warning(f"CRITICAL: {len(critical_disabled)} critical APIs disabled: {critical_disabled}")
        logger.info("=" * 80)
        
        return summary
    
    def enable_api(self, api_name: str, wait_for_completion: bool = True) -> Dict[str, Any]:
        """
        Enable a specific API (with cost awareness check)
        
        Args:
            api_name: API name to enable
            wait_for_completion: Whether to wait for enablement to complete
            
        Returns:
            Dict with success status and details
        """
        # COST-AWARE CHECK: Never enable expensive APIs without approval
        from app.services.cost_aware_api_service import cost_aware_api_service
        
        can_enable, reason = cost_aware_api_service.can_enable_api(api_name, user_approved=False)
        
        if not can_enable:
            logger.warning(f"[COST-AWARE] Blocked API enablement: {api_name}")
            logger.warning(f"[COST-AWARE] Reason: {reason}")
            return {
                'success': False,
                'api': api_name,
                'blocked': True,
                'reason': reason,
                'cost_aware': True
            }
        
        try:
            logger.info(f"Enabling API: {api_name}")
            service = self._get_service_usage_client()
            service_name = f"projects/{self.project_id}/services/{api_name}"
            
            # Enable the API
            operation = service.services().enable(name=service_name).execute()
            
            if wait_for_completion:
                # Wait for operation to complete (usually quick for enabling)
                logger.info(f"  Waiting for {api_name} to be enabled...")
                time.sleep(2)  # Give it a moment to propagate
                
                # Verify it's enabled
                status = self.check_api_status(api_name)
                if status['enabled']:
                    logger.info(f"  ✓ {api_name} successfully enabled")
                    return {'success': True, 'api': api_name, 'operation': operation}
                else:
                    logger.warning(f"  ⚠ {api_name} enable operation completed but API not yet active (may need more time)")
                    return {'success': True, 'api': api_name, 'pending': True, 'operation': operation}
            
            logger.info(f"  ✓ {api_name} enablement initiated")
            return {'success': True, 'api': api_name, 'operation': operation}
            
        except HttpError as e:
            error_msg = f"Failed to enable {api_name}: {str(e)}"
            logger.error(error_msg)
            return {'success': False, 'api': api_name, 'error': str(e)}
    
    def enable_required_apis(
        self, 
        check_first: bool = True,
        only_critical: bool = False
    ) -> Dict[str, Any]:
        """
        Enable all required APIs (or only critical ones)
        
        Args:
            check_first: Check status first to avoid unnecessary API calls
            only_critical: Only enable critical APIs
            
        Returns:
            Dict with results for each API
        """
        logger.info("=" * 80)
        logger.info("ENABLING REQUIRED APIs")
        logger.info("=" * 80)
        
        # Check current status if requested
        to_enable = []
        if check_first:
            status = self.check_all_required_apis()
            for api_detail in status['details']:
                if not api_detail['enabled']:
                    if only_critical and not api_detail['critical']:
                        logger.info(f"Skipping non-critical API: {api_detail['name']}")
                        continue
                    to_enable.append(api_detail)
        else:
            to_enable = [api for api in self.REQUIRED_APIS 
                        if not only_critical or api['critical']]
        
        if not to_enable:
            logger.info("✓ All required APIs are already enabled")
            return {'all_enabled': True, 'enabled_count': 0, 'results': []}
        
        logger.info(f"Enabling {len(to_enable)} APIs...")
        
        results = []
        success_count = 0
        failed_count = 0
        
        for api_config in to_enable:
            api_name = api_config['name']
            logger.info(f"\n[{to_enable.index(api_config) + 1}/{len(to_enable)}] Enabling {api_config['display_name']}...")
            
            result = self.enable_api(api_name, wait_for_completion=True)
            results.append(result)
            
            if result['success']:
                success_count += 1
            else:
                failed_count += 1
                logger.error(f"  Failed to enable {api_name}: {result.get('error')}")
        
        logger.info("=" * 80)
        logger.info(f"API Enablement Complete: {success_count} succeeded, {failed_count} failed")
        logger.info("=" * 80)
        
        return {
            'all_enabled': failed_count == 0,
            'enabled_count': success_count,
            'failed_count': failed_count,
            'results': results
        }
    
    def ensure_apis_enabled(self) -> bool:
        """
        Convenience method: Check and enable all required APIs
        Returns True if all APIs are enabled, False otherwise
        """
        logger.info("Ensuring all required APIs are enabled...")
        
        # First check status
        status = self.check_all_required_apis()
        
        if status['all_enabled']:
            logger.info("✓ All required APIs already enabled")
            return True
        
        # Enable any that are disabled
        logger.info(f"Found {status['disabled']} disabled APIs, enabling them...")
        result = self.enable_required_apis(check_first=False)
        
        if result['all_enabled']:
            logger.info("✓ Successfully enabled all required APIs")
            return True
        else:
            logger.error(f"✗ Failed to enable {result['failed_count']} APIs")
            return False
    
    def ensure_scanner_project_apis(self) -> Dict[str, Any]:
        """
        Ensure required APIs are enabled in scanner's OWN project.
        
        The scanner service account needs these APIs enabled in its own project
        to perform operations like listing all projects, accessing billing data, etc.
        
        This is different from enabling APIs in target projects during lockdown.
        
        Returns:
            Dict with enablement status and results
        """
        scanner_project_apis = [
            {
                "name": "cloudresourcemanager.googleapis.com",
                "display_name": "Cloud Resource Manager API",
                "purpose": "List all accessible projects"
            },
            {
                "name": "serviceusage.googleapis.com",
                "display_name": "Service Usage API", 
                "purpose": "Enable/disable APIs"
            },
            {
                "name": "billingbudgets.googleapis.com",
                "display_name": "Cloud Billing Budget API",
                "purpose": "Check billing budgets"
            },
            {
                "name": "cloudbilling.googleapis.com",
                "display_name": "Cloud Billing API",
                "purpose": "Get billing account info"
            },
            {
                "name": "recommender.googleapis.com",
                "display_name": "Recommender API",
                "purpose": "Cost optimization recommendations"
            }
        ]
        
        logger.info("=" * 80)
        logger.info("ENSURING SCANNER PROJECT APIs ARE ENABLED")
        logger.info(f"Scanner Project ID: {self.project_id}")
        logger.info("=" * 80)
        
        results = []
        enabled_count = 0
        failed_count = 0
        already_enabled = 0
        
        for api_config in scanner_project_apis:
            api_name = api_config["name"]
            
            try:
                # Check if already enabled
                status = self.check_api_status(api_name)
                
                if status['enabled']:
                    logger.info(f"✓ {api_config['display_name']} already enabled")
                    already_enabled += 1
                    results.append({'api': api_name, 'status': 'already_enabled', 'success': True})
                    continue
                
                # Enable the API (bypass cost-aware checks for scanner's own project)
                logger.info(f"Enabling {api_config['display_name']}...")
                logger.info(f"  Purpose: {api_config['purpose']}")
                
                service = self._get_service_usage_client()
                service_name = f"projects/{self.project_id}/services/{api_name}"
                
                operation = service.services().enable(name=service_name).execute()
                time.sleep(2)  # Wait for propagation
                
                # Verify
                verify_status = self.check_api_status(api_name)
                if verify_status['enabled']:
                    logger.info(f"  ✓ Successfully enabled {api_config['display_name']}")
                    enabled_count += 1
                    results.append({'api': api_name, 'status': 'enabled', 'success': True})
                else:
                    logger.warning(f"  ⚠ {api_config['display_name']} may need more time to activate")
                    enabled_count += 1  # Count as success, it's enabling
                    results.append({'api': api_name, 'status': 'enabling', 'success': True})
                    
            except HttpError as e:
                error_details = str(e)
                # If API already enabled, count as success
                if 'ALREADY_ENABLED' in error_details or 'already enabled' in error_details.lower():
                    logger.info(f"✓ {api_config['display_name']} already enabled")
                    already_enabled += 1
                    results.append({'api': api_name, 'status': 'already_enabled', 'success': True})
                else:
                    logger.error(f"✗ Failed to enable {api_config['display_name']}: {error_details}")
                    failed_count += 1
                    results.append({'api': api_name, 'status': 'failed', 'success': False, 'error': error_details})
            except Exception as e:
                logger.error(f"✗ Unexpected error enabling {api_config['display_name']}: {str(e)}")
                failed_count += 1
                results.append({'api': api_name, 'status': 'error', 'success': False, 'error': str(e)})
        
        total_ok = already_enabled + enabled_count
        all_enabled = (total_ok == len(scanner_project_apis))
        
        logger.info("=" * 80)
        logger.info(f"Scanner Project API Status:")
        logger.info(f"  Already enabled: {already_enabled}")
        logger.info(f"  Newly enabled: {enabled_count}")
        logger.info(f"  Failed: {failed_count}")
        logger.info(f"  Total OK: {total_ok}/{len(scanner_project_apis)}")
        logger.info("=" * 80)
        
        return {
            'all_enabled': all_enabled,
            'already_enabled': already_enabled,
            'newly_enabled': enabled_count,
            'failed': failed_count,
            'results': results
        }
