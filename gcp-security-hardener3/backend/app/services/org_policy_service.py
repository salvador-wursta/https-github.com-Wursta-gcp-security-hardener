"""
Organization Policy Service
Applies security constraints using GCP Organization Policy API
Security: Never logs sensitive policy details
"""
import logging
from typing import Optional, Dict, Any, List
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class OrgPolicyService:
    """Service for applying organization policies"""
    
    def __init__(self, credentials: Credentials, project_id: str, organization_id: Optional[str] = None):
        self.credentials = credentials
        self.project_id = project_id
        self.organization_id = organization_id
        self.service = build('cloudresourcemanager', 'v1', credentials=credentials)
        
        # Ensure Organization Policy API is enabled
        self._ensure_api_enabled()
    
    def _ensure_api_enabled(self):
        """Ensure Organization Policy API is enabled for the project"""
        try:
            logger.info(f"[ORG_POLICY] Checking if Organization Policy API is enabled...")
            service_usage = build('serviceusage', 'v1', credentials=self.credentials)
            
            # Check if API is enabled
            service_name = f"projects/{self.project_id}/services/orgpolicy.googleapis.com"
            try:
                service = service_usage.services().get(name=service_name).execute()
                state = service.get('state', 'DISABLED')
                
                if state == 'ENABLED':
                    logger.info(f"[ORG_POLICY] ✓ Organization Policy API is already enabled")
                    return True
                else:
                    logger.warning(f"[ORG_POLICY] Organization Policy API is {state}, attempting to enable...")
            except HttpError:
                logger.warning(f"[ORG_POLICY] Organization Policy API is not enabled, attempting to enable...")
            
            # Enable the API
            logger.info(f"[ORG_POLICY] Enabling Organization Policy API...")
            operation = service_usage.services().enable(
                name=service_name
            ).execute()
            
            logger.info(f"[ORG_POLICY] ✓ Organization Policy API enabled successfully")
            logger.info(f"[ORG_POLICY] Note: API may take a few moments to fully activate")
            return True
            
        except HttpError as e:
            logger.warning(f"[ORG_POLICY] Could not enable Organization Policy API: {e}")
            logger.warning(f"[ORG_POLICY] You may need to enable it manually at:")
            logger.warning(f"[ORG_POLICY]   https://console.developers.google.com/apis/api/orgpolicy.googleapis.com/overview?project={self.project_id}")
            return False
        except Exception as e:
            logger.warning(f"[ORG_POLICY] Error checking/enabling API: {e}")
            return False
    
    def set_policy_constraint(
        self,
        constraint: str,
        policy_value: Any,
        enforce: bool = True
    ) -> Dict[str, Any]:
        """
        Set an organization policy constraint
        
        Args:
            constraint: Policy constraint name (e.g., 'constraints/iam.disableServiceAccountKeyCreation')
            policy_value: Value to set (True/False for boolean, list for list constraints)
            enforce: Whether to enforce the policy
            
        Returns:
            Policy configuration dict
        """
        try:
            logger.info(f"Setting policy constraint: {constraint}")
            logger.info(f"  Project: {self.project_id}")
            logger.info(f"  Enforce: {enforce}")
            logger.info(f"  Policy value type: {type(policy_value).__name__}")
            if isinstance(policy_value, list):
                logger.info(f"  Policy value (list length): {len(policy_value)}")
            else:
                logger.info(f"  Policy value: {policy_value}")
            
            # For project-level policies
            parent = f"projects/{self.project_id}"
            
            # Build policy spec based on constraint type
            # IMPORTANT: The Organization Policy API v2 uses a "oneof" structure.
            # You can EITHER set "enforce" OR "values", but NOT BOTH!
            
            if isinstance(policy_value, list):
                # List constraint (e.g., serviceuser.services)
                # For list constraints, DO NOT set "enforce" - only set "values"
                # Note: For some constraints, values need to be prefixed (e.g., "serviceusage.googleapis.com/ORG_ID/services/SERVICE")
                policy_spec = {
                    "rules": [
                        {
                            "values": {
                                "allowedValues": policy_value
                            }
                        }
                    ]
                }
                logger.debug(f"  List constraint: Added allowedValues with {len(policy_value)} items")
            
            elif isinstance(policy_value, dict):
                # List constraint with deniedValues/allowedValues as dict
                # IMPORTANT: Empty lists are valid! They mean "deny all" or "allow all"
                # Build the values dict, including keys even if lists are empty
                values = {}
                
                if "allowedValues" in policy_value:
                    # Include allowedValues even if empty list (empty = allow none = deny all)
                    values["allowedValues"] = policy_value["allowedValues"]
                    
                if "deniedValues" in policy_value:
                    # Include deniedValues even if empty list (empty = deny none = allow all)
                    values["deniedValues"] = policy_value["deniedValues"]
                
                policy_spec = {
                    "rules": [
                        {
                            "values": values
                        }
                    ]
                }
                logger.debug(f"  List constraint (dict): {values}")
            
            elif isinstance(policy_value, bool):
                # Boolean constraint (e.g., compute.vmExternalIpAccess)
                # For boolean constraints, DO NOT set "values" - only set "enforce"
                policy_spec = {
                    "rules": [
                        {
                            "enforce": enforce
                        }
                    ]
                }
                logger.debug(f"  Boolean constraint: Set enforce={enforce}")
            
            else:
                # Unknown type - default to enforce
                logger.warning(f"  Unknown policy_value type: {type(policy_value)}, defaulting to enforce")
                policy_spec = {
                    "rules": [
                        {
                            "enforce": enforce
                        }
                    ]
                }
            
            policy = {
                "spec": policy_spec
            }
            
            logger.debug(f"  Policy spec: {policy_spec}")
            
            # Apply the policy using Organization Policy API v2
            try:
                logger.info(f"[POLICY] Initializing Organization Policy API v2...")
                org_policy_service = build('orgpolicy', 'v2', credentials=self.credentials)
                
                # Extract constraint name without "constraints/" prefix
                # Input: "constraints/serviceuser.services" → Output: "serviceuser.services"
                constraint_name = constraint.replace("constraints/", "") if constraint.startswith("constraints/") else constraint
                
                # Policy name format: projects/{project_id}/policies/{constraint_name}
                # The constraint_name should NOT include "constraints/" prefix
                policy_name = f"{parent}/policies/{constraint_name}"
                logger.info(f"[POLICY] Applying policy: {policy_name}")
                logger.debug(f"[POLICY] Constraint: {constraint}")
                logger.debug(f"[POLICY] Constraint name (without prefix): {constraint_name}")
                logger.debug(f"[POLICY] Policy body: {policy}")
                
                policy_body = {
                    "name": policy_name,
                    "spec": policy_spec
                }
                
                # Try to get existing policy first
                policy_exists = False
                try:
                    logger.info(f"[POLICY] Checking if policy already exists...")
                    existing_policy = org_policy_service.projects().policies().get(
                        name=policy_name
                    ).execute()
                    policy_exists = True
                    logger.info(f"[POLICY] Policy already exists, will update it")
                except HttpError as get_error:
                    if get_error.resp.status == 404:
                        logger.info(f"[POLICY] Policy does not exist, will create it")
                        policy_exists = False
                    else:
                        logger.warning(f"[POLICY] Error checking policy existence: {get_error}")
                        # Continue anyway, will try to create
                        policy_exists = False
                
                # Apply the policy
                if policy_exists:
                    # Update existing policy using patch
                    logger.info(f"[POLICY] Updating existing policy with patch...")
                    result = org_policy_service.projects().policies().patch(
                        name=policy_name,
                        body=policy_body
                    ).execute()
                    logger.info(f"[POLICY] ✓ Policy constraint {constraint} SUCCESSFULLY UPDATED")
                else:
                    # Create new policy
                    logger.info(f"[POLICY] Creating new policy...")
                    result = org_policy_service.projects().policies().create(
                        parent=parent,
                        body=policy_body
                    ).execute()
                    logger.info(f"[POLICY] ✓ Policy constraint {constraint} SUCCESSFULLY CREATED")
                
                logger.debug(f"[POLICY] API Response: {result}")
                
                return {
                    "constraint": constraint,
                    "status": "applied",
                    "enforced": enforce,
                    "policy_name": policy_name,
                    "api_response": result
                }
                
            except HttpError as api_error:
                # Log detailed error information
                logger.error(f"[POLICY] HTTP Error applying policy:")
                logger.error(f"  Status: {api_error.resp.status}")
                logger.error(f"  Reason: {api_error.reason if hasattr(api_error, 'reason') else 'N/A'}")
                logger.error(f"  Error: {str(api_error)}")
                raise api_error
            
        except HttpError as e:
            error_msg = f"Failed to set policy {constraint}: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"HTTP ERROR setting policy constraint:")
            logger.error(f"  Constraint: {constraint}")
            logger.error(f"  Project: {self.project_id}")
            logger.error(f"  HTTP Status: {e.resp.status if hasattr(e, 'resp') else 'N/A'}")
            logger.error(f"  Error message: {error_msg}")
            logger.error(f"  Error details: {e.error_details if hasattr(e, 'error_details') else 'N/A'}")
            import traceback
            logger.error(f"  Stack trace:\n{traceback.format_exc()}")
            logger.error("=" * 80)
            raise Exception(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error setting policy {constraint}: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"UNEXPECTED ERROR setting policy constraint:")
            logger.error(f"  Constraint: {constraint}")
            logger.error(f"  Project: {self.project_id}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Error message: {error_msg}")
            import traceback
            logger.error(f"  Stack trace:\n{traceback.format_exc()}")
            logger.error("=" * 80)
            raise Exception(error_msg)
    
    def disable_service_account_key_creation(self) -> Dict[str, Any]:
        """Disable service account key creation"""
        return self.set_policy_constraint(
            constraint="constraints/iam.disableServiceAccountKeyCreation",
            policy_value=True,
            enforce=True
        )
    
    def restrict_vm_external_ips(self, deny: bool = True) -> Dict[str, Any]:
        """
        Restrict VM external IP access
        
        NOTE: This constraint is SKIPPED due to GCP API limitations.
        compute.vmExternalIpAccess requires specific VM instance paths in the format:
        projects/PROJECT_ID/zones/ZONE/instances/INSTANCE
        
        Empty lists, wildcards, and boolean values all fail with different errors.
        This should be configured at the ORGANIZATION level, not project level.
        
        Alternative: Use VPC firewall rules or network policies instead.
        """
        logger.warning(f"[POLICY] Skipping compute.vmExternalIpAccess - requires org-level configuration")
        return {
            "constraint": "constraints/compute.vmExternalIpAccess",
            "status": "skipped",
            "reason": "This constraint requires organization-level configuration with specific VM instance paths. Please configure at org level or use VPC firewall rules instead.",
            "enforced": False
        }
    
    def restrict_allowed_services(self, allowed_services: List[str]) -> Dict[str, Any]:
        """Restrict which services can be enabled"""
        return self.set_policy_constraint(
            constraint="constraints/serviceuser.services",
            policy_value=allowed_services,
            enforce=True
        )
    
    def restrict_compute_regions(self, allowed_regions: List[str]) -> Dict[str, Any]:
        """
        Restrict resources to specific regions
        Uses gcp.resourceLocations constraint (tested and working)
        """
        # Use the constraint that actually works (from our testing)
        return self.set_policy_constraint(
            constraint="constraints/gcp.resourceLocations",
            policy_value={"allowedValues": allowed_regions},
            enforce=False  # Use allowedValues, not enforce
        )

