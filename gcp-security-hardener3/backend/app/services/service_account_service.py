"""
Service Account Management Service
Creates temporary service accounts for operations, then disables them after completion
Security: Service accounts are disabled but not deleted for audit purposes
"""
import logging
import time
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime
from google.cloud import iam_admin_v1
from googleapiclient.discovery import build
from google.auth import default as default_credentials

logger = logging.getLogger(__name__)


class ServiceAccountService:
    """Service for managing temporary service accounts"""
    
    # Required roles for scan and lockdown operations
    REQUIRED_ROLES = [
        "roles/serviceusage.serviceUsageConsumer",  # List enabled APIs
        "roles/recommender.viewer",  # Get recommendations
        "roles/billing.viewer",  # Check billing budgets
        "roles/orgpolicy.policyViewer",  # Check org policies
        "roles/viewer",  # View project info
        "roles/orgpolicy.policyAdmin",  # Set org policies (for lockdown)
        "roles/billing.budgetAdmin",  # Create budgets (for lockdown)
        "roles/logging.configWriter",  # Create logging sinks (for lockdown)
        "roles/pubsub.admin",  # Create Pub/Sub topics (for kill switch)
        "roles/cloudfunctions.admin",  # Deploy Cloud Functions (for kill switch)
        "roles/serviceusage.serviceUsageAdmin",  # Enable/disable APIs (for lockdown)
        "roles/compute.admin",  # Manage compute resources (for lockdown)
        "roles/iam.serviceAccountAdmin",  # Manage service accounts (for cleanup)
    ]
    
    def __init__(self, project_id: str, credentials=None):
        """
        Initialize service account management service
        
        Args:
            project_id: GCP project ID
            credentials: Optional credentials (uses default if not provided)
        """
        self.project_id = project_id
        
        if credentials:
            self.credentials = credentials
        else:
            # Use default credentials (for initial service account creation)
            # This requires GOOGLE_APPLICATION_CREDENTIALS to be set OR
            # gcloud auth application-default login
            try:
                self.credentials, _ = default_credentials()
            except Exception as e:
                error_msg = (
                    "Failed to load credentials for service account creation. "
                    "For organization admins, you have a few options:\n\n"
                    "Option 1 (Recommended - Browser-based):\n"
                    "  The app will try to get a GCP OAuth token from your browser.\n"
                    "  If this fails, you can:\n\n"
                    "Option 2 (Service Account):\n"
                    "  1. Create a service account in Google Cloud Console\n"
                    "  2. Grant it these roles:\n"
                    "     - roles/iam.serviceAccountAdmin\n"
                    "     - roles/iam.serviceAccountKeyAdmin\n"
                    "     - roles/resourcemanager.projectIamAdmin\n"
                    "  3. Download the JSON key file\n"
                    "  4. Set GOOGLE_APPLICATION_CREDENTIALS in backend/.env:\n"
                    "     GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json\n\n"
                    "Option 3 (gcloud CLI):\n"
                    "  Run: gcloud auth application-default login\n\n"
                    f"Original error: {str(e)}"
                )
                raise ValueError(error_msg)
        
        # Initialize IAM Admin client
        self.iam_client = iam_admin_v1.IAMClient(credentials=self.credentials)
        
        # Initialize Resource Manager for IAM policy operations
        self.resource_manager = build('cloudresourcemanager', 'v1', credentials=self.credentials)
    
    def create_temp_service_account(self, user_email: str) -> Dict[str, Any]:
        """
        Create a temporary service account with required permissions
        
        Args:
            user_email: Email of the user requesting the service account (for audit)
            
        Returns:
            Dict with service account details including email and key
        """
        try:
            # Generate unique service account ID (must be 6-30 characters)
            # Use shorter format: gh-temp-{timestamp} where timestamp is seconds since epoch
            timestamp = str(int(time.time()))  # Unix timestamp (10 digits)
            # Format: gh-temp-{timestamp} = 8 + 10 = 18 characters (within 6-30 limit)
            sa_id = f"gh-temp-{timestamp}"
            
            # Ensure it's within GCP limits (6-30 characters)
            if len(sa_id) > 30:
                # Fallback: use hash of timestamp if too long
                hash_suffix = hashlib.md5(timestamp.encode()).hexdigest()[:8]
                sa_id = f"gh-temp-{hash_suffix}"  # 17 characters
            
            sa_email = f"{sa_id}@{self.project_id}.iam.gserviceaccount.com"
            
            logger.info(f"Creating temporary service account: {sa_email}")
            
            # Create service account
            project_name = f"projects/{self.project_id}"
            service_account = iam_admin_v1.ServiceAccount(
                display_name=f"GCP Security Hardener Temporary ({user_email})",
                description=f"Temporary service account created by GCP Security Hardener for user {user_email} at {datetime.utcnow().isoformat()}. Will be disabled after operations complete."
            )
            
            request = iam_admin_v1.CreateServiceAccountRequest(
                name=project_name,
                account_id=sa_id,
                service_account=service_account
            )
            
            created_sa = self.iam_client.create_service_account(request=request)
            logger.info(f"Service account created: {created_sa.email}")
            
            # Grant required roles
            logger.info("Granting required roles to service account...")
            self._grant_roles(created_sa.email)
            
            # Create and download key
            logger.info("Creating service account key...")
            key = self._create_key(created_sa.name)
            
            return {
                "email": created_sa.email,
                "name": created_sa.name,
                "unique_id": created_sa.unique_id,
                "key": key,  # JSON key content
                "created_at": datetime.utcnow().isoformat(),
                "created_by": user_email
            }
            
        except Exception as e:
            logger.error(f"Failed to create service account: {str(e)}")
            raise ValueError(f"Failed to create service account: {str(e)}")
    
    def _grant_roles(self, service_account_email: str):
        """Grant required roles to service account"""
        try:
            # Get current IAM policy
            project_resource = f"projects/{self.project_id}"
            policy = self.resource_manager.projects().getIamPolicy(
                resource=project_resource,
                body={}
            ).execute()
            
            # Add bindings for each required role
            for role in self.REQUIRED_ROLES:
                # Check if binding already exists
                binding_exists = False
                for binding in policy.get("bindings", []):
                    if binding.get("role") == role:
                        if service_account_email not in binding.get("members", []):
                            binding["members"].append(f"serviceAccount:{service_account_email}")
                        binding_exists = True
                        break
                
                # Create new binding if it doesn't exist
                if not binding_exists:
                    if "bindings" not in policy:
                        policy["bindings"] = []
                    policy["bindings"].append({
                        "role": role,
                        "members": [f"serviceAccount:{service_account_email}"]
                    })
            
            # Update IAM policy
            self.resource_manager.projects().setIamPolicy(
                resource=project_resource,
                body={"policy": policy}
            ).execute()
            
            logger.info(f"Granted {len(self.REQUIRED_ROLES)} roles to {service_account_email}")
            
        except Exception as e:
            logger.error(f"Failed to grant roles: {str(e)}")
            raise ValueError(f"Failed to grant roles to service account: {str(e)}")
    
    def _create_key(self, service_account_name: str) -> Dict[str, Any]:
        """Create and return service account key"""
        try:
            request = iam_admin_v1.CreateServiceAccountKeyRequest(
                name=service_account_name,
                key_algorithm=iam_admin_v1.ServiceAccountKeyAlgorithm.KEY_ALG_RSA_2048,
                private_key_type=iam_admin_v1.ServiceAccountPrivateKeyType.TYPE_GOOGLE_CREDENTIALS_FILE
            )
            
            key = self.iam_client.create_service_account_key(request=request)
            
            # The key.private_key_data is base64-encoded JSON
            import base64
            import json
            key_json = json.loads(base64.b64decode(key.private_key_data).decode('utf-8'))
            
            logger.info(f"Service account key created for {service_account_name}")
            return key_json
            
        except Exception as e:
            logger.error(f"Failed to create service account key: {str(e)}")
            raise ValueError(f"Failed to create service account key: {str(e)}")
    
    def disable_and_cleanup(self, service_account_email: str):
        """
        Disable service account and remove all permissions (but don't delete)
        
        Args:
            service_account_email: Email of service account to disable
        """
        try:
            logger.info(f"Disabling service account: {service_account_email}")
            
            # Remove all IAM bindings
            self._remove_all_roles(service_account_email)
            
            # Disable the service account
            sa_name = f"projects/{self.project_id}/serviceAccounts/{service_account_email.split('@')[0]}"
            request = iam_admin_v1.DisableServiceAccountRequest(name=sa_name)
            self.iam_client.disable_service_account(request=request)
            
            logger.info(f"Service account {service_account_email} disabled and permissions removed")
            
        except Exception as e:
            logger.error(f"Failed to disable service account: {str(e)}")
            # Don't raise - we want to continue even if cleanup fails
            # The account will remain but disabled
    
    def _remove_all_roles(self, service_account_email: str):
        """Remove all IAM bindings for service account"""
        try:
            # Get current IAM policy
            project_resource = f"projects/{self.project_id}"
            policy = self.resource_manager.projects().getIamPolicy(
                resource=project_resource,
                body={}
            ).execute()
            
            # Remove service account from all bindings
            member = f"serviceAccount:{service_account_email}"
            updated_bindings = []
            
            for binding in policy.get("bindings", []):
                members = binding.get("members", [])
                if member in members:
                    # Remove this member
                    members = [m for m in members if m != member]
                    # Only keep binding if it has other members
                    if members:
                        binding["members"] = members
                        updated_bindings.append(binding)
                else:
                    # Keep binding as-is
                    updated_bindings.append(binding)
            
            policy["bindings"] = updated_bindings
            
            # Update IAM policy
            self.resource_manager.projects().setIamPolicy(
                resource=project_resource,
                body={"policy": policy}
            ).execute()
            
            logger.info(f"Removed all IAM bindings for {service_account_email}")
            
        except Exception as e:
            logger.error(f"Failed to remove IAM bindings: {str(e)}")
            # Don't raise - continue with disable

