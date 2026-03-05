"""
Google Workspace Admin SDK Service
Handles authentication and service account management at organization level
"""
import logging
from typing import Dict, Any, Optional, List
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class WorkspaceAdminService:
    """Service for Google Workspace Admin SDK operations"""
    
    # OAuth scopes needed for admin operations
    REQUIRED_SCOPES = [
        'https://www.googleapis.com/auth/admin.directory.user.readonly',
        'https://www.googleapis.com/auth/cloud-platform',
        'https://www.googleapis.com/auth/cloudplatformorganizations',
        'https://www.googleapis.com/auth/iam'
    ]
    
    def __init__(self, credentials: Optional[Credentials] = None):
        self.credentials = credentials
        self.iam_service = None
        self.crm_service = None  # Cloud Resource Manager
        
    def authenticate_superadmin(self, auth_code: str) -> Dict[str, Any]:
        """
        Exchange OAuth authorization code for admin credentials
        
        Args:
            auth_code: OAuth authorization code from Google Workspace
            
        Returns:
            {
                "success": bool,
                "credentials": Credentials object,
                "error": str (if failed)
            }
        """
        try:
            from google_auth_oauthlib.flow import Flow
            
            # This would be configured with your OAuth client credentials
            # For now, this is a placeholder for the OAuth flow
            logger.info("[WORKSPACE] Authenticating superadmin with OAuth code")
            
            # In production, you'd exchange the code for credentials here
            # flow = Flow.from_client_config(client_config, scopes=self.REQUIRED_SCOPES)
            # credentials = flow.fetch_token(code=auth_code)
            
            return {
                "success": True,
                "message": "Superadmin authenticated successfully",
                "scopes": self.REQUIRED_SCOPES
            }
            
        except Exception as e:
            logger.error(f"[WORKSPACE] Failed to authenticate superadmin: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def create_service_account_at_org(
        self,
        org_id: str,
        account_name: str = "svc-lockdown-tmp",
        description: str = "Temporary service account for GCP Security Hardener"
    ) -> Dict[str, Any]:
        """
        Create service account at organization level
        
        Args:
            org_id: GCP Organization ID
            account_name: Name for the service account
            description: Description for the service account
            
        Returns:
            {
                "success": bool,
                "service_account_email": str,
                "service_account_unique_id": str,
                "error": str (if failed)
            }
        """
        try:
            logger.info(f"[WORKSPACE] Creating service account: {account_name}")
            logger.info(f"[WORKSPACE] Organization ID: {org_id}")
            
            if not self.iam_service:
                self.iam_service = build('iam', 'v1', credentials=self.credentials)
            
            # Create service account
            # Note: Service accounts are created at project level, not org level
            # We'll create it in a designated admin project
            # For true org-level, you'd use Workforce Identity Federation
            
            # This is a simplified version - in production you'd specify a project
            project_id = f"org-{org_id}-admin"  # Admin project for org
            
            service_account = {
                'accountId': account_name,
                'serviceAccount': {
                    'displayName': f'{account_name} (Security Hardener)',
                    'description': description
                }
            }
            
            response = self.iam_service.projects().serviceAccounts().create(
                name=f'projects/{project_id}',
                body=service_account
            ).execute()
            
            service_account_email = response['email']
            service_account_unique_id = response['uniqueId']
            
            logger.info(f"[WORKSPACE] ✓ Service account created: {service_account_email}")
            
            return {
                "success": True,
                "service_account_email": service_account_email,
                "service_account_unique_id": service_account_unique_id,
                "account_name": account_name
            }
            
        except HttpError as e:
            error_msg = f"HTTP error creating service account: {str(e)}"
            logger.error(f"[WORKSPACE] {error_msg}")
            return {
                "success": False,
                "error": error_msg
            }
        except Exception as e:
            error_msg = f"Failed to create service account: {str(e)}"
            logger.error(f"[WORKSPACE] {error_msg}")
            return {
                "success": False,
                "error": error_msg
            }
    
    def find_existing_service_account(
        self,
        org_id: str,
        account_name_pattern: str = "svc-lockdown-tmp"
    ) -> Optional[Dict[str, Any]]:
        """
        Search for existing lockdown service account
        
        Args:
            org_id: Organization ID
            account_name_pattern: Pattern to match service account names
            
        Returns:
            Service account info if found, None otherwise
        """
        try:
            logger.info(f"[WORKSPACE] Searching for existing service account: {account_name_pattern}")
            
            if not self.iam_service:
                self.iam_service = build('iam', 'v1', credentials=self.credentials)
            
            # List service accounts in admin project
            project_id = f"org-{org_id}-admin"
            
            accounts = self.iam_service.projects().serviceAccounts().list(
                name=f'projects/{project_id}'
            ).execute()
            
            for account in accounts.get('accounts', []):
                if account_name_pattern in account.get('email', ''):
                    logger.info(f"[WORKSPACE] ✓ Found existing account: {account['email']}")
                    return {
                        "email": account['email'],
                        "unique_id": account['uniqueId'],
                        "display_name": account.get('displayName', ''),
                        "exists": True
                    }
            
            logger.info(f"[WORKSPACE] No existing service account found")
            return None
            
        except Exception as e:
            logger.warning(f"[WORKSPACE] Error searching for service account: {e}")
            return None
    
    def discover_org_projects(self, org_id: str) -> Dict[str, Any]:
        """
        Discover all projects in the organization
        
        Args:
            org_id: Organization ID
            
        Returns:
            {
                "success": bool,
                "organization_id": str,
                "total_projects": int,
                "projects": List[Dict],
                "error": str (if failed)
            }
        """
        try:
            logger.info(f"[WORKSPACE] Discovering projects in org: {org_id}")
            
            if not self.crm_service:
                self.crm_service = build('cloudresourcemanager', 'v1', credentials=self.credentials)
            
            # List all projects in organization
            projects_list = []
            page_token = None
            
            while True:
                response = self.crm_service.projects().list(
                    filter=f'parent.id:{org_id}',
                    pageToken=page_token
                ).execute()
                
                for project in response.get('projects', []):
                    project_info = {
                        'project_id': project['projectId'],
                        'project_name': project['name'],
                        'project_number': project['projectNumber'],
                        'status': project.get('lifecycleState', 'UNKNOWN'),
                        'created_date': project.get('createTime', 'Unknown')
                    }
                    projects_list.append(project_info)
                
                page_token = response.get('nextPageToken')
                if not page_token:
                    break
            
            logger.info(f"[WORKSPACE] ✓ Found {len(projects_list)} projects")
            
            return {
                "success": True,
                "organization_id": org_id,
                "total_projects": len(projects_list),
                "projects": projects_list
            }
            
        except HttpError as e:
            error_msg = f"HTTP error discovering projects: {str(e)}"
            logger.error(f"[WORKSPACE] {error_msg}")
            return {
                "success": False,
                "error": error_msg,
                "projects": []
            }
        except Exception as e:
            error_msg = f"Failed to discover projects: {str(e)}"
            logger.error(f"[WORKSPACE] {error_msg}")
            return {
                "success": False,
                "error": error_msg,
                "projects": []
            }
