"""
User Privilege Management Service
Temporarily grants IAM roles to user accounts for service account creation, then revokes them
Security: All privilege escalations are logged and automatically revoked
"""
import logging
from typing import List, Dict, Any
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

logger = logging.getLogger(__name__)


class UserPrivilegeService:
    """Service for managing temporary privilege escalation for service account creation"""
    
    # Roles needed to create and manage service accounts
    REQUIRED_ROLES = [
        "roles/iam.serviceAccountAdmin",  # Create service accounts
        "roles/iam.serviceAccountKeyAdmin",  # Create service account keys
        "roles/resourcemanager.projectIamAdmin",  # Grant IAM roles
    ]
    
    def __init__(self, project_id: str, user_credentials: Credentials):
        """
        Initialize privilege management service
        
        Args:
            project_id: GCP project ID
            user_credentials: User's OAuth credentials (from Firebase token exchange)
        """
        self.project_id = project_id
        self.credentials = user_credentials
        self.resource_manager = build('cloudresourcemanager', 'v1', credentials=self.credentials)
        self.granted_roles = []  # Track what we granted for cleanup
    
    def get_user_email(self) -> str:
        """Get the email address of the authenticated user"""
        try:
            # Refresh credentials to ensure they're valid
            request = Request()
            self.credentials.refresh(request)
            
            # Try to get email from token info
            if hasattr(self.credentials, 'id_token') and self.credentials.id_token:
                try:
                    import jwt
                    decoded = jwt.decode(self.credentials.id_token, options={"verify_signature": False})
                    email = decoded.get('email')
                    if email:
                        return email
                except:
                    pass
            
            # Try to get email from service account email (for service accounts)
            if hasattr(self.credentials, 'service_account_email'):
                return self.credentials.service_account_email
            
            # Try to get email from user account (for user credentials)
            # Use the OAuth2 token info endpoint
            try:
                from googleapiclient.discovery import build
                oauth2 = build('oauth2', 'v2', credentials=self.credentials)
                user_info = oauth2.userinfo().get().execute()
                email = user_info.get('email')
                if email:
                    return email
            except Exception as oauth_error:
                logger.warning(f"Could not get email from OAuth2 API: {str(oauth_error)}")
            
            # Fallback: try to extract from token
            if hasattr(self.credentials, 'token') and self.credentials.token:
                try:
                    import jwt
                    decoded = jwt.decode(self.credentials.token, options={"verify_signature": False})
                    email = decoded.get('email')
                    if email:
                        return email
                except:
                    pass
            
            return 'unknown'
        except Exception as e:
            logger.warning(f"Could not determine user email: {str(e)}")
            return 'unknown'
    
    def grant_privileges(self) -> Dict[str, Any]:
        """
        Grant required IAM roles to the user's account
        
        Returns:
            Dict with granted roles and user email
        """
        try:
            user_email = self.get_user_email()
            logger.info(f"Granting privileges to user: {user_email}")
            
            # Get current IAM policy
            project_resource = f"projects/{self.project_id}"
            policy = self.resource_manager.projects().getIamPolicy(
                resource=project_resource,
                body={}
            ).execute()
            
            # Grant each required role
            granted = []
            for role in self.REQUIRED_ROLES:
                # Check if binding already exists
                binding_exists = False
                member = f"user:{user_email}"
                
                for binding in policy.get("bindings", []):
                    if binding.get("role") == role:
                        if member not in binding.get("members", []):
                            binding["members"].append(member)
                            granted.append(role)
                        else:
                            logger.info(f"User already has role: {role}")
                        binding_exists = True
                        break
                
                # Create new binding if it doesn't exist
                if not binding_exists:
                    if "bindings" not in policy:
                        policy["bindings"] = []
                    policy["bindings"].append({
                        "role": role,
                        "members": [member]
                    })
                    granted.append(role)
            
            # Update IAM policy
            if granted:
                self.resource_manager.projects().setIamPolicy(
                    resource=project_resource,
                    body={"policy": policy}
                ).execute()
                logger.info(f"Granted {len(granted)} roles to {user_email}: {granted}")
                self.granted_roles = granted
            else:
                logger.info(f"User {user_email} already has all required roles")
                self.granted_roles = self.REQUIRED_ROLES
            
            return {
                "user_email": user_email,
                "granted_roles": granted,
                "all_roles": self.granted_roles
            }
            
        except Exception as e:
            logger.error(f"Failed to grant privileges: {str(e)}")
            raise ValueError(f"Failed to grant privileges: {str(e)}")
    
    def revoke_privileges(self) -> Dict[str, Any]:
        """
        Revoke IAM roles that were granted to the user's account
        
        Returns:
            Dict with revoked roles
        """
        try:
            user_email = self.get_user_email()
            logger.info(f"Revoking privileges from user: {user_email}")
            
            if not self.granted_roles:
                logger.info("No roles to revoke (none were granted)")
                return {"revoked_roles": [], "user_email": user_email}
            
            # Get current IAM policy
            project_resource = f"projects/{self.project_id}"
            policy = self.resource_manager.projects().getIamPolicy(
                resource=project_resource,
                body={}
            ).execute()
            
            # Remove user from bindings for granted roles
            revoked = []
            member = f"user:{user_email}"
            
            for role in self.granted_roles:
                for binding in policy.get("bindings", []):
                    if binding.get("role") == role:
                        members = binding.get("members", [])
                        if member in members:
                            # Remove this member
                            members = [m for m in members if m != member]
                            binding["members"] = members
                            revoked.append(role)
                            
                            # Remove binding if it has no members
                            if not members:
                                policy["bindings"] = [b for b in policy["bindings"] if b != binding]
                        break
            
            # Update IAM policy
            if revoked:
                self.resource_manager.projects().setIamPolicy(
                    resource=project_resource,
                    body={"policy": policy}
                ).execute()
                logger.info(f"Revoked {len(revoked)} roles from {user_email}: {revoked}")
            else:
                logger.info(f"No roles to revoke from {user_email}")
            
            # Clear granted roles
            self.granted_roles = []
            
            return {
                "revoked_roles": revoked,
                "user_email": user_email
            }
            
        except Exception as e:
            logger.error(f"Failed to revoke privileges: {str(e)}")
            # Don't raise - we want to continue even if revocation fails
            # Log it for manual cleanup if needed
            logger.warning(f"Manual cleanup may be required for user: {self.get_user_email()}")
            return {"revoked_roles": [], "error": str(e)}

