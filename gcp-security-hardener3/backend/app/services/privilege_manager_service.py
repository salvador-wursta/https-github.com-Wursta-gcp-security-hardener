"""
Privilege Manager Service
Manages IAM role assignments and privilege escalation/de-escalation
"""
import logging
from typing import Dict, Any, List, Optional
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


# View-only roles for scanning
VIEW_ONLY_ROLES = [
    "roles/viewer",
    "roles/orgpolicy.policyViewer",
    "roles/billing.viewer",
    "roles/compute.viewer",
    "roles/logging.viewer"
]

# Elevated roles for lockdown operations
ELEVATED_ROLES = [
    "roles/orgpolicy.policyAdmin",
    "roles/billing.admin",
    "roles/compute.securityAdmin",
    "roles/logging.configWriter",
    "roles/iam.securityAdmin"
]


class PrivilegeManagerService:
    """Service for managing service account privileges"""
    
    def __init__(self, credentials: Credentials):
        self.credentials = credentials
        self.crm_service = None  # Cloud Resource Manager
        
    def _get_crm_service(self):
        """Get or create Cloud Resource Manager service"""
        if not self.crm_service:
            self.crm_service = build('cloudresourcemanager', 'v1', credentials=self.credentials)
        return self.crm_service
    
    def grant_project_roles(
        self,
        project_id: str,
        service_account_email: str,
        roles: List[str]
    ) -> Dict[str, Any]:
        """
        Grant specific roles to service account on a project
        
        Args:
            project_id: GCP project ID
            service_account_email: Service account email
            roles: List of role names (e.g., ["roles/viewer"])
            
        Returns:
            {
                "success": bool,
                "project_id": str,
                "roles_granted": List[str],
                "error": str (if failed)
            }
        """
        try:
            logger.info(f"[PRIVILEGE] Granting roles to {service_account_email} on {project_id}")
            logger.info(f"[PRIVILEGE] Roles: {roles}")
            
            crm = self._get_crm_service()
            
            # Get current IAM policy
            policy = crm.projects().getIamPolicy(
                resource=project_id,
                body={}
            ).execute()
            
            # Add service account to each role
            member = f"serviceAccount:{service_account_email}"
            roles_granted = []
            
            for role in roles:
                binding_found = False
                
                # Check if role binding exists
                for binding in policy.get('bindings', []):
                    if binding['role'] == role:
                        if member not in binding['members']:
                            binding['members'].append(member)
                            roles_granted.append(role)
                        binding_found = True
                        break
                
                # Create new binding if role doesn't exist
                if not binding_found:
                    if 'bindings' not in policy:
                        policy['bindings'] = []
                    policy['bindings'].append({
                        'role': role,
                        'members': [member]
                    })
                    roles_granted.append(role)
            
            # Set updated policy
            crm.projects().setIamPolicy(
                resource=project_id,
                body={'policy': policy}
            ).execute()
            
            logger.info(f"[PRIVILEGE] ✓ Granted {len(roles_granted)} roles on {project_id}")
            
            return {
                "success": True,
                "project_id": project_id,
                "roles_granted": roles_granted
            }
            
        except HttpError as e:
            error_msg = f"HTTP error granting roles: {str(e)}"
            logger.error(f"[PRIVILEGE] {error_msg}")
            return {
                "success": False,
                "project_id": project_id,
                "error": error_msg
            }
        except Exception as e:
            error_msg = f"Failed to grant roles: {str(e)}"
            logger.error(f"[PRIVILEGE] {error_msg}")
            return {
                "success": False,
                "project_id": project_id,
                "error": error_msg
            }
    
    def assign_viewer_to_projects(
        self,
        service_account_email: str,
        project_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Assign view-only roles to service account on selected projects
        
        Args:
            service_account_email: Service account email
            project_ids: List of project IDs to assign to
            
        Returns:
            {
                "success": bool,
                "total_selected": int,
                "assigned": List[str],
                "failed": List[str],
                "errors": List[str]
            }
        """
        results = {
            "total_selected": len(project_ids),
            "assigned": [],
            "failed": [],
            "errors": []
        }
        
        logger.info(f"[PRIVILEGE] Assigning viewer roles to {len(project_ids)} projects")
        
        for project_id in project_ids:
            result = self.grant_project_roles(
                project_id,
                service_account_email,
                VIEW_ONLY_ROLES
            )
            
            if result["success"]:
                results["assigned"].append(project_id)
            else:
                results["failed"].append(project_id)
                results["errors"].append(f"{project_id}: {result.get('error', 'Unknown error')}")
        
        success = len(results["failed"]) == 0
        logger.info(f"[PRIVILEGE] Assignment complete: {len(results['assigned'])} succeeded, {len(results['failed'])} failed")
        
        return {
            "success": success,
            **results
        }
    
    def elevate_to_admin(
        self,
        service_account_email: str,
        project_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Elevate service account to admin roles for lockdown operations
        
        Args:
            service_account_email: Service account email
            project_ids: List of project IDs
            
        Returns:
            {
                "success": bool,
                "elevated_projects": List[str],
                "failed_projects": List[str],
                "errors": List[str]
            }
        """
        logger.info(f"[PRIVILEGE] Elevating to admin roles on {len(project_ids)} projects")
        
        results = {
            "elevated_projects": [],
            "failed_projects": [],
            "errors": []
        }
        
        for project_id in project_ids:
            result = self.grant_project_roles(
                project_id,
                service_account_email,
                ELEVATED_ROLES
            )
            
            if result["success"]:
                results["elevated_projects"].append(project_id)
            else:
                results["failed_projects"].append(project_id)
                results["errors"].append(f"{project_id}: {result.get('error')}")
        
        success = len(results["failed_projects"]) == 0
        logger.info(f"[PRIVILEGE] Elevation complete: {len(results['elevated_projects'])} succeeded")
        
        return {
            "success": success,
            **results
        }
    
    def revoke_all_privileges(
        self,
        service_account_email: str,
        project_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Revoke ALL privileges from service account (Phase 3)
        
        Args:
            service_account_email: Service account email
            project_ids: List of project IDs
            
        Returns:
            {
                "success": bool,
                "revoked_projects": List[str],
                "failed_projects": List[str]
            }
        """
        logger.info(f"[PRIVILEGE] Revoking ALL privileges from {service_account_email}")
        
        results = {
            "revoked_projects": [],
            "failed_projects": [],
            "errors": []
        }
        
        member = f"serviceAccount:{service_account_email}"
        crm = self._get_crm_service()
        
        for project_id in project_ids:
            try:
                # Get current policy
                policy = crm.projects().getIamPolicy(
                    resource=project_id,
                    body={}
                ).execute()
                
                # Remove service account from all bindings
                modified = False
                for binding in policy.get('bindings', []):
                    if member in binding.get('members', []):
                        binding['members'].remove(member)
                        modified = True
                
                # Remove empty bindings
                policy['bindings'] = [b for b in policy.get('bindings', []) if b.get('members')]
                
                # Update policy if modified
                if modified:
                    crm.projects().setIamPolicy(
                        resource=project_id,
                        body={'policy': policy}
                    ).execute()
                
                results["revoked_projects"].append(project_id)
                logger.info(f"[PRIVILEGE] ✓ Revoked all privileges from {project_id}")
                
            except Exception as e:
                results["failed_projects"].append(project_id)
                results["errors"].append(f"{project_id}: {str(e)}")
                logger.error(f"[PRIVILEGE] Failed to revoke from {project_id}: {e}")
        
        success = len(results["failed_projects"]) == 0
        logger.info(f"[PRIVILEGE] Revocation complete: {len(results['revoked_projects'])} projects")
        
        return {
            "success": success,
            **results
        }

    def audit_iam_segmentation(self, project_id: str, organization_id: Optional[str]) -> Dict[str, Any]:
        """
        Identify Org Admins with direct project privileges
        
        Args:
            project_id: GCP project ID
            organization_id: Optional organization ID
            
        Returns:
            Dict list of users and their direct project roles
        """
        results = {
            "org_admin_users": [],
            "offenders": []
        }
        
        try:
            logger.info(f"[PRIVILEGE] audit_iam_segmentation started for project: {project_id}")
            
            # Resolve Organization ID if missing
            if not organization_id:
                logger.info("[PRIVILEGE] No organization_id provided. Attempting to resolve via project ancestry...")
                try:
                    # Initialize GCP client to use ancestry lookup
                    # We can't access gcp_client here easily without passing it, but we can reconstruct it or use crm directly
                    # Better to do it via CRM service we already have
                    crm_ancestry = self._get_crm_service() # Use a separate CRM service instance for ancestry if needed, or reuse
                    ancestry = crm_ancestry.projects().getAncestry(projectId=project_id).execute()
                    ancestors = ancestry.get('ancestor', [])
                    for ancestor in ancestors:
                        if ancestor.get('resourceId', {}).get('type') == 'organization':
                            organization_id = ancestor['resourceId']['id']
                            logger.info(f"[PRIVILEGE] Auto-resolved Organization ID: {organization_id}")
                            break
                    
                    if not organization_id:
                        logger.warning("[PRIVILEGE] Could not resolve Organization ID. Project might not be in an organization.")
                        return results
                except Exception as ancestry_error:
                    logger.warning(f"[PRIVILEGE] Ancestry lookup failed: {ancestry_error}")
                    return results
            else:
                logger.info(f"[PRIVILEGE] Using provided Organization ID: {organization_id}")

            crm = self._get_crm_service()
            
            # 1. Fetch Org Admins
            org_admins = []
            try:
                # Clean up org id
                org_id = organization_id.replace('organizations/', '')
                
                logger.info(f"Fetching IAM policy for organization: {org_id}")
                org_policy = crm.organizations().getIamPolicy(
                    resource=f"organizations/{org_id}",
                    body={}
                ).execute()
                
                for binding in org_policy.get('bindings', []):
                    if binding['role'] == 'roles/resourcemanager.organizationAdmin':
                        for member in binding.get('members', []):
                            if member.startswith('user:'):
                                org_admins.append(member.replace('user:', ''))
                
                logger.info(f"[PRIVILEGE] Found {len(org_admins)} Org Admins: {org_admins}")
                results["org_admin_users"] = org_admins
            except Exception as org_err:
                logger.warning(f"[PRIVILEGE] Could not fetch org admins: {org_err}")
                return results

            if not org_admins:
                logger.info("[PRIVILEGE] No Org Admins found. Skipping audit.")
                return results

            # 2. Inspect Project IAM Policy
            logger.info("[PRIVILEGE] Inspecting project IAM policy for direct segmentation violations...")
            project_policy = crm.projects().getIamPolicy(
                resource=project_id,
                body={}
            ).execute()
            
            # Check for ANY direct role assignment (Segmentation Violation)
            for binding in project_policy.get('bindings', []):
                role = binding['role']
                # Skip the organization admin role if inherited/displayed (not actually possible in getIamPolicy usually)
                
                for member in binding.get('members', []):
                    if member.startswith('user:'):
                        email = member.replace('user:', '')
                        if email in org_admins:
                            logger.info(f"[PRIVILEGE] VIOLATION DETECTED: Org Admin {email} has direct role {role}")
                            results["offenders"].append({
                                "email": email,
                                "role": role
                            })
            
            return results
            
        except Exception as e:
            logger.error(f"[PRIVILEGE] Error auditing IAM segmentation: {str(e)}")
            return results
