"""
IAM Analysis Service
Analyzes IAM policies and configurations to identify security risks.
"""
import logging
from typing import Dict, Any, List
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class IamAnalysisService:
    """Service for performing comprehensive IAM security analysis"""
    
    def __init__(self, gcp_client):
        self.gcp_client = gcp_client
        self.iam_service = build('iam', 'v1', credentials=gcp_client.credentials)
        self.crm_service = build('cloudresourcemanager', 'v1', credentials=gcp_client.credentials)

    def analyze_iam(self, project_id: str) -> Dict[str, Any]:
        """
        Perform full IAM analysis on the project
        """
        logger.info(f"[IAM ANALYSIS] Starting analysis for {project_id}")
        
        iam_policy = self._get_iam_policy(project_id)
        service_accounts = self._list_service_accounts(project_id)
        external_sa_principals = self._list_external_sa_principals(iam_policy)
        
        # Total SA count = SAs defined IN this project + external SAs granted access to it
        all_sa_count = len(service_accounts) + len(external_sa_principals)
        
        findings = {
            'basic_roles': self._check_basic_roles(iam_policy),
            'service_account_keys': self._check_service_account_keys(project_id, service_accounts),
            'default_service_accounts': self._check_default_service_accounts(iam_policy),
            'external_members': self._check_external_members(iam_policy, project_id),
            'service_account_count': all_sa_count,
            'local_service_accounts': [
                {'email': sa['email'], 'display_name': sa.get('displayName', ''), 'source': 'local'}
                for sa in service_accounts
            ],
            'external_sa_principals': external_sa_principals,
        }
        
        return findings

    def _get_iam_policy(self, project_id: str) -> Dict[str, Any]:
        try:
            return self.crm_service.projects().getIamPolicy(
                resource=project_id, 
                body={}
            ).execute()
        except HttpError as e:
            logger.error(f"[IAM ANALYSIS] Failed to get IAM policy: {e}")
            return {}

    def _list_service_accounts(self, project_id: str) -> List[Dict[str, Any]]:
        try:
            service_accounts = []
            request = self.iam_service.projects().serviceAccounts().list(
                name=f'projects/{project_id}'
            )
            while request:
                response = request.execute()
                service_accounts.extend(response.get('accounts', []))
                request = self.iam_service.projects().serviceAccounts().list_next(
                    previous_request=request, 
                    previous_response=response
                )
            return service_accounts
        except HttpError as e:
            logger.error(f"[IAM ANALYSIS] Failed to list service accounts: {e}")
            return []

    def _list_external_sa_principals(self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract all serviceAccount: members from the IAM policy bindings.
        These are SAs from this or other projects that have been explicitly
        granted roles on this project. The scanner SA shows up here.
        """
        seen = set()
        principals = []
        for binding in policy.get('bindings', []):
            role = binding.get('role', '')
            for member in binding.get('members', []):
                if member.startswith('serviceAccount:') and member not in seen:
                    seen.add(member)
                    email = member.replace('serviceAccount:', '')
                    # Determine if this SA belongs to a different project
                    is_cross_project = not email.endswith(f".iam.gserviceaccount.com") or True
                    principals.append({
                        'email': email,
                        'member': member,
                        'roles': [b['role'] for b in policy.get('bindings', []) if member in b.get('members', [])],
                        'source': 'external_grant',
                        'is_google_managed': email.endswith('@cloudservices.gserviceaccount.com') or
                                             email.endswith('@appspot.gserviceaccount.com') or
                                             '-compute@developer.gserviceaccount.com' in email,
                    })
        logger.info(f"[IAM ANALYSIS] Found {len(principals)} external SA principals in IAM policy")
        return principals


    def _check_basic_roles(self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify usage of primitive roles (Owner, Editor, Viewer)"""
        risks = []
        basic_roles = ['roles/owner', 'roles/editor', 'roles/viewer']
        
        for binding in policy.get('bindings', []):
            role = binding['role']
            if role in basic_roles:
                for member in binding.get('members', []):
                    # Ignore our own JIT accounts/Google-managed SAs to reduce noise
                    if 'gcp-hardener' in member or 'service-org' in member:
                        continue
                        
                    risks.append({
                        'role': role,
                        'member': member,
                        'risk_level': 'CRITICAL' if role == 'roles/owner' else 'HIGH',
                        'recommendation': 'Replace with predefined or custom roles (Least Privilege).'
                    })
        return risks

    def _check_service_account_keys(self, project_id: str, service_accounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify user-managed keys that are old or extensive"""
        risks = []
        
        for sa in service_accounts:
            sa_email = sa['email']
            # Skip checking our own temporary scanner keys (performance optimization + noise reduction)
            if 'gcp-hardener' in sa_email:
                continue

            try:
                keys = self.iam_service.projects().serviceAccounts().keys().list(
                    name=f'projects/{project_id}/serviceAccounts/{sa_email}',
                    keyTypes=['USER_MANAGED'] # Only care about keys users created
                ).execute().get('keys', [])
                
                for key in keys:
                    valid_after = key.get('validAfterTime')
                    if valid_after:
                        # Parse time (iso format like 2023-10-01T10:00:00Z)
                        # Remove 'Z' for simple parsing if needed, but datetime.fromisoformat handles it in Py3.11
                        # Fix: Handle 'Z' explicitly for older Python or specific formats
                        date_str = valid_after.replace('Z', '+00:00')
                        created_date = datetime.fromisoformat(date_str)
                        age_days = (datetime.now(timezone.utc) - created_date).days
                        
                        if age_days > 90:
                            risks.append({
                                'account': sa_email,
                                'key_id': key['name'].split('/')[-1],
                                'age_days': age_days,
                                'risk_level': 'HIGH',
                                'recommendation': 'Rotate key immediately (older than 90 days).'
                            })
            except HttpError as e:
                logger.warning(f"[IAM ANALYSIS] Failed to list keys for {sa_email}: {e}")
                
        return risks

    def _check_default_service_accounts(self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if default SAs are used and have risky permissions"""
        risks = []
        # Identifiers for default SAs
        # Compute: [project-number]-compute@developer.gserviceaccount.com
        # App Engine: [project-id]@appspot.gserviceaccount.com
        
        for binding in policy.get('bindings', []):
            role = binding['role']
            if role == 'roles/editor': # Default role
                for member in binding.get('members', []):
                    if '-compute@developer.gserviceaccount.com' in member or '@appspot.gserviceaccount.com' in member:
                        risks.append({
                            'account': member,
                            'role': role,
                            'risk_level': 'HIGH',
                            'recommendation': 'Remove Editor role and grant specific permissions, or disable default SA automatic assignment.'
                        })
        return risks

    def _check_external_members(self, policy: Dict[str, Any], project_id: str) -> List[Dict[str, Any]]:
        """Identify members outside the organization (e.g. gmail.com users)"""
        risks = []
        # This is a heuristic. A proper check needs Org ID.
        # We'll flag @gmail.com or other generic domains.
        
        risky_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
        
        for binding in policy.get('bindings', []):
            role = binding['role']
            for member in binding.get('members', []):
                if any(domain in member for domain in risky_domains):
                    risks.append({
                        'member': member,
                        'role': role,
                        'risk_level': 'HIGH',
                        'recommendation': 'Remove consumer email accounts. Use Cloud Identity or corporate accounts.'
                    })
        return risks
