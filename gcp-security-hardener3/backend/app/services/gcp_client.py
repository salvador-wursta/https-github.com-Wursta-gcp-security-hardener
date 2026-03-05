"""
GCP API Client wrapper with proper error handling
Security: Never logs access tokens or sensitive credentials
"""
import logging
import os
from typing import List, Dict, Any, Optional
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth import default as default_credentials
import google.auth.impersonated_credentials
from googleapiclient.discovery import build
# Removed top-level conditional imports to speed up startup
# These will be imported lazily inside methods as needed

# Configure logging - explicitly exclude sensitive data
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class GCPClient:
    """Wrapper for GCP API clients with credential management"""
    
    def __init__(self, project_id: str = None, impersonate_email: str = None):
        """
        Initialize GCP client with Application Default Credentials (ADC).
        Supports cross-project scanning by taking a target_project_id.
        Optional support for service account impersonation.
        
        Args:
            project_id: The target GCP project ID to scan.
            impersonate_email: Optional service account email to impersonate.
        
        Security: No keys or tokens are stored or logged.
        """
        # Phase 4 Refactor: Standardize on ADC for SaaS Readiness
        logger.info(f"Initializing GCP Client with ADC for target project: {project_id}")
        self.impersonate_email = impersonate_email  # Store for downstream consumers
        if impersonate_email:
             logger.info(f"🎭 Impersonation Mode: {impersonate_email}")
        
        try:
            # 1. Base Credentials (Developer Identity or Running Environment Identity)
            self.credentials, detected_project = default_credentials()
            self.source_identity = None  # Will be set after refresh if needed
            
            # 2. Impersonate if requested
            if impersonate_email:
                self.credentials = google.auth.impersonated_credentials.Credentials(
                    source_credentials=self.credentials,
                    target_principal=impersonate_email,
                    target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
                    lifetime=3600
                )
                logger.info("✓ Credentials swapped for impersonated identity")
            
            # Use the requested project_id, or fallback to the one associated with the credentials
            self.project_id = project_id or detected_project
            
            if not self.project_id:
                raise ValueError("Project ID is required. Target project_id must be provided or available via ADC.")
                
            logger.info(f"GCP Client ready. Target Project: {self.project_id}")
            
        except Exception as e:
            logger.error(f"Failed to load Application Default Credentials (ADC): {str(e)}")
            raise ValueError(
                f"SaaS Authentication Error: Could not load ADC. "
                f"Ensure the Cloud Run Service Account has permissions on the target project {project_id}."
            )

    
    def _refresh_if_needed(self):
        """Refresh credentials if expired (only for OAuth tokens)"""
        try:
            if hasattr(self.credentials, 'expired') and self.credentials.expired:
                logger.info("Credentials expired, attempting refresh...")
                self.credentials.refresh(Request())
                logger.info("Credentials refreshed successfully")
        except Exception as e:
            error_msg = f"Failed to refresh credentials: {str(e)}"
            logger.error(error_msg)
            logger.error(f"Token type: {type(self.credentials)}")
            logger.error(f"Token expired: {self.credentials.expired if hasattr(self.credentials, 'expired') else 'N/A'}")
            raise ValueError("Invalid or expired access token. Note: Firebase ID tokens cannot be used directly with GCP APIs. You need a GCP OAuth access token.")
    
    def get_enabled_apis(self) -> List[str]:
        """
        List all enabled APIs in the project
        
        Returns:
            List of enabled API service names (e.g., ['compute.googleapis.com'])
        """
        try:
            # Lazy import
            try:
                from google.cloud import serviceusage_v1
            except ImportError:
                serviceusage_v1 = None

            if serviceusage_v1 is None:
                # Fallback to REST API if client library not available
                service = build('serviceusage', 'v1', credentials=self.credentials)
                request = service.services().list(
                    parent=f"projects/{self.project_id}",
                    filter="state:ENABLED"
                )
                response = request.execute()
                enabled_apis = []
                for service_item in response.get('services', []):
                    if 'name' in service_item:
                        # Extract API name from full resource name
                        api_name = service_item['name'].split('/')[-1]
                        enabled_apis.append(api_name)
                logger.info(f"Found {len(enabled_apis)} enabled APIs for project {self.project_id}")
                return enabled_apis
            
            client = serviceusage_v1.ServiceUsageClient(credentials=self.credentials)
            parent = f"projects/{self.project_id}"
            
            enabled_apis = []
            request = serviceusage_v1.ListServicesRequest(
                parent=parent,
                filter="state:ENABLED"
            )
            
            page_result = client.list_services(request=request)
            for service in page_result:
                # Extract API name from full resource name
                # Format: projects/{project}/services/{service}
                if "/services/" in service.name:
                    api_name = service.name.split("/services/")[-1]
                    enabled_apis.append(api_name)
            
            logger.info(f"Found {len(enabled_apis)} enabled APIs for project {self.project_id}")
            return enabled_apis
            
        except Exception as e:
            logger.error(f"Error listing enabled APIs: {str(e)}")
            raise Exception(f"Failed to list enabled APIs: {str(e)}")
    
    def check_org_policy(self, constraint: str, organization_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Check organization policy constraint at project or organization level
        
        Args:
            constraint: Policy constraint name (e.g., 'constraints/iam.disableServiceAccountKeyCreation')
            organization_id: Optional organization ID (if None, checks project level)
            
        Returns:
            Dict with policy state and enforcement
        """
        try:
            from googleapiclient.discovery import build
            orgpolicy = build('orgpolicy', 'v2', credentials=self.credentials)
            
            # Determine parent (project or organization)
            if organization_id:
                parent = f"organizations/{organization_id}"
            else:
                parent = f"projects/{self.project_id}"
            
            # Get the policy
            policy_name = f"{parent}/policies/{constraint}"
            
            try:
                policy = orgpolicy.projects().policies().get(name=policy_name).execute()
                
                # Check if policy is enforced
                # For boolean constraints, check the 'enforce' field in rules
                enforced = False
                if 'spec' in policy and 'rules' in policy['spec']:
                    for rule in policy['spec']['rules']:
                        if 'enforce' in rule and rule['enforce']:
                            enforced = True
                            break
                
                logger.info(f"✓ Policy {constraint} check: enforced={enforced}")
                return {
                    "constraint": constraint,
                    "enforced": enforced,
                    "parent": parent
                }
                
            except Exception as get_error:
                # Policy might not exist (not set)
                if "404" in str(get_error) or "NOT_FOUND" in str(get_error):
                    logger.info(f"Policy {constraint} not set at {parent}")
                    return {
                        "constraint": constraint,
                        "enforced": False,
                        "note": "Policy not set"
                    }
                else:
                    raise
                    
        except Exception as e:
            logger.error(f"Error checking org policy {constraint}: {str(e)}")
            return {
                "constraint": constraint,
                "enforced": False,
                "error": str(e)
            }

    
    def get_recommendations(self, recommender_id: str = "google.compute.instance.MachineTypeRecommender") -> List[Dict[str, Any]]:
        """
        Get recommendations from GCP Recommender API
        
        Args:
            recommender_id: Type of recommender to query
            
        Returns:
            List of recommendation objects
        """
        # OPTIMIZATION: Removed eager API enablement check to speed up scan.
        # The Recommender API is usually enabled. If not, the call will fail gracefully (returns empty list).
        
        try:
            # Lazy import
            try:
                from google.cloud import recommender_v1
            except ImportError:
                recommender_v1 = None

            if recommender_v1 is None:
                # Fallback: return empty list if library not available
                logger.warning("Recommender client library not available, skipping recommendations")
                return []
            
            client = recommender_v1.RecommenderClient(credentials=self.credentials)
            # Use "global" location instead of "-" which is invalid
            parent = f"projects/{self.project_id}/locations/global/recommenders/{recommender_id}"
            
            recommendations = []
            request = recommender_v1.ListRecommendationsRequest(parent=parent)
            
            page_result = client.list_recommendations(request=request)
            for recommendation in page_result:
                recommendations.append({
                    "name": recommendation.name,
                    "description": recommendation.description,
                    "primary_impact": recommendation.primary_impact.name if recommendation.primary_impact else None,
                    "priority": recommendation.priority.name if recommendation.priority else None,
                    "content": {
                        "operation_groups": [
                            {
                                "operations": [
                                    {
                                        "action": op.action,
                                        "resource_type": op.resource_type,
                                        "resource": op.resource
                                    }
                                    for op in group.operations
                                ]
                            }
                            for group in recommendation.content.operation_groups
                        ] if recommendation.content.operation_groups else []
                    }
                })
            
            logger.info(f"Found {len(recommendations)} recommendations for project {self.project_id}")
            return recommendations
            
        except Exception as e:
            logger.warning(f"Could not fetch recommendations: {str(e)}")
            # Return empty list instead of failing - recommendations are optional
            return []
    
    def get_billing_budgets(self, billing_account_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List existing billing budgets
        
        Args:
            billing_account_id: Optional billing account ID
            
        Returns:
            List of budget configurations
        """
        try:
            # Lazy imports
            try:
                from google.cloud import billing_v1
                from google.cloud import billing_budgets_v1
            except ImportError:
                billing_v1 = None
                billing_budgets_v1 = None

            if billing_budgets_v1 is None or billing_v1 is None:
                # Fallback: return empty list if libraries not available
                logger.warning("Billing client libraries not available, skipping budget check")
                return []
            
            client = billing_budgets_v1.BudgetServiceClient(credentials=self.credentials)
            
            # Try to find billing account if not provided
            if not billing_account_id:
                billing_client = billing_v1.CloudBillingClient(credentials=self.credentials)
                project_name = f"projects/{self.project_id}"
                try:
                    project = billing_client.get_project_billing_info(name=project_name)
                    if project.billing_account_name:
                        billing_account_id = project.billing_account_name.split("/")[-1]
                except Exception:
                    logger.warning("Could not determine billing account")
                    return []
            
            if not billing_account_id:
                return []
            
            parent = f"billingAccounts/{billing_account_id}"
            budgets = []
            
            request = billing_budgets_v1.ListBudgetsRequest(parent=parent)
            page_result = client.list_budgets(request=request)
            
            for budget in page_result:
                budgets.append({
                    "name": budget.name,
                    "display_name": budget.display_name,
                    "budget_filter": {
                        "projects": list(budget.budget_filter.projects) if budget.budget_filter.projects else []
                    },
                    "amount": {
                        "specified_amount": {
                            "currency_code": budget.amount.specified_amount.currency_code if budget.amount.specified_amount else None,
                            "units": str(budget.amount.specified_amount.units) if budget.amount.specified_amount else None
                        } if budget.amount.specified_amount else None
                    },
                    "threshold_rules": [
                        {
                            "threshold_percent": rule.threshold_percent,
                            "spend_basis": rule.spend_basis.name if rule.spend_basis else None
                        }
                        for rule in budget.threshold_rules
                    ]
                })
            
            logger.info(f"Found {len(budgets)} budgets for billing account {billing_account_id}")
            return budgets
            
        except Exception as e:
            logger.warning(f"Could not fetch billing budgets: {str(e)}")
            # Return empty list - budgets may not exist yet
            return []
    
    def get_organization(self, organization_id: str) -> Dict[str, Any]:
        """
        Get organization details (display name)
        
        Args:
            organization_id: The numeric Organization ID
            
        Returns:
            Dict with organization details
        """
        try:
            service = build('cloudresourcemanager', 'v1', credentials=self.credentials)
            name = f"organizations/{organization_id}"
            org = service.organizations().get(name=name).execute()
            
            return {
                "organization_id": organization_id,
                "display_name": org.get("displayName"),
                "lifecycle_state": org.get("lifecycleState")
            }
        except Exception as e:
            logger.warning(f"Could not fetch organization details for {organization_id}: {str(e)}")
            # Return minimal info if we can't fetch details (likely permission denied)
            return {
                "organization_id": organization_id,
                "display_name": None
            }

    def get_project_info(self) -> Dict[str, Any]:
        """
        Get basic project information
        
        Returns:
            Dict with project metadata
        """
        try:
            service = build('cloudresourcemanager', 'v1', credentials=self.credentials)
            project = service.projects().get(projectId=self.project_id).execute()
            
            return {
                "project_id": project.get("projectId"),
                "name": project.get("name"),
                "project_number": project.get("projectNumber"),
                "lifecycle_state": project.get("lifecycleState"),
                "labels": project.get("labels", {})
            }
        except Exception as e:
            logger.error(f"Error getting project info: {str(e)}")
            raise Exception(f"Failed to get project information: {str(e)}")

    def get_project_ancestry(self) -> List[Dict[str, str]]:
        """
        Get project ancestry (Project -> Folder(s) -> Organization)
        
        Returns:
            List of ancestor resources [{'resourceId': {'type': 'organization', 'id': '123'}}]
        """
        try:
            service = build('cloudresourcemanager', 'v1', credentials=self.credentials)
            ancestry = service.projects().getAncestry(projectId=self.project_id).execute()
            return ancestry.get('ancestor', [])
        except Exception as e:
            logger.error(f"Error getting project ancestry: {str(e)}")
            # Don't fail the entire scan for this, just return empty
            return []
    
    def enable_api(self, api_name: str, project_id: Optional[str] = None, project_number: Optional[str] = None) -> Dict[str, Any]:
        """
        Enable a GCP API in a project
        
        Args:
            api_name: API service name (e.g., 'cloudresourcemanager.googleapis.com')
            project_id: Project ID (defaults to self.project_id)
            project_number: Project number (optional, used if project_id fails)
        
        Returns:
            Dict with operation status
        """
        try:
            target_project = project_id or self.project_id
            if not target_project:
                # Try using project number if available
                if project_number:
                    target_project = project_number
                    logger.info(f"Using project number {project_number} to enable API")
                else:
                    raise ValueError("Project ID or project number is required to enable API")
            
            logger.info(f"Enabling API {api_name} in project {target_project}")
            
            service = build('serviceusage', 'v1', credentials=self.credentials)
            
            # Enable the API - can use either project ID or project number
            service_name = f"projects/{target_project}/services/{api_name}"
            logger.info(f"Service name: {service_name}")
            request = service.services().enable(name=service_name)
            operation = request.execute()
            
            # Wait for operation to complete (with timeout)
            import time
            max_wait = 15  # Reduced from 30 to 15s for faster initial response
            wait_time = 0
            poll_interval = 1.5
            logger.info(f"Waiting for API {api_name} to enable (max {max_wait}s)...")
            
            while wait_time < max_wait:
                if operation.get('done', False):
                    logger.info(f"API {api_name} enable operation completed after {wait_time}s")
                    break
                time.sleep(poll_interval)
                wait_time += poll_interval
                logger.debug(f"API enable operation still in progress... ({wait_time}s elapsed)")
                
                # Check operation status
                if 'name' in operation:
                    try:
                        op_request = service.operations().get(name=operation['name'])
                        operation = op_request.execute()
                    except Exception as op_error:
                        logger.warning(f"Error checking operation status: {str(op_error)}")
                        # Continue waiting - operation might still be processing
                        continue
                else:
                    logger.warning("Operation name not found, cannot check status")
                    break
            
            if operation.get('done', False):
                # Check if there was an error
                if 'error' in operation:
                    error_info = operation.get('error', {})
                    error_msg = f"API enable operation failed: {error_info}"
                    logger.error(error_msg)
                    raise Exception(error_msg)
                
                logger.info(f"✓ API {api_name} enabled in project {target_project}")
                return {
                    "api_name": api_name,
                    "project_id": target_project,
                    "status": "enabled",
                    "operation": operation.get('name', 'unknown')
                }
            else:
                logger.warning(f"API {api_name} enable operation did not complete within {max_wait}s timeout")
                logger.warning(f"Operation may still be in progress. Continuing anyway...")
                # Don't fail - the API might still enable, or it might already be enabled
                return {
                    "api_name": api_name,
                    "project_id": target_project,
                    "status": "enabling",
                    "note": f"Operation may still be in progress (waited {wait_time}s). Will attempt to use API anyway."
                }
                
        except Exception as e:
            error_msg = str(e)
            # Check if API is already enabled
            if 'already enabled' in error_msg.lower() or 'ALREADY_EXISTS' in error_msg:
                logger.info(f"API {api_name} is already enabled in project {target_project}")
                return {
                    "api_name": api_name,
                    "project_id": target_project,
                    "status": "already_enabled"
                }
            logger.error(f"Error enabling API {api_name}: {error_msg}")
            raise Exception(f"Failed to enable API {api_name}: {error_msg}")
    
    def disable_api(self, api_name: str, project_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Disable a GCP API in a project
        
        Args:
            api_name: API service name (e.g., 'cloudresourcemanager.googleapis.com')
            project_id: Project ID (defaults to self.project_id)
        
        Returns:
            Dict with operation status
        """
        try:
            target_project = project_id or self.project_id
            if not target_project:
                raise ValueError("Project ID is required to disable API")
            
            logger.info(f"Disabling API {api_name} in project {target_project}")
            
            service = build('serviceusage', 'v1', credentials=self.credentials)
            
            # Disable the API
            service_name = f"projects/{target_project}/services/{api_name}"
            request = service.services().disable(name=service_name)
            operation = request.execute()
            
            # Wait for operation to complete (with timeout)
            import time
            max_wait = 60  # 60 seconds max wait
            wait_time = 0
            while wait_time < max_wait:
                if operation.get('done', False):
                    break
                time.sleep(2)
                wait_time += 2
                # Check operation status
                if 'name' in operation:
                    op_request = service.operations().get(name=operation['name'])
                    operation = op_request.execute()
            
            if operation.get('done', False):
                if 'error' in operation:
                    error_msg = operation['error'].get('message', 'Unknown error')
                    raise Exception(f"Failed to disable API: {error_msg}")
                logger.info(f"✓ API {api_name} disabled in project {target_project}")
                return {
                    "api_name": api_name,
                    "project_id": target_project,
                    "status": "disabled",
                    "operation": operation.get('name', 'unknown')
                }
            else:
                logger.warning(f"API disable operation still in progress after {max_wait}s")
                return {
                    "api_name": api_name,
                    "project_id": target_project,
                    "status": "disabling",
                    "note": "Operation may still be in progress"
                }
                
        except Exception as e:
            error_msg = str(e)
            # Check if API is already disabled
            if 'not enabled' in error_msg.lower() or 'NOT_FOUND' in error_msg:
                logger.info(f"API {api_name} is already disabled in project {target_project}")
                return {
                    "api_name": api_name,
                    "project_id": target_project,
                    "status": "already_disabled"
                }
            logger.error(f"Error disabling API {api_name}: {error_msg}")
            raise Exception(f"Failed to disable API {api_name}: {error_msg}")
    
    def list_all_projects(self, organization_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all accessible projects
        
        Args:
            organization_id: Optional organization ID to filter projects
        
        Returns:
            List of project dictionaries with project_id, name, project_number, etc.
        
        Note: This requires the service account to have:
        - roles/resourcemanager.organizationViewer (at org level) to list all org projects, OR
        - roles/viewer or roles/browser (at project level) to list projects the account can access
        """
        try:
            # Build the service - let GCP handle quota/billing naturally
            # Don't override quota_project as it can limit visibility
            service = build('cloudresourcemanager', 'v1', credentials=self.credentials)
            projects = []
            
            # Do NOT filter by organization_id here.
            # The v1 projects.list API with a parent.id filter only returns DIRECT children of
            # that org/folder node — it does NOT recursively traverse folder hierarchies.
            # To see all projects at every depth, we simply list all accessible projects without a filter
            # and optionally post-filter client-side if organization_id was provided.
            filter_expr = None
            
            logger.info(f"Listing all accessible projects (org scope: {organization_id or 'all'})")

            
            # Use same pageSize as gcloud for consistency
            request = service.projects().list(filter=filter_expr, pageSize=500)
            
            page_count = 0
            total_projects_seen = 0
            
            page_count = 0
            total_projects_seen = 0
            max_pages = 20  # SAFETY: Don't fetch more than 20 pages (10,000 projects) during discovery
            
            while request is not None and page_count < max_pages:
                
                try:
                    response = request.execute()
                    projects_in_page = response.get('projects', [])
                    total_projects_seen += len(projects_in_page)
                    
                    logger.info(f"Page {page_count}: Received {len(projects_in_page)} projects (total seen so far: {total_projects_seen})")
                    
                    for project in projects_in_page:
                        lifecycle_state = project.get('lifecycleState')
                        project_id = project.get("projectId")
                        
                        # Log all projects, not just active ones
                        logger.debug(f"Project {project_id}: lifecycleState={lifecycle_state}")
                        
                        # Only include active projects
                        if lifecycle_state == 'ACTIVE':
                            # Extract parent organization if available
                            parent = project.get("parent", {})
                            org_id = None
                            if parent.get("type") == "organization":
                                org_id = parent.get("id")
                            
                            projects.append({
                                "project_id": project_id,
                                "name": project.get("name"),
                                "project_number": project.get("projectNumber"),
                                "lifecycle_state": lifecycle_state,
                                "labels": project.get("labels", {}),
                                "organization_id": org_id
                            })
                        else:
                            logger.info(f"Skipping project {project_id} (lifecycleState: {lifecycle_state})")
                    
                    # Get next page
                    request = service.projects().list_next(request, response)
                    page_count += 1  # increment AFTER processing each page
                    
                    # Safety check: if response doesn't have nextPageToken, we're done
                    if not response.get('nextPageToken'):
                        logger.info("No nextPageToken found - pagination complete")
                        break
                        
                except Exception as page_error:
                    logger.error(f"Error fetching page {page_count}: {str(page_error)}")
                    # SAFETY: Don't try to continue if we've already had issues with this page
                    # It's better to return partial results than to hang in an infinite loop
                    break
            
            logger.info(f"Pagination complete: {page_count} pages processed, {total_projects_seen} total projects seen, {len(projects)} active projects found")
            
            # If no projects found, log a warning but don't raise an error
            # This could be legitimate (no access, no projects, etc.)
            if len(projects) == 0:
                logger.warning(
                    f"No active projects found (saw {total_projects_seen} total projects across {page_count} pages). "
                    "This usually means the Service Account lacks org-level listing permissions."
                )
                logger.info(f"Fallback: Attempting to directly fetch explicitly impersonated target {self.project_id}...")
                try:
                    # Attempt a direct GET call on the exact target project.
                    # This succeeds even if the SA only has project-specific roles/browser and not org-level listing.
                    single_proj = service.projects().get(projectId=self.project_id).execute()
                    if single_proj.get('lifecycleState') == 'ACTIVE':
                         parent = single_proj.get("parent", {})
                         org_id = parent.get("id") if parent.get("type") == "organization" else None
                         projects.append({
                              "project_id": single_proj.get("projectId"),
                              "name": single_proj.get("name"),
                              "project_number": single_proj.get("projectNumber"),
                              "lifecycle_state": single_proj.get("lifecycleState"),
                              "labels": single_proj.get("labels", {}),
                              "organization_id": org_id
                         })
                         logger.info(f"Fallback SUCCESS: Retrieved exact project {self.project_id}")
                except Exception as get_err:
                     logger.error(f"Fallback direct fetch also failed: {get_err}")
            elif len(projects) == 1:
                logger.warning(
                    f"Only 1 project found (saw {total_projects_seen} total projects across {page_count} pages). "
                    "This might indicate: "
                    "1. Service account only has access to one project (check IAM permissions) "
                    "2. Service account needs roles/resourcemanager.organizationViewer at org level to see all projects "
                    "3. Only one project exists in the organization"
                )
            
            # Fallback: If we only found the local project, try Cloud Asset Inventory
            # This is robust because we explicitly granted 'roles/cloudasset.viewer' at Org level.
            if len(projects) <= 1:
                logger.info("Project list restricted (count <= 1). Attempting discovery via Cloud Asset Inventory (CAI)...")
                try:
                    # 1. Determine Organization ID (if not provided)
                    target_org_id = organization_id
                    if not target_org_id:
                        # Ancestry failed to show Org (maybe SA is in a different project/org).
                        # Attempt to search for visible organizations directly
                        # The SA has 'Organization Viewer', so this should return the Org.
                        try:
                            crm_service = build('cloudresourcemanager', 'v1', credentials=self.credentials)
                            # search() is a POST request in v1
                            search_request = crm_service.organizations().search(body={}) 
                            search_response = search_request.execute()
                            orgs = search_response.get('organizations', [])
                            if orgs:
                                target_org_id = orgs[0].get('organizationId')
                                logger.info(f"Discovered Organization ID via search: {target_org_id}")
                        except Exception as search_err:
                            logger.warning(f"Organization search failed: {search_err}")

                    if target_org_id:
                        logger.info(f"Using Organization ID {target_org_id} for CAI discovery")
                        from google.cloud import asset_v1
                        
                        # Initialize CAI Client
                        cai_client = asset_v1.AssetServiceClient(credentials=self.credentials)
                        
                        # Search for Projects using a request object (page_size is not a direct kwarg)
                        scope = f"organizations/{target_org_id}"
                        request = asset_v1.SearchAllResourcesRequest(
                            scope=scope,
                            asset_types=["cloudresourcemanager.googleapis.com/Project"],
                            page_size=500,
                        )
                        results = cai_client.search_all_resources(request=request)
                        
                        cai_projects = []
                        for r in results:
                            # r is ResourceSearchResult
                            # Filter ACTIVE only if state available (usually additional_attributes)
                            # CAI 'state' field: result.state
                            if r.state == "DELETE_REQUESTED" or r.state == "DELETE_IN_PROGRESS":
                                continue

                            # Standardize format
                            # result.name is like "//cloudresourcemanager.googleapis.com/projects/123"
                            # result.project is like "projects/123"
                            p_num = r.project.split('/')[-1] if r.project else ""
                            # We need project ID (string), usually in display_name or name
                            # display_name is usually the 'Name' (Project Name), not ID.
                            # For Projects, 'name' field in CAI result struct uses project NUMBER usually?
                            # Actually, for Project asset, 'name' is full resource name.
                            # 'display_name' is Project Name (Friendly).
                            # 'additional_attributes' might contain projectId.
                            
                            # Let's inspect carefully.
                            # CAI Resource for Project:
                            # name: //cloudresourcemanager.googleapis.com/projects/NUMBER
                            # display_name: My Project
                            # additional_attributes: {'projectId': 'my-project-id', ...}
                            
                            p_id = None
                            if r.additional_attributes and 'projectId' in r.additional_attributes:
                                p_id = r.additional_attributes['projectId']
                            else:
                                # Fallback or skip
                                continue
                                
                            cai_projects.append({
                                "project_id": p_id,
                                "name": r.display_name,
                                "project_number": p_num,
                                "lifecycle_state": "ACTIVE", # Assumed if not deleted
                                "labels": dict(r.labels),
                                "organization_id": target_org_id
                            })
                        
                        logger.info(f"CAI Discovery found {len(cai_projects)} projects")
                        if len(cai_projects) > len(projects):
                            logger.info("Using CAI project list (more complete)")
                            return cai_projects
                            
                except Exception as cai_error:
                    logger.warning(f"CAI Discovery failed: {cai_error}")
                    # Continue with original short list

            return projects
            
        except Exception as e:
            error_msg = str(e)
            # Check if it's an API not enabled error
            if 'SERVICE_DISABLED' in error_msg or 'has not been used' in error_msg or 'is disabled' in error_msg:
                logger.error(f"Cloud Resource Manager API not enabled: {error_msg}")
                raise Exception(
                    "Cloud Resource Manager API is not enabled. "
                    "This API is required to list projects. "
                    "Please enable it in your GCP project or ensure your service account has the necessary permissions. "
                    f"Original error: {error_msg}"
                )
            # Check if it's a permissions error
            if 'PERMISSION_DENIED' in error_msg or 'permission denied' in error_msg.lower():
                logger.error(f"Permission denied when listing projects: {error_msg}")
                raise Exception(
                    "Permission denied when listing projects. "
                    "Your service account needs one of these roles: "
                    "roles/resourcemanager.organizationViewer (at organization level) OR "
                    "roles/viewer or roles/browser (at project level). "
                    f"Original error: {error_msg}"
                )
            logger.error(f"Error listing projects: {error_msg}")
            raise Exception(f"Failed to list projects: {error_msg}")
            raise Exception(f"Failed to list projects: {error_msg}")
    
    def get_scc_settings(self, organization_id: str) -> Dict[str, Any]:
        """
        Get Security Command Center settings for an organization
        
        Args:
            organization_id: The numeric Organization ID
            
        Returns:
            Dict with 'status' (ACTIVE/DISABLED/UNKNOWN) and 'tier' (STANDARD/PREMIUM)
        """
        try:
            # Lazy import
            try:
                from google.cloud import securitycenter
            except ImportError:
                logger.warning("google-cloud-securitycenter not installed")
                return {"status": "UNKNOWN", "tier": "UNKNOWN"}

            client = securitycenter.SecurityCenterClient(credentials=self.credentials)
            org_settings_name = f"organizations/{organization_id}/organizationSettings"
            
            try:
                settings = client.get_organization_settings(name=org_settings_name)
                
                # If we got settings, it's active. Check tier.
                # If we got settings, it's active.
                
                # Accurately detect Tier by checking for Premium-only features (Event Threat Detection)
                # Querying the 'sources' list is the reliable way to distinguish.
                try:
                    tier = "STANDARD"
                    sources_iterator = client.list_sources(parent=f"organizations/{organization_id}")
                    for source in sources_iterator:
                        if "Event Threat Detection" in source.display_name:
                            tier = "PREMIUM"
                            break
                except Exception:
                    # If we can't list sources, we can't verify Premium.
                    # We leave it as STANDARD (base active level).
                    pass
                
                return {"status": "ACTIVE", "tier": tier}
                
            except Exception as e:
                error_str = str(e)
                # Check if API is disabled in the client project (Quota Project)
                # Note: Enabling the API in the client project is required to query the Org-level settings.
                # It does NOT activate Premium tier or incur charges; it simply enables the programmatic interface.
                if "SERVICE_DISABLED" in error_str or "has not been used" in error_str:
                    logger.info("Security Command Center API is disabled. Attempting to enable...")
                    
                    # Try to detect which project needs it enabled
                    import re
                    project_to_enable = self.project_id
                    project_match = re.search(r'project[\/\s]+([a-zA-Z0-9\-\.]+)', error_str)
                    
                    if project_match:
                         # It might match 'project 12345' or 'projects/my-proj/...'
                         # Cleaning up the match if it includes 'projects/'
                         detected = project_match.group(1)
                         if detected != 'projects': # avoid matching just the word
                             project_to_enable = detected
                             logger.info(f"Detected project {project_to_enable} from error message")

                    try:
                        self.enable_api("securitycenter.googleapis.com", project_id=project_to_enable)
                        
                        # Retrying the operation
                        settings = client.get_organization_settings(name=org_settings_name)
                        
                        # (Retry successful) - Accurately detect Tier
                        try:
                            tier = "STANDARD"
                            sources_iterator = client.list_sources(parent=f"organizations/{organization_id}")
                            for source in sources_iterator:
                                if "Event Threat Detection" in source.display_name:
                                    tier = "PREMIUM"
                                    break
                        except Exception:
                            pass
                        return {"status": "ACTIVE", "tier": tier}

                    except Exception as retry_idx:
                         logger.warning(f"Failed to auto-enable SCC API or retry failed: {retry_idx}")
                         return {"status": "DISABLED", "tier": "UNKNOWN"}

                # If 404 or perm denied, likely not active or accessible
                logger.info(f"SCC Org Settings not accessible: {e}")
                return {"status": "DISABLED", "tier": "UNKNOWN"}
                
        except Exception as e:
            logger.error(f"Error checking SCC settings: {str(e)}")
            return {"status": "UNKNOWN", "tier": "UNKNOWN"}

    def list_scc_findings(self, project_id: str = None, organization_id: str = None) -> List[Dict[str, Any]]:
        """
        List active findings for a specific project.
        If organization_id is provided, also fetches critical Org-level findings (e.g. MFA).
        
        Args:
            project_id: Project ID to query
            organization_id: Optional Org ID to include Org-level findings
            
        Returns:
            List of finding objects
        """
        target_project = project_id or self.project_id
        if not target_project:
            return []
            
        try:
            # Lazy import - Prefer V2 as V1 is deprecated/removed for some paths
            try:
                from google.cloud import securitycenter_v2 as securitycenter
            except ImportError:
                try:
                    from google.cloud import securitycenter
                except ImportError:
                    return []

            client = securitycenter.SecurityCenterClient(credentials=self.credentials)
            
            # V2 Access Pattern
            source_name = f"projects/{target_project}/sources/-"
            
            # Filter for active findings
            filter_str = "state=\"ACTIVE\""
            
            try:
                # Try project-scoped listing (v1p1beta1 or similar supports it, v1 standard strictly Org?)
                # Attempt standard client
                findings_result = client.list_findings(
                    request={"parent": source_name, "filter": filter_str}
                )
                
                findings = []
                for result in findings_result:
                    f = result.finding
                    findings.append({
                        "category": f.category,
                        "state": f.state.name,
                        "severity": f.severity.name,
                        "event_time": f.event_time.isoformat() if f.event_time else "",
                        "resource_name": f.resource_name,
                        "external_uri": f.external_uri
                    })

                # SECONDARY QUERY: Organization Level (if ID provided)
                if organization_id:
                     try:
                         org_source = f"organizations/{organization_id}/sources/-"
                         # specific check for MFA
                         mfa_filter = 'category="MFA_NOT_ENFORCED" AND state="ACTIVE"'
                         
                         org_findings = client.list_findings(request={"parent": org_source, "filter": mfa_filter})
                         for result in org_findings:
                            f = result.finding
                            findings.append({
                                "category": f.category,
                                "state": f.state.name,
                                "severity": f.severity.name,
                                "event_time": f.event_time.isoformat() if f.event_time else "",
                                "resource_name": f.resource_name,
                                "external_uri": f.external_uri
                            })
                     except Exception as org_e:
                         # It's okay if this fails (permissions), just log it
                         logger.warning(f"Failed to fetch Org-level findings (MFA check): {org_e}")

                return findings
                
            except Exception as e:
                error_str = str(e)
                if "SERVICE_DISABLED" in error_str or "has not been used" in error_str:
                     # Attempt Auto-Enable
                     import re
                     project_to_enable = target_project
                     project_match = re.search(r'project[\/\s]+([a-zA-Z0-9\-\.]+)', error_str)
                     if project_match:
                         detected = project_match.group(1)
                         if detected != 'projects':
                             project_to_enable = detected
                     
                     logger.info(f"SCC API disabled. Attempting to enable on {project_to_enable} and retry...")
                     try:
                         self.enable_api("securitycenter.googleapis.com", project_id=project_to_enable)
                         
                         # Retry Listing
                         findings_result = client.list_findings(
                            request={"parent": source_name, "filter": filter_str}
                         )
                         # Process results (dup logic, but simple enough)
                         findings = []
                         for result in findings_result:
                            f = result.finding
                            findings.append({
                                "category": f.category,
                                "state": f.state.name,
                                "severity": f.severity.name,
                                "event_time": f.event_time.isoformat() if f.event_time else "",
                                "resource_name": f.resource_name,
                                "external_uri": f.external_uri
                            })
                         return findings
                     except Exception as retry_err:
                         retry_msg = str(retry_err)
                         logger.warning(f"SCC Auto-Enable/Retry failed: {retry_msg}")
                         
                         if "Permission denied" in retry_msg or "403" in retry_msg:
                             return [{
                                 "category": "Configuration Error", 
                                 "state": "API_DISABLED", 
                                 "severity": "HIGH", 
                                 "resource_name": f"Check Permissions in {project_to_enable}", 
                                 "external_uri": f"https://console.cloud.google.com/iam-admin/iam?project={project_to_enable}",
                                 "event_time": "",
                                 "source_properties": {
                                     "Explanation": "Scanner attempted to enable securitycenter.googleapis.com but was denied.",
                                     "Action": "Grant 'Service Usage Admin' to scanner SA or enable API manually."
                                 }
                             }]

                         # Fall through to return generic error finding
                     
                     return [{
                         "category": "Configuration Error", 
                         "state": "API_DISABLED", 
                         "severity": "HIGH", 
                         "resource_name": f"Enable [securitycenter.googleapis.com] in Project: {project_to_enable}", 
                         "external_uri": f"https://console.developers.google.com/apis/api/securitycenter.googleapis.com/overview?project={project_to_enable}",
                         "event_time": ""
                     }]
                elif "403" in error_str or "Permission denied" in error_str:
                     logger.error(f"Permission Error listing findings for {target_project}: {e}")
                     return [{
                         "category": "Access Denied", 
                         "state": "PERMISSION_DENIED", 
                         "severity": "HIGH", 
                         "resource_name": "Missing roles/securitycenter.findingsViewer", 
                         "external_uri": "https://console.cloud.google.com/iam-admin/iam",
                         "event_time": ""
                     }]
                elif "400" in error_str and "sources" in error_str:
                     logger.warning(f"Project-level source queries not supported in this org (requires Enterprise): {e}")
                else:
                     logger.warning(f"Project-level SCC query failed: {e}")
                return []

        except Exception as e:
            logger.error(f"Error listing SCC findings: {e}")
            return []

    def get_iam_policy(self, project_id: Optional[str] = None, organization_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get IAM policy for a project or organization
        
        Args:
            project_id: Project ID (defaults to self.project_id)
            organization_id: Optional Org ID (if provided, gets Org policy instead of Project)
            
        Returns:
            Dict representing the IAM Policy
        """
        try:
            service = build('cloudresourcemanager', 'v1', credentials=self.credentials)
            
            if organization_id:
                resource = f"organizations/{organization_id}"
                policy = service.organizations().getIamPolicy(resource=resource, body={}).execute()
            else:
                target = project_id or self.project_id
                resource = target  # v1 API expects just project_id for projects().getIamPolicy
                policy = service.projects().getIamPolicy(resource=resource, body={}).execute()
                
            return policy
        except Exception as e:
            logger.error(f"Error fetching IAM policy: {str(e)}")
            # Return empty structure on failure
            return {"bindings": [], "etag": ""}
            
    def list_log_metrics(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List Log-Based Metrics in a project
        
        Args:
            project_id: Project ID
            
        Returns:
            List of metric descriptors
        """
        try:
            target = project_id or self.project_id
            
            # Lazy import
            try:
                from google.cloud import logging as cloud_logging
            except ImportError:
                return []
                
            client = cloud_logging.Client(credentials=self.credentials, project=target)
            metrics = list(client.list_metrics())
            
            results = []
            for m in metrics:
                results.append({
                    "name": m.name,
                    "filter": m.filter,
                    "description": m.description
                })
            return results
        except Exception as e:
            logger.warning(f"Error listing log metrics: {str(e)}")
            return []

    def list_alert_policies(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List Monitoring Alert Policies
        
        Args:
            project_id: Project ID
            
        Returns:
            List of alert policies
        """
        try:
            target = project_id or self.project_id
            try:
                from google.cloud import monitoring_v3
            except ImportError:
                return []
                
            client = monitoring_v3.AlertPolicyServiceClient(credentials=self.credentials)
            project_name = f"projects/{target}"
            
            policies = client.list_alert_policies(name=project_name)
            results = []
            for p in policies:
                results.append({
                    "name": p.name,
                    "display_name": p.display_name,
                    "enabled": p.enabled.value if hasattr(p.enabled, 'value') else p.enabled,
                    "conditions": [c.display_name for c in p.conditions]
                })
            return results
        except Exception as e:
            logger.warning(f"Error listing alert policies: {str(e)}")
            return []
