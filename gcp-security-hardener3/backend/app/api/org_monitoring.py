
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from app.services.org_monitoring_service import OrgMonitoringService
from app.services.credential_service import CredentialService
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

class OrgMonitoringSetupRequest(BaseModel):
    org_id: str = Field(..., description="Organization ID (e.g., '1234567890')")
    project_id: str = Field(..., description="Destination Project ID for Security Monitoring")
    billing_account_id: str = Field(..., description="Billing Account ID for the safety budget")
    alert_emails: List[str] = Field(..., description="List of emails to receive alerts")
    region: str = Field("us-central1", description="Region for the Log Bucket (default: us-central1)")
    credential_token: str = Field(..., description="Secure token for service account credentials")

class OrgMonitoringSetupResponse(BaseModel):
    success: bool
    steps_completed: List[str]
    sink_name: Optional[str]
    bucket_path: Optional[str]
    budget_name: Optional[str]
    errors: List[str]

@router.post("/setup", response_model=OrgMonitoringSetupResponse)
async def setup_org_monitoring(request: OrgMonitoringSetupRequest):
    """
    Orchestrates the setup of Organization-Level Monitoring:
    1. Aggregated Sink
    2. Central Log Bucket
    3. Log-Based Metrics
    4. Alert Policies
    5. Billing Budget
    """
    # Retrieve credentials from token
    try:
        credentials = CredentialService.get_credentials(request.credential_token)
        if not credentials:
            raise HTTPException(status_code=401, detail="Invalid or expired credential token")
        
        # UNWRAP if there's a service_account_key wrapper
        if 'service_account_key' in credentials:
            credentials = credentials['service_account_key']
        
        # CHECK IF THIS IS DUAL-SERVICE-ACCOUNT
        if credentials.get('auth_type') == 'dual-service-account':
            scanner_creds = credentials.get('scanner_credentials')
            if not scanner_creds:
                raise HTTPException(status_code=400, detail="Dual-service-account missing scanner_credentials")
            credentials = scanner_creds
            
        logger.info(f"Retrieved credentials for org monitoring setup")
    except Exception as e:
        logger.error(f"Failed to retrieve credentials: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid or expired credential token")
    
    service = OrgMonitoringService(credentials=credentials)
    response = {
        "success": True, 
        "steps_completed": [], 
        "errors": [],
        "sink_name": None,
        "bucket_path": None,
        "budget_name": None
    }

    try:
        # 1. Setup Sink
        try:
            # Standard bucket name for security logs
            bucket_name = "security-org-logs"
            
            sink_result = service.setup_aggregated_sink(
                org_id=request.org_id,
                destination_project_id=request.project_id,
                destination_bucket_name=bucket_name,
                location=request.region
            )
            response["sink_name"] = sink_result.get("sink_name")
            response["steps_completed"].append("setup_aggregated_sink")
            
        except Exception as e:
            response["errors"].append(f"Sink Setup Failed: {str(e)}")
            response["success"] = False
            return response # Critical failure

        # 2. Ensure Bucket
        try:
            bucket_result = service.ensure_log_bucket(
                project_id=request.project_id,
                bucket_name=bucket_name,
                location=request.region,
                writer_identity=sink_result.get("writer_identity")
            )
            response["bucket_path"] = bucket_result.get("bucket_path")
            response["steps_completed"].append("ensure_log_bucket")
        except Exception as e:
            response["errors"].append(f"Bucket Setup Failed: {str(e)}")
            response["success"] = False

        # 3. Create Metrics
        try:
            metrics_result = service.create_log_metrics(request.project_id)
            if not metrics_result["success"]:
                response["errors"].append(f"Metrics Creation Failed: {metrics_result.get('error')}")
            else:
                response["steps_completed"].append("create_log_metrics")
        except Exception as e:
            response["errors"].append(f"Metrics Creation Exception: {str(e)}")

        # 4. Create Alerts
        try:
            alerts_result = service.create_metric_alerts(request.project_id, request.alert_emails)
            response["steps_completed"].append("create_metric_alerts")
        except Exception as e:
            response["errors"].append(f"Alerts Creation Exception: {str(e)}")

        # 5. Create Budget
        try:
            budget_result = service.create_logging_budget(
                billing_account_id=request.billing_account_id,
                project_id=request.project_id,
                email_address=request.alert_emails[0] if request.alert_emails else "admin"
            )
            if budget_result["success"]:
                 response["budget_name"] = budget_result.get("budget_name")
                 response["steps_completed"].append("create_logging_budget")
            else:
                 response["errors"].append(f"Budget Creation Failed: {budget_result.get('error')}")
        except Exception as e:
            response["errors"].append(f"Budget Creation Exception: {str(e)}")

    except Exception as e:
        response["success"] = False
        response["errors"].append(f"Orchestration Error: {str(e)}")

    return response


class GetOrgIdRequest(BaseModel):
    project_id: str = Field(..., description="Project ID to get the organization for")
    credential_token: str = Field(..., description="Secure token for service account credentials")


class GetOrgIdResponse(BaseModel):
    success: bool
    organization_id: Optional[str] = None
    organization_name: Optional[str] = None
    error: Optional[str] = None


@router.post("/get-org-id", response_model=GetOrgIdResponse)
async def get_organization_id(request: GetOrgIdRequest):
    """
    Automatically retrieves the Organization ID for a given project.
    Uses the Cloud Resource Manager API to get the project's parent organization.
    """
    logger.info(f"[GET-ORG-ID] Getting org ID for project: {request.project_id}")
    
    try:
        # Retrieve credentials from token
        credentials = CredentialService.get_credentials(request.credential_token)
        if not credentials:
            return GetOrgIdResponse(success=False, error="Invalid or expired credential token")
        
        # UNWRAP if there's a service_account_key wrapper
        if 'service_account_key' in credentials:
            credentials = credentials['service_account_key']
        
        # CHECK IF THIS IS DUAL-SERVICE-ACCOUNT
        if credentials.get('auth_type') == 'dual-service-account':
            scanner_creds = credentials.get('scanner_credentials')
            if not scanner_creds:
                    return GetOrgIdResponse(success=False, error="Dual-service-account missing scanner_credentials")
            credentials = scanner_creds
            logger.info("Using scanner credentials for org ID lookup")
            
        # Build credentials object
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        
        creds = service_account.Credentials.from_service_account_info(credentials)
        
        # Use Cloud Resource Manager API to get project info
        crm_service = build('cloudresourcemanager', 'v1', credentials=creds)
        
        # Get project to find its parent
        project = crm_service.projects().get(projectId=request.project_id).execute()
        logger.info(f"[GET-ORG-ID] Project info: {project}")
        
        # Walk up the hierarchy to find organization
        parent = project.get('parent', {})
        
        if parent.get('type') == 'organization':
            org_id = parent.get('id')
            logger.info(f"[GET-ORG-ID] Found org directly: {org_id}")
            return GetOrgIdResponse(
                success=True,
                organization_id=org_id,
                organization_name=None
            )
        elif parent.get('type') == 'folder':
            # Need to traverse up through folders to find org
            folders_service = build('cloudresourcemanager', 'v2', credentials=creds)
            folder_id = parent.get('id')
            
            # Walk up folder hierarchy (max 10 levels)
            for _ in range(10):
                folder = folders_service.folders().get(name=f"folders/{folder_id}").execute()
                folder_parent = folder.get('parent', '')
                
                if folder_parent.startswith('organizations/'):
                    org_id = folder_parent.replace('organizations/', '')
                    logger.info(f"[GET-ORG-ID] Found org via folder: {org_id}")
                    return GetOrgIdResponse(
                        success=True,
                        organization_id=org_id,
                        organization_name=None
                    )
                elif folder_parent.startswith('folders/'):
                    folder_id = folder_parent.replace('folders/', '')
                else:
                    break
            
            return GetOrgIdResponse(
                success=False,
                error="Could not find organization in folder hierarchy"
            )
        else:
            return GetOrgIdResponse(
                success=False,
                error=f"Project has no parent organization (parent type: {parent.get('type', 'none')})"
            )
            
    except Exception as e:
        logger.error(f"[GET-ORG-ID] Error: {str(e)}")
        return GetOrgIdResponse(
            success=False,
            error=f"Failed to get organization: {str(e)}"
        )
