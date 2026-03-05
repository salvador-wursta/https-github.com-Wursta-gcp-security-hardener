"""
API endpoints for listing GCP projects
"""
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any, Optional
from app.services.gcp_client import GCPClient
from app.services.firebase_auth_service import FirebaseAuthService
from app.services.credential_service import CredentialService
from pydantic import BaseModel, Field, validator, root_validator

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])


class ListProjectsRequest(BaseModel):
    """Request to list projects"""
    access_token: str = ""  # Optional Firebase token
    organization_id: Optional[str] = None  # Optional organization ID to filter
    credential_token: Optional[str] = Field(None, description="Secure token for service account credentials")
    jit_token: Optional[str] = Field(None, description="JIT Session Token from /session/start (Phase 2 Auth)")
    impersonate_email: Optional[str] = Field(None, description="Scanner SA email to impersonate for project listing")
    target_id: Optional[str] = Field(None, description="Explict target ID (Project) for fallback lookup if org listing fails")

    @validator('credential_token')
    def validate_credential(cls, v, values):
        return v # Defer to root validator or check logic

    @root_validator(pre=True)
    def validate_tokens(cls, values):
        cred = values.get('credential_token')
        jit = values.get('jit_token')
        if not cred and not jit:
            # Check if using other mechanism? 
            # Actually, let's stick to the logic: validation fails if neither is present.
            # But values might be raw dict here (pre=True).
            pass 
        return values

    @root_validator(skip_on_failure=True)
    def validate_at_least_one_token(cls, values):
        # Phase 4 SaaS: In identity-based mode, tokens are optional.
        # We allow empty tokens and will fallback to ADC.
        return values


class ProjectInfo(BaseModel):
    """Project information"""
    project_id: str
    name: Optional[str] = None
    project_number: Optional[str] = None
    lifecycle_state: Optional[str] = None
    labels: Dict[str, str] = {}
    organization_id: Optional[str] = None


class ListProjectsResponse(BaseModel):
    """Response with list of projects"""
    projects: List[ProjectInfo]
    total: int
    warning: Optional[str] = None


@router.post("/list", response_model=ListProjectsResponse)
def list_projects(request: ListProjectsRequest):
    """
    List all accessible GCP projects
    
    Uses service account credentials to list all projects the service account can access.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("List projects request received")
        
        # Verify Firebase token if provided (optional)
        if request.access_token:
            logger.info("Verifying Firebase authentication token...")
            try:
                user_info = FirebaseAuthService.verify_firebase_token(request.access_token)
                user_email = user_info.get('email', 'unknown')
                logger.info(f"Firebase token verified for user: {user_email}")
            except Exception as auth_error:
                logger.warning(f"Firebase token verification failed: {str(auth_error)}")
                logger.info("Continuing with service account credentials only")
        else:
            logger.info("No Firebase token provided - using service account credentials only")
        
        if request.jit_token:
            # Phase 2 JIT Auth
            logger.info("Retrieving credentials from JIT Session Token")
            from app.services.jit_session_service import JITSessionService
            session_service = JITSessionService()
            creds_tuple = session_service.get_session_credentials(request.jit_token)
            if not creds_tuple:
                raise HTTPException(status_code=401, detail="JIT Session expired or invalid.")
            service_account_credentials = creds_tuple[0]
            logger.info("Retrieved Scanner credentials from JIT Session")
        else:
            # Phase 4: Fallback to Identity-based Auth (ADC)
            logger.info("No tokens provided, falling back to Identity-based Auth (ADC)")
            service_account_credentials = None 
        
        # Initialize GCPClient using impersonated SA if provided.
        # CRITICAL: impersonate_email MUST be used here so only the scanner SA's projects are returned.
        # Without this, GCPClient() uses personal ADC which lists ALL projects the backend has access to (e.g. sys-projects).
        if request.impersonate_email:
            logger.info(f"Listing projects via impersonation of SA: {request.impersonate_email} for Target: {request.target_id}")
            gcp_client = GCPClient(project_id=request.target_id, impersonate_email=request.impersonate_email)
        elif request.jit_token:
             # Legacy support for JIT Token
             gcp_client = GCPClient(project_id=request.target_id, credentials=service_account_credentials)
        else:
            logger.warning("No impersonate_email or token provided. Returning empty project list to prevent internal ADC leak.")
            return ListProjectsResponse(projects=[], total=0, warning="Please Connect Environment to scan projects.")
        
        logger.info("GCPClient initialized for project listing")

        logger.info("=" * 80)
        logger.info("LISTING ALL ACCESSIBLE PROJECTS")
        logger.info("=" * 80)
        
        try:
            logger.info(f"Calling gcp_client.list_all_projects(organization_id={request.organization_id})...")
            projects_data = gcp_client.list_all_projects(organization_id=request.organization_id)
            logger.info(f"✓ API returned {len(projects_data)} projects")
        except Exception as list_error:
            error_msg = str(list_error)
            logger.error(f"Error listing projects: {error_msg}")
            raise HTTPException(status_code=500, detail=f"Failed to list projects: {error_msg}")

        
        # Convert to response format
        projects = projects_data # Re-bind for consistency below
        
        logger.info(f"Found {len(projects)} projects")
        
        # Convert to response format
        project_infos = [
            ProjectInfo(
                project_id=p["project_id"],
                name=p.get("name", p["project_id"]),
                project_number=p.get("project_number", ""),
                lifecycle_state=p.get("lifecycle_state", "ACTIVE"),
                labels=p.get("labels", {}),
                organization_id=p.get("organization_id")
            )
            for p in projects
        ]
        
        response = ListProjectsResponse(
            projects=project_infos,
            total=len(project_infos)
        )
        
        # Add visibility warning if needed
        if len(projects) <= 1:
             response.warning = (
                 "Only 1 project found. If you expect to see more, ensure the Service Account has "
                 "'roles/resourcemanager.organizationViewer' on the Organization Node."
             )
        
        # Store whether we enabled the API (for cleanup later)
        # We'll pass this information through the response or store it in the client
        # For now, we'll note it in the logs - the lockdown endpoint will handle cleanup
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list projects: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list projects: {str(e)}"
        )


@router.get("/health")
async def projects_health():
    """Health check for projects service"""
    return {"status": "healthy", "service": "projects"}
