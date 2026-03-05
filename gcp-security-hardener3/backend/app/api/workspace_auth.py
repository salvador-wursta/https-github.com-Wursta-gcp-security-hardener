"""
Workspace Authentication API
Endpoints for Google Workspace superadmin OAuth and service account creation
"""
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from app.services.workspace_admin_service import WorkspaceAdminService
from app.services.privilege_manager_service import PrivilegeManagerService
from app.services.privilege_tester_service import PrivilegeTesterService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/workspace", tags=["workspace"])


class ServiceAccountCreateRequest(BaseModel):
    org_id: str
    account_name: str = "svc-lockdown-tmp"


class ProjectSelectionRequest(BaseModel):
    service_account_email: str
    project_ids: List[str]


@router.post("/service-account/create")
async def create_service_account(
    request: ServiceAccountCreateRequest
):
    """
    Create temporary service account at organization level
    
    **Phase 1Step 2:** After superadmin OAuth authentication
    """
    try:
        # In production, get credentials from OAuth flow
        # For now, using default credentials
        workspace_admin = WorkspaceAdminService()
        
        result = workspace_admin.create_service_account_at_org(
            org_id=request.org_id,
            account_name=request.account_name
        )
        
        if not result["success"]:
            raise HTTPException(status_code=400, detail=result.get("error"))
        
        return result
        
    except Exception as e:
        logger.error(f"Error creating service account: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/projects/discover")
async def discover_projects(
    org_id: str
):
    """
    Discover all projects in organization
    
    **Phase 1, Step 3:** Show user all available projects
    """
    try:
        workspace_admin = WorkspaceAdminService()
        
        result = workspace_admin.discover_org_projects(org_id)
        
        if not result["success"]:
            raise HTTPException(status_code=400, detail=result.get("error"))
        
        return result
        
    except Exception as e:
        logger.error(f"Error discovering projects: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/service-account/assign-viewer")
async def assign_viewer_privileges(
    request: ProjectSelectionRequest
):
    """
    Assign view-only roles to service account on selected projects
    
    **Phase 1, Step 6:** After user selects projects
    """
    try:
        privilege_manager = PrivilegeManagerService(credentials=None)  # Would use actual creds
        
        result = privilege_manager.assign_viewer_to_projects(
            service_account_email=request.service_account_email,
            project_ids=request.project_ids
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Error assigning viewer privileges: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/service-account/test-privileges")
async def test_privileges(
    service_account_email: str,
    project_id: str,
    test_type: str = "scan"  # "scan" or "lockdown"
):
    """
    Test if service account has required privileges
    
    **Phase 1, Step 7:** Test scan privileges
    **Phase 2:** Test lockdown privileges
    """
    try:
        privilege_tester = PrivilegeTesterService(
            credentials=None,  # Would use actual credentials
            project_id=project_id
        )
        
        if test_type == "scan":
            result = privilege_tester.test_scan_privileges(service_account_email)
        elif test_type == "lockdown":
            result = privilege_tester.test_lockdown_privileges(service_account_email)
        else:
            raise HTTPException(status_code=400, detail=f"Invalid test_type: {test_type}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error testing privileges: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/service-account/find")
async def find_existing_service_account(
    org_id: str,
    account_name_pattern: str = "svc-lockdown-tmp"
):
    """
    Search for existing lockdown service account
    
    **Phase 4:** Check if service account already exists before creating new one
    """
    try:
        workspace_admin = WorkspaceAdminService()
        
        result = workspace_admin.find_existing_service_account(
            org_id=org_id,
            account_name_pattern=account_name_pattern
        )
        
        if result:
            return {
                "exists": True,
                **result
            }
        else:
            return {
                "exists": False
            }
        
    except Exception as e:
        logger.error(f"Error finding service account: {e}")
        raise HTTPException(status_code=500, detail=str(e))
