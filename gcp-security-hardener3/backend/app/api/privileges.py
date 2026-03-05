"""
Privilege Management API
Endpoints for privilege escalation, de-escalation, and timer management
"""
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from app.services.privilege_manager_service import PrivilegeManagerService
from app.services.privilege_timer_service import PrivilegeTimerService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/privileges", tags=["privileges"])

# In-memory timer service (would be replaced with database in production)
_timer_service = PrivilegeTimerService()


class ElevateRequest(BaseModel):
    service_account_email: str
    project_ids: List[str]
    duration_minutes: int = 5


class RevokeRequest(BaseModel):
    service_account_email: str
    project_ids: List[str]
    timer_id: Optional[str] = None


@router.post("/elevate")
async def elevate_privileges(
    request: ElevateRequest
):
    """
    Elevate service account to admin privileges (Phase 2)
    
    **Flow:**
    1. Grant elevated roles
    2. Start 5-minute timer
    3. Return timer ID
    """
    try:
        logger.info(f"[PRIVILEGES] Elevating {request.service_account_email}")
        
        privilege_manager = PrivilegeManagerService(credentials=None)  # Would use actual creds
        
        # Elevate privileges
        elevation_result = privilege_manager.elevate_to_admin(
            service_account_email=request.service_account_email,
            project_ids=request.project_ids
        )
        
        if not elevation_result["success"]:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to elevate privileges: {elevation_result.get('errors')}"
            )
        
        # Start timer
        timer_result = _timer_service.start_timer(
            service_account_email=request.service_account_email,
            project_ids=request.project_ids,
            duration_minutes=request.duration_minutes
        )
        
        return {
            "success": True,
            "elevated_projects": elevation_result["elevated_projects"],
            "timer": timer_result,
            "message": f"Privileges elevated for {request.duration_minutes} minutes"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error elevating privileges: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/timer/{timer_id}")
async def get_timer_status(
    timer_id: str
):
    """
    Check status of privilege escalation timer
    
    Used for countdown display in frontend
    """
    try:
        status = _timer_service.check_timer_status(timer_id)
        
        if "error" in status:
            raise HTTPException(status_code=404, detail=status["error"])
        
        return status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking timer: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/revoke")
async def revoke_privileges(
    request: RevokeRequest
):
    """
    Revoke ALL privileges from service account (Phase 3)
    
    **Triggers:**
    - User clicks "Finished" button
    - Timer expires (automatic)
    """
    try:
        logger.info(f"[PRIVILEGES] Revoking all privileges from {request.service_account_email}")
        
        privilege_manager = PrivilegeManagerService(credentials=None)
        
        # Revoke all privileges
        revoke_result = privilege_manager.revoke_all_privileges(
            service_account_email=request.service_account_email,
            project_ids=request.project_ids
        )
        
        # Cancel timer if provided
        if request.timer_id:
            _timer_service.force_expire(request.timer_id)
        
        return {
            "success": revoke_result["success"],
            "revoked_projects": revoke_result["revoked_projects"],
            "failed_projects": revoke_result.get("failed_projects", []),
            "message": "All privileges revoked successfully"
        }
        
    except Exception as e:
        logger.error(f"Error revoking privileges: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/{service_account_email}")
async def get_privilege_status(
    service_account_email: str
):
    """
    Get current privilege level for a service account
    
    Used to display current status badge in UI
    """
    try:
        # In production, would query actual IAM roles
        # For now, check active timers
        
        # Find active timers for this service account
        active_timers = [
            timer for timer in _timer_service.active_timers.values()
            if timer ["service_account_email"] == service_account_email
            and timer["status"] == "active"
        ]
        
        if active_timers:
            timer = active_timers[0]
            status = _timer_service.check_timer_status(timer["timer_id"])
            
            privilege_level = "elevated" if not status["expired"] else "viewer"
        else:
            privilege_level = "viewer"
        
        return {
            "service_account_email": service_account_email,
            "privilege_level": privilege_level,
            "active_timer": active_timers[0]["timer_id"] if active_timers else None
        }
        
    except Exception as e:
        logger.error(f"Error getting privilege status: {e}")
        raise HTTPException(status_code=500, detail=str(e))
