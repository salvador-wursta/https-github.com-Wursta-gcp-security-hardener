from fastapi import APIRouter, Depends, HTTPException, Header
from app.models.session_models import SessionInitRequest, SessionStatus
from app.services.jit_session_service import JITSessionService
import logging

router = APIRouter(tags=["session"])
logger = logging.getLogger(__name__)

def get_session_service():
    return JITSessionService()

@router.post("/start")
async def start_session(
    request: SessionInitRequest,
    service: JITSessionService = Depends(get_session_service)
):
    """
    Start a new JIT session with the provided credential keys.
    Returns: {"token": "..."}
    """
    try:
        if not request.scanner_key_content:
            raise HTTPException(status_code=400, detail="Scanner key is required")
            
        token = service.start_session(request.scanner_key_content, request.admin_key_content)
        return {"token": token}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Session start failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to start session")

@router.get("/status")
async def check_session_status(
    x_jit_token: str = Header(None),
    service: JITSessionService = Depends(get_session_service)
):
    """
    Check if the current session is valid and get remaining time.
    """
    if not x_jit_token:
        return SessionStatus(is_active=False, remaining_seconds=0, expires_at="1970-01-01T00:00:00")
        
    status = service.get_status(x_jit_token)
    return status

@router.post("/refresh")
async def refresh_session(
    x_jit_token: str = Header(None),
    service: JITSessionService = Depends(get_session_service)
):
    """
    Ping to keep the session alive (reset timeout).
    """
    if not x_jit_token:
        raise HTTPException(status_code=401, detail="No session token provided")
        
    session = service.access_session(x_jit_token)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
        
    return service.get_status(x_jit_token)

@router.post("/end")
async def end_session(
    x_jit_token: str = Header(None),
    service: JITSessionService = Depends(get_session_service)
):
    """
    Securely end the session and purge credentials.
    """
    if x_jit_token:
        service.end_session(x_jit_token)
    return {"message": "Session ended"}
