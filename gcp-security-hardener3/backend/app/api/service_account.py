"""
API endpoints for service account management
"""
from fastapi import APIRouter, HTTPException
from app.models.service_account_models import (
    CreateServiceAccountRequest,
    ServiceAccountResponse,
    DisableServiceAccountRequest,
    DisableServiceAccountResponse
)
from app.services.service_account_service import ServiceAccountService
from app.services.firebase_auth_service import FirebaseAuthService

router = APIRouter(prefix="/api/v1/service-account", tags=["service-account"])


@router.post("/create", response_model=ServiceAccountResponse)
async def create_service_account(request: CreateServiceAccountRequest):
    """
    Create a temporary service account with required permissions
    
    Security: Requires user authentication via Firebase token
    The service account will be disabled after operations complete
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"Service account creation requested for project: {request.project_id}")
        logger.info(f"Requested by user: {request.user_email}")
        
        # Initialize service account service
        sa_service = ServiceAccountService(project_id=request.project_id)
        
        # Create service account
        sa_info = sa_service.create_temp_service_account(request.user_email)
        
        logger.info(f"Service account created: {sa_info['email']}")
        
        return ServiceAccountResponse(**sa_info)
        
    except ValueError as e:
        logger.error(f"Service account creation failed: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail=f"Failed to create service account: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Service account creation error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Service account creation failed: {str(e)}"
        )


@router.post("/disable", response_model=DisableServiceAccountResponse)
async def disable_service_account(request: DisableServiceAccountRequest):
    """
    Disable a service account and remove all permissions
    
    Security: Service account is disabled but not deleted for audit purposes
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"Service account disable requested: {request.service_account_email}")
        
        # Initialize service account service
        sa_service = ServiceAccountService(project_id=request.project_id)
        
        # Disable and cleanup
        sa_service.disable_and_cleanup(request.service_account_email)
        
        logger.info(f"Service account disabled: {request.service_account_email}")
        
        return DisableServiceAccountResponse(
            service_account_email=request.service_account_email,
            status="disabled",
            message="Service account disabled and permissions removed. Account retained for audit purposes."
        )
        
    except Exception as e:
        logger.error(f"Service account disable error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to disable service account: {str(e)}"
        )


@router.get("/health")
async def service_account_health():
    """Health check for service account service"""
    return {"status": "healthy", "service": "service-account"}

