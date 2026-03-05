"""
API endpoints for backout/rollback operations
"""
from fastapi import APIRouter, HTTPException, Response
from app.models.backout_models import BackoutRequest, BackoutResponse
from app.services.gcp_client import GCPClient
from app.services.backout_service import BackoutService
from app.services.firebase_auth_service import FirebaseAuthService
from app.services.script_generator import ScriptGenerator
from app.services.credential_service import CredentialService  # New import
from typing import Dict, Any

router = APIRouter(prefix="/api/v1/backout", tags=["backout"])


@router.post("/", response_model=BackoutResponse)
async def perform_backout(request: BackoutRequest):
    """
    Rollback all security lockdown changes
    
    ⚠️ WARNING: This removes all security protections!
    Requires confirm_backout=True in the request body.
    
    Security: Uses service account credentials for GCP API calls
    """
    import logging
    logger = logging.getLogger(__name__)
    
    if not request.confirm_backout:
        raise HTTPException(
            status_code=400,
            detail="confirm_backout must be True to perform backout operation. "
                   "This is a safety measure to prevent accidental rollback."
        )
    
    try:
        logger.info(f"Backout request received for project: {request.project_id}")
        
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
        
        # Retrieve service account credentials from cache using the token
        if request.credential_token:
            logger.info(f"Retrieving service account credentials for token: {request.credential_token[:8]}...")
            service_account_credentials = CredentialService.get_credentials(request.credential_token)
            if not service_account_credentials:
                raise HTTPException(status_code=400, detail="Invalid or expired credential token.")
            logger.info("Service account credentials retrieved successfully.")
        else:
            raise HTTPException(
                status_code=400,
                detail="Credential token is required. Please upload service account credentials to get a token."
            )
        
        # Get project_id from service account (prioritize over request parameter)
        sa_project_id = service_account_credentials.get('project_id')
        effective_project_id = sa_project_id or request.project_id
        
        if not effective_project_id:
            raise HTTPException(
                status_code=400,
                detail="Project ID is required. Please provide project_id in the request or ensure your service account key includes a project_id field."
            )
        
        # Warn if project_id from request doesn't match service account
        if request.project_id and sa_project_id and request.project_id != sa_project_id:
            logger.warning(
                f"Project ID mismatch: request has '{request.project_id}' but service account has '{sa_project_id}'. "
                f"Using '{sa_project_id}' from service account credentials."
            )
        
        # Initialize GCP client with service account credentials
        logger.info(f"Initializing GCP client with project_id: {effective_project_id}")
        try:
            gcp_client = GCPClient(
                project_id=effective_project_id,
                service_account_key=service_account_credentials
            )
        except Exception as cred_error:
            logger.error(f"Failed to initialize GCP client: {str(cred_error)}")
            raise HTTPException(
                status_code=400,
                detail=f"Invalid service account credentials: {str(cred_error)}"
            )
        
        # Update request with effective project_id
        request.project_id = effective_project_id
        
        # Initialize backout service
        logger.info("Initializing backout service...")
        backout_service = BackoutService(gcp_client)
        
        # Perform backout
        logger.info(f"Starting backout process for project: {effective_project_id}...")
        result = backout_service.perform_backout(request)
        
        logger.info(f"Backout completed. Status: {result.status}")
        
        return result
        
    except ValueError as e:
        # Invalid request (e.g., confirm_backout not True)
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    except Exception as e:
        # Generic error
        raise HTTPException(
            status_code=500,
            detail=f"Backout failed: {str(e)}"
        )


@router.post("/generate-script")
async def generate_backout_script(request: BackoutRequest):
    """
    Generate a shell script with gcloud commands for backout
    
    Returns a downloadable shell script file
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # Retrieve service account credentials from cache using the token
        if request.credential_token:
            logger.info(f"Retrieving service account credentials for token: {request.credential_token[:8]}...")
            service_account_credentials = CredentialService.get_credentials(request.credential_token)
            if not service_account_credentials:
                raise HTTPException(status_code=400, detail="Invalid or expired credential token.")
            logger.info("Service account credentials retrieved successfully.")
        else:
            raise HTTPException(
                status_code=400,
                detail="Credential token is required. Please upload service account credentials to get a token."
            )
        
        # Ensure project_id is set from service account if not in request
        if not request.project_id:
            sa_project_id = service_account_credentials.get('project_id')
            if sa_project_id:
                logger.info(f"Using project_id from service account: {sa_project_id}")
                request.project_id = sa_project_id
        
        if not request.project_id:
            raise HTTPException(
                status_code=400,
                detail="Project ID is required. Please provide project_id in the request or ensure your service account key includes a project_id field."
            )
        
        logger.info(f"Generating backout script for project: {request.project_id}")
        script_content = ScriptGenerator.generate_backout_script(request)
        
        # Generate timestamp for unique filename
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"backout_{request.project_id}_{timestamp}.sh"
        
        # Return as downloadable file
        return Response(
            content=script_content,
            media_type="application/x-sh",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to generate backout script: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate script: {str(e)}"
        )


@router.get("/health")
async def backout_health():
    """Health check for backout service"""
    return {"status": "healthy", "service": "backout"}

