"""
API endpoints for security lockdown operations
"""
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import FileResponse
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging
import sys

logger = logging.getLogger(__name__)
from app.models.lockdown_models import (
    LockdownRequest, LockdownResponse, 
    MultiProjectLockdownRequest, MultiProjectLockdownResponse
)
from app.models.script_models import (
    AnalyzeLockdownRequest, AnalyzeLockdownResponse, GenerateScriptRequest,
    ExecuteScriptRequest, ExecuteScriptResponse
)
from app.services.gcp_client import GCPClient
from app.services.lockdown_service import LockdownService
from app.services.firebase_auth_service import FirebaseAuthService
from app.services.script_generator import ScriptGenerator
from app.services.credential_service import CredentialService
from typing import List
from datetime import datetime
from slowapi import Limiter
from slowapi.util import get_remote_address


router = APIRouter(prefix="/api/v1/lockdown", tags=["lockdown"])
limiter = Limiter(key_func=get_remote_address)


@router.get("/reports/{filename}")
async def download_report_file(filename: str):
    """
    Download a persistent report/log file.
    Ensures security by stripping paths and only serving from reports/ directory.
    """
    # Security: Prevent directory traversal
    safe_filename = os.path.basename(filename)
    reports_dir = Path(os.getcwd()) / "reports"
    file_path = reports_dir / safe_filename

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail=f"Log file not found: {safe_filename}")

    return FileResponse(
        path=file_path, 
        filename=safe_filename,
        media_type='text/plain' 
    )


@router.post("/", response_model=LockdownResponse)
@limiter.limit("5/minute")
async def apply_lockdown(http_request: Request, request: LockdownRequest):
    """
    Apply comprehensive security lockdown to a GCP project
    
    Security: Uses user-provided service account credentials
    This endpoint performs destructive operations - use with caution!
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"Lockdown request received for project: {request.project_id}")
        
        # Verify Firebase token if provided (optional when using service account)
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
        
        # Get credentials from token or direct (support both methods)
        credentials = None
        
        if request.credential_token:
            logger.info("Retrieving credentials from secure token for lockdown")
            credentials = CredentialService.get_credentials(request.credential_token)
            if not credentials:
                logger.error("Failed to retrieve credentials: Invalid or expired token")
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or expired credential token"
                )
            logger.info("Successfully retrieved credentials from token (token deleted)")
        elif request.service_account_credentials:
            logger.warning("Using credentials from request body for lockdown (deprecated - use credential_token)")
            credentials = request.service_account_credentials
        else:
            raise HTTPException(
                status_code=400,
                detail="Either credential_token or service_account_credentials is required"
            )
        
        logger.info("Using service account credentials for lockdown")
        
        # Prioritize project_id from service account credentials over request parameter
        # Service account credentials always have the correct project_id
        sa_project_id = credentials.get('project_id')
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
        
        try:
            from google.oauth2 import service_account
            sa_credentials = service_account.Credentials.from_service_account_info(
                credentials
            )
            logger.info(f"Loaded service account: {sa_credentials.service_account_email}")
            
            # Initialize GCP client with provided credentials
            gcp_client = GCPClient(
                project_id=effective_project_id,
                service_account_key=credentials
            )
            logger.info(f"GCP client initialized with project_id: {effective_project_id}")
        except Exception as cred_error:
            logger.error(f"Failed to use service account credentials: {str(cred_error)}")
            raise HTTPException(
                status_code=400,
                detail=f"Invalid service account credentials: {str(cred_error)}"
            )
        
        # Update request with effective project_id
        request.project_id = effective_project_id
        
        # Initialize lockdown service
        logger.info("Initializing lockdown service...")
        lockdown_service = LockdownService(gcp_client)
        
        # Apply lockdown
        logger.info(f"Starting lockdown process for project: {effective_project_id}...")
        logger.info(f"Request details:")
        logger.info(f"  Security profile: {request.security_profile}")
        logger.info(f"  Selected risk IDs: {request.selected_risk_ids or 'None (all steps)'}")
        logger.info(f"  Region: {request.region or 'None'}")
        logger.info(f"  Budget limit: ${request.budget_limit or 'None'}")
        logger.info(f"  Alert emails: {request.alert_emails or 'None'}")
        
        try:
            result = lockdown_service.apply_lockdown(request)
            logger.info(f"Lockdown completed. Status: {result.status}")
            logger.info(f"Summary: {result.summary}")
            if result.errors:
                logger.error(f"Errors encountered: {len(result.errors)}")
                for i, error in enumerate(result.errors, 1):
                    logger.error(f"  {i}. {error}")
        except Exception as lockdown_error:
            logger.error("=" * 80)
            logger.error(f"CRITICAL ERROR during lockdown execution:")
            logger.error(f"  Project: {effective_project_id}")
            logger.error(f"  Error type: {type(lockdown_error).__name__}")
            logger.error(f"  Error message: {str(lockdown_error)}")
            import traceback
            logger.error(f"  Stack trace:\n{traceback.format_exc()}")
            logger.error("=" * 80)
            raise
        
        # Disable Cloud Resource Manager API after lockdown (cleanup)
        # This API was only needed for listing projects, not for lockdown operations
        # We disable it to follow least-privilege principle - only enable APIs when needed
        logger.info("Cleaning up: Disabling Cloud Resource Manager API...")
        try:
            cloud_resource_manager_api = "cloudresourcemanager.googleapis.com"
            disable_result = gcp_client.disable_api(cloud_resource_manager_api, project_id=effective_project_id)
            if disable_result.get("status") in ["disabled", "already_disabled"]:
                logger.info("✓ Cloud Resource Manager API disabled (or was already disabled)")
            else:
                logger.info(f"Cloud Resource Manager API disable operation: {disable_result.get('status')}")
        except Exception as disable_error:
            logger.warning(f"Could not disable Cloud Resource Manager API: {str(disable_error)}")
            logger.info("This is not critical - API will remain enabled. You can disable it manually if needed.")
        
        return result
        
    except HTTPException:
        # Re-raise HTTP exceptions (already formatted)
        raise
    except ValueError as e:
        # Invalid credentials
        logger.error(f"Authentication failed: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail=f"Authentication failed: {str(e)}"
        )
    except Exception as e:
        # Generic error
        logger.error(f"Lockdown failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Lockdown failed: {str(e)}"
        )


@router.post("/plan", response_model=LockdownResponse)
async def plan_lockdown(request: LockdownRequest):
    """
    Generate a lockdown plan (Change Control) without executing it.
    Returns list of proposed changes.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # Retrieve credentials (same logic as apply)
        # Note: We still need credentials to initialize clients even for planning,
        # though plan currently just generates based on input.
        # Ideally, a robust plan would check 'current state' vs 'desired state', which requires creds.
        
        credentials = None
        if request.credential_token:
            from app.services.credential_service import CredentialService
            credentials = CredentialService.get_credentials(request.credential_token)
        elif request.service_account_credentials:
            credentials = request.service_account_credentials
        else:
             raise HTTPException(status_code=400, detail="Credentials required for planning")
             
        sa_project_id = credentials.get('project_id')
        effective_project_id = sa_project_id or request.project_id
        request.project_id = effective_project_id
        
        # Init client is optional for pure generation but good for future "dry run"
        gcp_client = GCPClient(project_id=effective_project_id, service_account_key=credentials)
        
        lockdown_service = LockdownService(gcp_client)
        plan = lockdown_service.create_plan(request)
        
        return plan

    except Exception as e:
        logger.error(f"Planning failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/profiles")
async def list_profiles():
    """List available security profiles"""
    from app.models.lockdown_models import SecurityProfile
    from app.services.security_profiles import SecurityProfiles
    
    profiles = []
    for profile in SecurityProfile:
        config = SecurityProfiles.get_profile(profile)
        profiles.append({
            "id": profile.value,
            "name": config["name"],
            "description": config["description"],
            "allowed_apis": config["allowed_apis"],
            "denied_apis": config.get("denied_apis", []),
            "allow_external_ips": config.get("allow_external_ips", False),
            "allow_gpus": config.get("allow_gpus", False)
        })
    
    return {"profiles": profiles}


@router.post("/analyze")
async def analyze_lockdown(request: AnalyzeLockdownRequest):
    """
    Analyze project and return list of APIs with recommendations
    
    This endpoint analyzes all enabled APIs, categorizes them by risk level,
    and provides recommendations for which APIs to disable.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"[API ANALYSIS] Analyzing project: {request.project_id}")
        
        # Get service account credentials from credential token
        from app.services.credential_service import CredentialService
        from app.services.gcp_client import GCPClient
        
        # Use credential token if provided, otherwise fallback to stored credentials
        if request.credential_token:
            logger.info(f"[API ANALYSIS] Attempting to retrieve credentials for token: {request.credential_token[:8]}...")
            cred_service = CredentialService()
            credentials_data = cred_service.get_credentials(request.credential_token)
            
            if credentials_data is None:
                logger.error(f"[API ANALYSIS] Credential token not found or expired: {request.credential_token[:8]}...")
                raise HTTPException(status_code=401, detail="Invalid or expired credential token")
            
            # Check if this is dual-service-account format
            if credentials_data.get('auth_type') == 'dual-service-account':
                logger.info(f"[API ANALYSIS] Dual-service-account detected, using scanner credentials")
                service_account_key = credentials_data.get('scanner_credentials')
                if not service_account_key:
                    raise HTTPException(status_code=400, detail="Dual-service-account missing scanner_credentials")
            else:
                # Regular service account key
                service_account_key = credentials_data
            
            logger.info(f"[API ANALYSIS] Successfully retrieved credentials from token")
            gcp_client = GCPClient(project_id=request.project_id, service_account_key=service_account_key)
        else:
            # Try to use default credentials
            logger.warning(f"[API ANALYSIS] No credential_token provided, using default credentials")
            gcp_client = GCPClient(project_id=request.project_id)
        
        # Analyze APIs
        from app.services.api_analysis_service import ApiAnalysisService
        analysis_service = ApiAnalysisService(gcp_client)
        
        result = analysis_service.analyze_apis(request.project_id)
        
        logger.info(f"[API ANALYSIS] Found {result.get('total_apis', 0)} APIs")
        
        from app.models.script_models import AnalyzeLockdownResponse
        return AnalyzeLockdownResponse(**result)
        
    except Exception as e:
        logger.error(f"[API ANALYSIS] Failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"API analysis failed: {str(e)}"
        )



@router.post("/generate-script")
async def generate_lockdown_script(request: LockdownRequest):
    """
    Generate a shell script with gcloud commands for lockdown
    
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
        
        logger.info(f"Generating lockdown script for project: {request.project_id}")
        script_content = ScriptGenerator.generate_lockdown_script(request)
        
        # Generate timestamp for unique filename
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"lockdown_{request.project_id}_{timestamp}.sh"
        
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
        logger.error(f"Failed to generate lockdown script: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate script: {str(e)}"
        )


@router.post("/generate-multi-script")
async def generate_multi_project_lockdown_script(request: MultiProjectLockdownRequest):
    """
    Generate a shell script with gcloud commands for multi-project lockdown
    
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
        
        if not request.project_ids:
            raise HTTPException(
                status_code=400,
                detail="At least one project ID is required."
            )
        
        logger.info(f"Generating multi-project lockdown script for {len(request.project_ids)} projects")
        script_content = ScriptGenerator.generate_multi_project_lockdown_script(request)
        
        # Generate timestamp for unique filename
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        project_count = len(request.project_ids)
        filename = f"lockdown_multi_{project_count}projects_{timestamp}.sh"
        
        # Return as downloadable file
        return Response(
            content=script_content,
            media_type="application/x-sh",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except Exception as e:
        logger.error(f"Failed to generate multi-project lockdown script: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate script: {str(e)}"
        )
        
        # Return as downloadable file
        return Response(
            content=script_content,
            media_type="application/x-sh",
            headers={
                "Content-Disposition": f"attachment; filename=lockdown_{request.project_id}.sh"
            }
        )
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to generate lockdown script: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate script: {str(e)}"
        )


@router.post("/multi", response_model=MultiProjectLockdownResponse)
async def apply_multi_project_lockdown(request: MultiProjectLockdownRequest):
    """
    Apply security lockdown to multiple GCP projects
    
    Security: Uses user-provided service account credentials
    This endpoint performs destructive operations - use with caution!
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"Multi-project lockdown request received for {len(request.project_ids)} projects")
        
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
        
        # Get credentials from token or direct (support both methods)
        credentials = None
        
        if request.credential_token:
            logger.info("Retrieving credentials from secure token for multi-project lockdown")
            credentials = CredentialService.get_credentials(request.credential_token)
            if not credentials:
                logger.error("Failed to retrieve credentials: Invalid or expired token")
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or expired credential token"
                )
            logger.info("Successfully retrieved credentials from token")
            
            # UNWRAP if there's a service_account_key wrapper
            if 'service_account_key' in credentials:
                logger.info("DEBUG lockdown.py: Unwrapping service_account_key wrapper")
                credentials = credentials['service_account_key']
                logger.info(f"DEBUG lockdown.py: After unwrap - keys: {list(credentials.keys())}")
            
            # CHECK IF THIS IS DUAL-SERVICE-ACCOUNT - use ADMIN for lockdown!
            if credentials.get('auth_type') == 'dual-service-account':
                logger.info("=" * 80)
                logger.info("DUAL-SERVICE-ACCOUNT DETECTED - Using ADMIN Credentials for Lockdown")
                logger.info("=" * 80)
                admin_creds = credentials.get('admin_credentials')
                if not admin_creds:
                    raise HTTPException(
                        status_code=400,
                        detail="Dual-service-account missing admin_credentials"
                    )
                logger.info(f"Using ADMIN SA: {admin_creds.get('client_email')}")
                logger.info("Admin credentials have elevated permissions for lockdown operations")
                credentials = admin_creds
                logger.info("=" * 80)
                
        elif request.service_account_credentials:
            logger.warning("Using credentials from request body for multi-project lockdown (deprecated)")
            credentials = request.service_account_credentials
        else:
            raise HTTPException(
                status_code=400,
                detail="Either credential_token or service_account_credentials is required"
            )
        
        project_results: List[LockdownResponse] = []
        errors: List[str] = []
        completed = 0
        failed = 0
        
        # Apply lockdown to each project
        for idx, project_id in enumerate(request.project_ids, 1):
            try:
                logger.info(f"Applying lockdown to project {idx}/{len(request.project_ids)}: {project_id}")
                
                # Create a LockdownRequest for this project
                project_request = LockdownRequest(
                    project_id=project_id,
                    access_token=request.access_token,
                    security_profile=request.security_profile,
                    service_account_credentials=credentials,  # Use retrieved credentials
                    region=request.region,
                    budget_limit=request.budget_limit,
                    alert_emails=request.alert_emails,
                    organization_id=request.organization_id,
                    selected_risk_ids=request.selected_risk_ids
                )
                
                # Apply lockdown using the single-project endpoint logic
                sa_project_id = credentials.get('project_id')
                effective_project_id = sa_project_id or project_id
                
                if not effective_project_id:
                    raise ValueError(f"Project ID is required for project: {project_id}")
                
                # Initialize GCP client for this project
                from google.oauth2 import service_account
                sa_creds = service_account.Credentials.from_service_account_info(
                    credentials
                )
                
                gcp_client = GCPClient(
                    project_id=effective_project_id,
                    service_account_key=credentials
                )
                
                # Update request with effective project_id
                project_request.project_id = effective_project_id
                
                # Initialize lockdown service
                lockdown_service = LockdownService(gcp_client)
                
                # Apply lockdown
                result = lockdown_service.apply_lockdown(project_request)
                
                # Disable Cloud Resource Manager API after lockdown (cleanup)
                try:
                    cloud_resource_manager_api = "cloudresourcemanager.googleapis.com"
                    disable_result = gcp_client.disable_api(cloud_resource_manager_api, project_id=effective_project_id)
                    if disable_result.get("status") in ["disabled", "already_disabled"]:
                        logger.info(f"✓ Cloud Resource Manager API disabled for {effective_project_id}")
                except Exception as disable_error:
                    logger.warning(f"Could not disable Cloud Resource Manager API for {effective_project_id}: {str(disable_error)}")
                
                project_results.append(result)
                completed += 1
                logger.info(f"✓ Completed lockdown for project: {project_id} ({completed}/{len(request.project_ids)})")
                
            except Exception as project_error:
                error_msg = f"Failed to apply lockdown to project {project_id}: {str(project_error)}"
                logger.error(error_msg, exc_info=True)
                errors.append(error_msg)
                failed += 1
                # Continue with next project
                continue
        
        # Determine overall status
        overall_status = "completed"
        if failed > 0:
            overall_status = "completed_with_errors"
        if completed == 0:
            overall_status = "failed"
        
        logger.info(f"Multi-project lockdown completed: {completed} succeeded, {failed} failed")
        
        return MultiProjectLockdownResponse(
            project_results=project_results,
            total_projects=len(request.project_ids),
            completed_projects=completed,
            failed_projects=failed,
            timestamp=datetime.utcnow().isoformat(),
            overall_status=overall_status,
            errors=errors
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Multi-project lockdown failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Multi-project lockdown failed: {str(e)}"
        )


@router.get("/health")
async def lockdown_health():
    """Health check for lockdown service"""
    return {"status": "healthy", "service": "lockdown"}



@router.post("/generate-script-v2")
async def generate_lockdown_script_v2(request: GenerateScriptRequest):
    """
    Generate lockdown script in specified format (Python/Terraform/Pulumi)
    
    This is the new granular API selection endpoint that generates
    scripts based on user-selected APIs to disable.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"[SCRIPT GEN V2] Generating {request.format} script for project: {request.project_id}")
        logger.info(f"[SCRIPT GEN V2] Organization ID received: '{request.organization_id}'")
        logger.info(f"[SCRIPT GEN V2] APIs to disable: {len(request.apis_to_disable)}")
        
        from app.services.script_generator_service import ScriptGeneratorService
        
        # Initialize script generator
        generator = ScriptGeneratorService()
        
        # Generate script in requested format
        result = generator.generate_lockdown_script(
            project_id=request.project_id,
            organization_id=request.organization_id,
            apis_to_disable=request.apis_to_disable,
            apply_network_hardening=request.apply_network_hardening,
            apply_org_policies=request.apply_org_policies,
            region_lockdown=request.region_lockdown,
            budget_limit=request.budget_limit,
            alert_emails=request.alert_emails,
            compute_monitoring=request.compute_monitoring,
            format=request.format
        )
        
        logger.info(f"[SCRIPT GEN V2] Script generated successfully ({len(result.get('script', ''))} chars)")
        
        from app.models.script_models import GenerateScriptResponse
        return GenerateScriptResponse(**result)
        
    except Exception as e:
        logger.error(f"[SCRIPT GEN V2] Failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Script generation failed: {str(e)}"
        )


@router.post("/execute-script", response_model=ExecuteScriptResponse)
async def execute_lockdown_script(request: ExecuteScriptRequest):
    """
    Execute a Python lockdown script on the backend server
    
    This endpoint allows non-technical users to run lockdown scripts
    without needing local Python environment or manual execution.
    
    Security: Uses service account credentials from credential_token
    Execution: Runs in isolated subprocess with timeout
    """
    import tempfile
    import subprocess
    import os
    import json
    import time
    
    logger.info(f"[SCRIPT EXEC] Starting execution for project: {request.project_id}")
    
    try:
        # Get service account credentials
        from app.services.credential_service import CredentialService
        cred_service = CredentialService()
        credentials = cred_service.get_credentials(request.credential_token)
        
        if not credentials:
            logger.error("[SCRIPT EXEC] Invalid or expired credential token")
            raise HTTPException(status_code=401, detail="Invalid or expired credential token")
        
        # Handle dual-service-account format
        if credentials.get('auth_type') == 'dual-service-account':
            # Use admin credentials for lockdown operations
            service_account_key = credentials.get('admin_credentials')
            logger.info("[SCRIPT EXEC] Dual-service-account detected. Using ADMIN credentials.")
            if not service_account_key:
                logger.error("[SCRIPT EXEC] Admin credentials missing in dual account object")
                raise HTTPException(status_code=400, detail="Admin credentials not found")
        else:
            logger.info("[SCRIPT EXEC] Single service account detected. Using provided credentials.")
            service_account_key = credentials
        
        # Log the service account email being used
        client_email = service_account_key.get('client_email', 'unknown')
        logger.info(f"[SCRIPT EXEC] Executing script as: {client_email}")
        
        logger.info("[SCRIPT EXEC] Credentials retrieved successfully")
        
        # Write script to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as script_file:
            script_file.write(request.script)
            script_path = script_file.name
        
        # Write credentials to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as cred_file:
            json.dump(service_account_key, cred_file)
            cred_path = cred_file.name
        
        logger.info(f"[SCRIPT EXEC] Script written to: {script_path}")
        logger.info(f"[SCRIPT EXEC] Credentials written to: {cred_path}")
        
        # Set up environment
        env = os.environ.copy()
        env['GOOGLE_APPLICATION_CREDENTIALS'] = cred_path
        
        # Execute script with timeout
        start_time = time.time()
        
        try:
            process = subprocess.Popen(
                [sys.executable, '-u', script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=tempfile.gettempdir(),  # Run in temp dir so strict relative paths work
                env=env,
                universal_newlines=True,
                encoding='utf-8'
            )
            
            # Capture output with timeout (5 minutes)
            output_lines = []
            try:
                stdout, _ = process.communicate(timeout=300)
                output_lines = stdout.split('\n') if stdout else []
            except subprocess.TimeoutExpired:
                process.kill()
                logger.error("[SCRIPT EXEC] Script execution timed out after 5 minutes")
                raise HTTPException(status_code=504, detail="Script execution timed out")
            
            exit_code = process.returncode
            duration = time.time() - start_time
            
            logger.info(f"[SCRIPT EXEC] Execution complete. Exit code: {exit_code}, Duration: {duration:.2f}s")
            logger.info(f"[SCRIPT EXEC] Captured {len(output_lines)} lines of output")
            if len(output_lines) > 0:
                logger.info(f"[SCRIPT EXEC] First 5 lines: {output_lines[:5]}")
            else:
                logger.warning("[SCRIPT EXEC] NO OUTPUT CAPTURED from stdout/stderr")
            
            # Persist execution log to file
            log_dir = os.path.join(os.getcwd(), "reports")
            os.makedirs(log_dir, exist_ok=True)
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_project_id = request.project_id.replace(":", "_").replace("/", "_") # Sanitize
            log_filename = f"{safe_project_id}_{timestamp_str}.log"
            log_path = os.path.join(log_dir, log_filename)
            
            try:
                with open(log_path, "w", encoding='utf-8') as f:
                    f.write("\n".join(output_lines))
                logger.info(f"[SCRIPT EXEC] Log persisted to: {log_path}")
            except Exception as e:
                logger.error(f"[SCRIPT EXEC] Failed to write persistent log: {e}")
                log_path = None # Don't return if write failed

            # Read report file if it exists
            report_path = os.path.join(tempfile.gettempdir(), "lockdown_report.json")
            report_data = None
            if os.path.exists(report_path):
                try:
                    with open(report_path, 'r') as f:
                        report_data = json.load(f)
                    logger.info("[SCRIPT EXEC] Report file read successfully")
                    # Clean up report file
                    os.unlink(report_path)
                except Exception as e:
                    logger.warning(f"[SCRIPT EXEC] Failed to read report file: {e}")
            else:
                logger.warning("[SCRIPT EXEC] No report file generated")

        finally:
            # Clean up temporary files
            try:
                os.unlink(script_path)
                os.unlink(cred_path)
                logger.info("[SCRIPT EXEC] Temporary files cleaned up")
            except Exception as cleanup_error:
                logger.warning(f"[SCRIPT EXEC] Failed to cleanup temp files: {cleanup_error}")
        
        # Return execution result
        return ExecuteScriptResponse(
            success=exit_code == 0,
            exit_code=exit_code,
            output=[line for line in output_lines if line.strip()],  # Remove empty lines
            report=report_data,
            error=None if exit_code == 0 else f"Script exited with code {exit_code}",
            duration_seconds=round(duration, 2),
            log_file_path=log_path
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[SCRIPT EXEC] Execution failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Script execution failed: {str(e)}"
        )
