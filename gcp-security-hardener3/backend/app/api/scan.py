"""
API endpoints for security scanning
"""
from fastapi import APIRouter, HTTPException, Request
from typing import List
from app.models.scan_models import ScanRequest, ScanResponse, MultiProjectScanRequest, MultiProjectScanResponse
from app.services.gcp_client import GCPClient
from app.services.scan_service import ScanService
from app.services.firebase_auth_service import FirebaseAuthService
from app.services.credential_service import CredentialService
from datetime import datetime
from slowapi import Limiter
from slowapi.util import get_remote_address
import asyncio
from concurrent.futures import ThreadPoolExecutor

router = APIRouter(prefix="/api/v1/scan", tags=["scan"])
limiter = Limiter(key_func=get_remote_address)


@router.post("/", response_model=ScanResponse)
@limiter.limit("100/minute")
async def perform_scan(request: Request, body: ScanRequest):
    """
    Perform a comprehensive security scan of a GCP project
    
    Security: Access tokens are never logged or exposed in responses
    Rate limit: 10 requests per minute per IP
    
    Accepts either:
    - Firebase ID token (will be exchanged for GCP token)
    - Direct GCP OAuth access token
    """
    import logging
    logger = logging.getLogger(__name__)

    # Use 'body' for the Pydantic model
    scan_request = body
    
    try:
        logger.info(f"SaaS Scan request received for project: {scan_request.project_id}")
        
        # Determine target project ID
        effective_project_id = scan_request.project_id
        
        if not effective_project_id:
            raise HTTPException(
                status_code=400, 
                detail="Project ID is required. Please select a project to scan."
            )
            
        logger.info(f"Targeting Project ID via Identity: {effective_project_id}")
        
        try:
            # Look up active session identity (passed by frontend, fallback to global)
            impersonate_email = scan_request.impersonate_email
            if not impersonate_email:
                from app.main import _active_session
                impersonate_email = _active_session.get("sa_email")

            # Initialize GCP client with ADC + Impersonation
            gcp_client = GCPClient(project_id=effective_project_id, impersonate_email=impersonate_email)
            logger.info(f"GCP client initialized via ADC for target: {effective_project_id} (impersonating: {impersonate_email})")
        except Exception as cred_error:
            logger.error(f"SaaS Auth failure (ADC missing or insufficient permissions): {str(cred_error)}")
            raise HTTPException(
                status_code=403,
                detail=f"SaaS Authorization Failed: Ensure the app service account has permissions on {effective_project_id}."
            )
        
        logger.info("Initializing scan service...")
        # Initialize scan service
        scan_service = ScanService(gcp_client)
        
        logger.info(f"Starting security scan for project: {effective_project_id}...")
        # Perform the scan
        scan_result = scan_service.perform_scan(
            organization_id=scan_request.organization_id,
            scan_modules=scan_request.scan_modules
        )
        
        # Ensure the scan result uses the correct project_id
        scan_result.project_id = effective_project_id
        
        # Inject scanner identity so the frontend always knows which SA ran the scan
        if hasattr(scan_result, 'organization_name') and not scan_result.organization_name:
            pass  # Keep as-is
        # Store scanner email in the result for the frontend to display
        try:
            scan_result.scanner_email = impersonate_email
        except Exception:
            pass  # Field may not exist on model - that's ok
        
        logger.info(f"Scan completed. Found {len(scan_result.risks)} risks.")
        logger.info(f"Scan summary: {scan_result.summary}")

        
        # --- PERSIST SCAN RESULTS ---
        try:
            from app.services.db_service import db_service
            # We need a client ID to save associated scans.
            # For now, we'll try to find a client by the project_id or create a temporary one.
            # In a real app, client_id should be passed in the request or derived from auth.
            
            # Using project_id as a proxy for client lookup for now
            # (or we could default to a 'default' client if none matches)
            client = db_service.upsert_client({
                "company_name": effective_project_id, # Placeholder name
                "id": effective_project_id # Force ID to be project ID for simplicity in this flow
            })
            
            db_service.save_scan(
                client_id=client['id'],
                scan_data={"project_id": effective_project_id, "summary": scan_result.summary},
                results=scan_result.dict()
            )
            logger.info(f"Scan results saved to database for client: {client['company_name']}")
        except Exception as db_err:
            logger.warning(f"Failed to save scan results to DB: {db_err}")
        # ----------------------------
        
        return scan_result
        
    except ValueError as e:
        # Invalid credentials
        logger.error(f"Authentication failed: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail=f"Authentication failed: {str(e)}"
        )
    except Exception as e:
        # Generic error
        logger.error(f"Scan failed with error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(e)}"
        )


@router.post("/multi", response_model=MultiProjectScanResponse)
async def perform_multi_project_scan(request: MultiProjectScanRequest):
    """
    Perform security scan on multiple GCP projects
    
    Scans all provided projects and returns aggregated results.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"SaaS Multi-project scan request received for {len(request.project_ids)} projects")
        
        # In the new SaaS "Zero Keys" model, we rely entirely on the Cloud Run identity
        # having permissions on the target projects. 
        # No jit_token, credential_token, or keys are required.
        
        scan_results: List[ScanResponse] = []
        errors: List[str] = []
        
        logger.info(f"Will scan {len(request.project_ids)} projects via Identity: {', '.join(request.project_ids)}")
        
        # Limit to 5 concurrent scans to avoid hitting GCP API rate limits
        MAX_CONCURRENT_SCANS = 5
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        
        # Helper function to run in thread pool
        def scan_single_project(project_id: str):
            try:
                # Look up active session identity (passed by frontend, fallback to global)
                impersonate_email = request.impersonate_email
                if not impersonate_email:
                    from app.main import _active_session
                    impersonate_email = _active_session.get("sa_email")

                # Create GCP client for this specific project using ADC + Impersonation
                gcp_client = GCPClient(project_id=project_id, impersonate_email=impersonate_email)
                
                # Initialize scan service
                scan_service = ScanService(gcp_client)
                
                # Perform the scan
                result = scan_service.perform_scan(
                    organization_id=request.organization_id,
                    scan_modules=request.scan_modules
                )
                
                # Ensure project_id is set correctly
                result.project_id = project_id
                
                # Inject scanner identity so the frontend always knows which SA ran the scan.
                # Priority:
                #   1. Impersonation email passed directly (from _active_session via GCPClient)
                #   2. _active_session['sa_email'] stored by /api/session/activate
                #   3. SA attributes from google.auth creds (service key / workload identity)
                #   4. tokeninfo API — LAST RESORT, may return personal ADC user email
                try:
                    from app.main import _active_session  # shared mutable dict in main.py
                    session_sa = _active_session.get("sa_email")
                except Exception:
                    session_sa = None

                if impersonate_email:
                    result.scanner_email = impersonate_email
                elif session_sa and session_sa.endswith(".iam.gserviceaccount.com"):
                    # Session has the scanner SA — prioritize this over ADC resolution
                    result.scanner_email = session_sa
                else:
                    # Last resort: resolve from google.auth default credentials
                    try:
                        import google.auth
                        import google.auth.transport.requests
                        creds, _ = google.auth.default()
                        real_email = (
                            getattr(creds, "service_account_email", None)
                            or getattr(creds, "signer_email", None)
                            or getattr(creds, "_service_account_email", None)
                        )
                        # Only use tokeninfo if we have a proper SA email
                        # to avoid returning personal ADC user email
                        if real_email and real_email.endswith(".iam.gserviceaccount.com"):
                            result.scanner_email = real_email
                        else:
                            result.scanner_email = session_sa or "Service Account Not Configured"
                    except Exception:
                        result.scanner_email = session_sa or "Service Account Not Configured"


                
                return result, None
                
            except Exception as e:
                error_msg = f"Failed to scan project {project_id}: {str(e)}"
                logger.error(error_msg, exc_info=True)
                return None, error_msg

        # Async wrapper with semaphore
        async def scan_with_semaphore(project_id: str, idx: int, total: int):
            async with semaphore:
                logger.info(f"Scanning project {idx}/{total}: {project_id} (Parallel)")
                # Run blocking scan code in a separate thread
                return await asyncio.to_thread(scan_single_project, project_id)

        # Launch all scans
        tasks = [
            scan_with_semaphore(pid, i+1, len(request.project_ids)) 
            for i, pid in enumerate(request.project_ids)
        ]
        
        logger.info(f"Starting {len(tasks)} parallel scan tasks...")
        results = await asyncio.gather(*tasks)
        
        # Process results
        for res, err in results:
            if res:
                scan_results.append(res)
            if err:
                errors.append(err)
        
        completed = len(scan_results)
        failed = len(errors)
        
        # Determine overall status
        overall_status = "completed"
        if failed > 0:
            overall_status = "completed_with_errors"
        if completed == 0:
            overall_status = "failed"
        
        logger.info(f"Multi-project scan completed: {completed} succeeded, {failed} failed")
        
        return MultiProjectScanResponse(
            scans=scan_results,
            total_projects=len(request.project_ids),
            completed_projects=completed,
            failed_projects=failed,
            scan_timestamp=datetime.utcnow().isoformat(),
            overall_status=overall_status,
            errors=errors
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Multi-project scan failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Multi-project scan failed: {str(e)}"
        )


@router.get("/health")
async def scan_health():
    """Health check for scan service"""
    return {"status": "healthy", "service": "scan"}

