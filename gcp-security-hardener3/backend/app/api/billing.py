from fastapi import APIRouter, HTTPException, Depends
from app.models.billing_models import UpdateBudgetRequest, UpdateBudgetResponse
from app.services.billing_service import BillingService
from app.services.gcp_client import GCPClient
from app.services.jit_session_service import JITSessionService
from app.services.credential_service import CredentialService
import logging

router = APIRouter(prefix="/api/v1/billing", tags=["billing"])
logger = logging.getLogger(__name__)

@router.post("/budget", response_model=UpdateBudgetResponse)
async def update_budget(request: UpdateBudgetRequest):
    """
    Create or update a billing budget for a project.
    """
    # ... existing code ...
    logger.info(f"Budget update request for project: {request.project_id}")
    
    # 1. Authentication & Credentials Retrieval
    credentials = None
    
    if request.jit_token:
        # Phase 2 JIT Auth
        logger.info("Retrieving credentials from JIT Session Token")
        session_service = JITSessionService()
        creds_tuple = session_service.get_credentials(request.jit_token)
        
        if not creds_tuple:
             raise HTTPException(status_code=401, detail="JIT Session expired or invalid.")
        
        # Use credentials. For budget update, we might need writer/admin permissions?
        # The JIT service returns (scanner, admin).
        # Billing budget creation usually requires 'billing.budgets.create' which scanner might not have.
        # However, checking 'billing_service.py', it uses the credentials passed to init.
        # Let's try with Scanner first, but logically this is a 'Fix' operation, so Admin might be safer?
        # But 'Lockdown' uses Admin if available.
        # Let's use Admin credentials if available (tuple[1]), else Scanner (tuple[0]).
        
        if creds_tuple[1]:
            credentials = creds_tuple[1]
            logger.info("Using ADMIN credentials for budget update")
        else:
            credentials = creds_tuple[0]
            logger.info("Using SCANNER credentials for budget update")
            
    elif request.credential_token:
         # Legacy
         credentials = CredentialService.get_credentials(request.credential_token)
         if not credentials:
             raise HTTPException(status_code=401, detail="Invalid credential token")
             
         if 'service_account_key' in credentials:
             credentials = credentials['service_account_key']
             
         if credentials.get('auth_type') == 'dual-service-account':
             # Use Admin if available
             if credentials.get('admin_credentials'):
                 credentials = credentials.get('admin_credentials')
             else:
                 credentials = credentials.get('scanner_credentials')
    else:
        raise HTTPException(status_code=400, detail="Authentication token required (jit_token or credential_token)")

    if not credentials:
        raise HTTPException(status_code=400, detail="Failed to resolve credentials")

    # 2. Perform Operation
    try:
        # Initialize GCP Client (needed for project info)
        gcp_client = GCPClient(project_id=request.project_id, service_account_key=credentials)
        
        # Initialize Billing Service
        billing_service = BillingService(
            credentials=credentials, 
            project_id=request.project_id,
            gcp_client=gcp_client
        )
        
        # Create/Update Budget
        result = billing_service.create_budget(
            budget_amount=request.amount,
            alert_emails=request.alert_emails or []
        )
        
        return UpdateBudgetResponse(
            success=True,
            budget_id=result.get('budget_id', 'unknown'),
            message="Budget updated successfully.",
            amount=request.amount
        )
        
    except Exception as e:
        logger.error(f"Failed to update budget: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to update budget: {str(e)}")

from fastapi import UploadFile, File
from app.services.billing_csv_parser import BillingCsvParser
from app.services.billing_history_service import BillingHistoryService

@router.post("/upload-csv")
async def upload_billing_csv(file: UploadFile = File(...)):
    """
    Upload a GCP Billing Cost Table CSV to populate local history.
    """
    try:
        content = await file.read()
        csv_text = content.decode('utf-8')
        
        history_service = BillingHistoryService()
        parser = BillingCsvParser(history_service)
        
        result = parser.parse_and_store(csv_text)
        
        if result["status"] == "error":
            raise HTTPException(status_code=400, detail=result["message"])
            
        return result
        
    except Exception as e:
        logger.error(f"CSV upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
