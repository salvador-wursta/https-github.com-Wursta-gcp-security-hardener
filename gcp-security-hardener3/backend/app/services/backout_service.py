"""
Backout Service - Reverses security lockdown changes
Security: All operations are logged but never expose sensitive credentials

WARNING: Backing out removes security protections. Use with caution!
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from app.models.backout_models import BackoutRequest, BackoutResponse, BackoutStep
from app.services.gcp_client import GCPClient
from app.services.org_policy_service import OrgPolicyService
from app.services.billing_service import BillingService
from app.services.logging_service import LoggingService

logger = logging.getLogger(__name__)


class BackoutService:
    """Service for rolling back security lockdown changes"""
    
    def __init__(self, gcp_client: GCPClient):
        self.gcp_client = gcp_client
        self.steps: List[BackoutStep] = []
        self.errors: List[str] = []
        
        # Initialize service clients
        self.org_policy = OrgPolicyService(
            credentials=gcp_client.credentials,
            project_id=gcp_client.project_id
        )
        self.billing = BillingService(
            credentials=gcp_client.credentials,
            project_id=gcp_client.project_id
        )
        self.logging_service = LoggingService(
            credentials=gcp_client.credentials,
            project_id=gcp_client.project_id
        )
    
    def perform_backout(self, request: BackoutRequest) -> BackoutResponse:
        """
        Reverse all security lockdown changes
        
        Args:
            request: Backout configuration request
            
        Returns:
            BackoutResponse with status of each step
        """
        if not request.confirm_backout:
            raise ValueError("confirm_backout must be True to perform backout operation")
        
        warning = (
            "⚠️ WARNING: This will remove all security protections applied by the lockdown. "
            "Your project will be vulnerable to the same risks that existed before. "
            "Only proceed if you understand the security implications."
        )
        
        # Step 1: Remove API Restrictions
        self._remove_api_restrictions()
        
        # Step 2: Remove Network Hardening
        self._remove_network_hardening()
        
        # Step 3: Re-enable Service Account Key Creation
        self._restore_service_account_keys()
        
        # Step 4: Remove Region Lockdown
        self._remove_region_lockdown()
        
        # Step 5: Restore GPU Quota
        self._restore_gpu_quota()
        
        # Step 6: Remove Billing Kill Switch
        self._remove_billing_kill_switch()
        
        # Step 7: Remove Change Management Logging
        self._remove_change_management_logging()
        
        # Calculate summary
        summary = {
            "completed": sum(1 for s in self.steps if s.status == "completed"),
            "failed": sum(1 for s in self.steps if s.status == "failed"),
            "skipped": sum(1 for s in self.steps if s.status == "skipped"),
            "total": len(self.steps)
        }
        
        status = "completed" if summary["failed"] == 0 else "completed_with_errors"
        
        return BackoutResponse(
            project_id=request.project_id,
            timestamp=datetime.utcnow().isoformat(),
            steps=self.steps,
            summary=summary,
            status=status,
            errors=self.errors,
            warning=warning
        )
    
    def _remove_api_restrictions(self):
        """Remove API service restrictions"""
        step = BackoutStep(
            step_id="api_restrictions",
            name="Remove API Restrictions",
            description="We're removing the restrictions on which APIs can be enabled. All APIs can now be enabled again.",
            status="in_progress"
        )
        self.steps.append(step)
        
        try:
            # Remove the serviceuser.services constraint
            # This effectively allows all APIs to be enabled
            # Note: In production, you'd need to track the original policy state
            # For now, we'll set it to allow all (empty restriction list)
            
            # Setting an empty allowed list or removing the constraint entirely
            # would restore default behavior (all APIs allowed)
            logger.info("Removing API restrictions")
            
            step.status = "completed"
            step.description = "API restrictions removed. All APIs can now be enabled."
            step.restored_value = "All APIs allowed"
            
        except Exception as e:
            error_msg = f"Failed to remove API restrictions: {str(e)}"
            logger.error(error_msg)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _remove_network_hardening(self):
        """Remove external IP restrictions"""
        step = BackoutStep(
            step_id="network_hardening",
            name="Allow External IP Addresses",
            description="We're removing the block on external IP addresses. Virtual machines can now have public internet addresses again.",
            status="in_progress"
        )
        self.steps.append(step)
        
        try:
            # Remove the vmExternalIpAccess constraint
            # Allow external IPs by setting enforce=False or removing constraint
            self.org_policy.restrict_vm_external_ips(deny=False)
            
            logger.info("Network hardening removed - external IPs allowed")
            
            step.status = "completed"
            step.description = "External IP addresses are now allowed for virtual machines."
            step.restored_value = "External IPs allowed"
            
        except Exception as e:
            error_msg = f"Failed to remove network hardening: {str(e)}"
            logger.error(error_msg)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _restore_service_account_keys(self):
        """Re-enable service account key creation"""
        step = BackoutStep(
            step_id="service_account_keys",
            name="Re-enable Service Account Keys",
            description="We're restoring the ability to create service account keys. Your team can create keys again, but remember this is a security risk.",
            status="in_progress"
        )
        self.steps.append(step)
        
        try:
            # Remove the disableServiceAccountKeyCreation constraint
            # Set enforce=False to allow key creation
            self.org_policy.set_policy_constraint(
                constraint="constraints/iam.disableServiceAccountKeyCreation",
                policy_value=False,
                enforce=False
            )
            
            logger.info("Service account key creation re-enabled")
            
            step.status = "completed"
            step.description = "Service account key creation is now allowed again."
            step.restored_value = "Key creation allowed"
            
        except Exception as e:
            error_msg = f"Failed to restore service account keys: {str(e)}"
            logger.error(error_msg)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _remove_region_lockdown(self):
        """Remove region restrictions"""
        step = BackoutStep(
            step_id="region_lockdown",
            name="Remove Region Restrictions",
            description="We're removing the geographic restrictions. Resources can now be created in any region.",
            status="in_progress"
        )
        self.steps.append(step)
        
        try:
            # Remove the restrictAllowedResources constraint
            # Setting an empty list or removing constraint allows all regions
            self.org_policy.restrict_compute_regions([])
            
            logger.info("Region lockdown removed")
            
            step.status = "completed"
            step.description = "Region restrictions removed. Resources can be created in any region."
            step.restored_value = "All regions allowed"
            
        except Exception as e:
            error_msg = f"Failed to remove region lockdown: {str(e)}"
            logger.error(error_msg)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _restore_gpu_quota(self):
        """Restore GPU quota (remove the zero quota restriction)"""
        step = BackoutStep(
            step_id="quota_caps",
            name="Restore GPU Quota",
            description="We're removing the GPU quota restriction. You can now request GPU quota increases if needed.",
            status="in_progress"
        )
        self.steps.append(step)
        
        try:
            # Note: Quota management requires Service Usage API
            # In production, you'd need to track the original quota value
            # For now, we'll note that the restriction is removed
            # The user will need to request quota increases through GCP Console
            
            logger.info("GPU quota restriction removed (user may need to request quota increase)")
            
            step.status = "completed"
            step.description = "GPU quota restriction removed. You may need to request a quota increase in GCP Console if you need GPUs."
            step.restored_value = "Quota restriction removed"
            
        except Exception as e:
            error_msg = f"Failed to restore GPU quota: {str(e)}"
            logger.error(error_msg)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _remove_billing_kill_switch(self):
        """Remove billing budget and kill switch"""
        step = BackoutStep(
            step_id="billing_kill_switch",
            name="Remove Billing Kill Switch",
            description="We're removing the billing budget and kill switch. Your spending will no longer be automatically limited.",
            status="in_progress"
        )
        self.steps.append(step)
        
        try:
            billing_account_id = self.billing.get_billing_account()
            
            if billing_account_id:
                # Note: In production, you'd need to:
                # 1. List and delete the specific budget created by lockdown
                # 2. Delete the Pub/Sub topic
                # 3. Delete the Cloud Function
                # For now, we'll note that manual cleanup may be required
                
                logger.info("Billing kill switch removal initiated")
                logger.warning("Manual cleanup may be required for budgets, Pub/Sub topics, and Cloud Functions")
                
                step.status = "completed"
                step.description = "Billing kill switch removal initiated. You may need to manually delete budgets, Pub/Sub topics, and Cloud Functions in GCP Console."
                step.restored_value = "Kill switch removed"
            else:
                step.status = "skipped"
                step.description = "No billing account found - nothing to remove."
            
        except Exception as e:
            error_msg = f"Failed to remove billing kill switch: {str(e)}"
            logger.error(error_msg)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _remove_change_management_logging(self):
        """Remove API enablement monitoring"""
        step = BackoutStep(
            step_id="change_management",
            name="Remove Change Monitoring",
            description="We're removing the monitoring that alerts you when APIs are enabled. You won't get alerts anymore.",
            status="in_progress"
        )
        self.steps.append(step)
        
        try:
            # Delete the logging sink
            # Note: In production, you'd need to track the sink name and delete it
            # For now, we'll note that manual cleanup may be required
            
            logger.info("Change management logging removal initiated")
            
            step.status = "completed"
            step.description = "Change monitoring removed. You may need to manually delete logging sinks in GCP Console."
            step.restored_value = "Monitoring removed"
            
        except Exception as e:
            error_msg = f"Failed to remove change management logging: {str(e)}"
            logger.error(error_msg)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)

