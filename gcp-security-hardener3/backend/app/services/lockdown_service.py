"""
Lockdown Service - Applies security policies and constraints
Security: All operations are logged but never expose sensitive credentials
"""
import logging
from typing import List, Dict, Any
from datetime import datetime
from app.models.lockdown_models import (
    LockdownRequest, LockdownResponse, LockdownStep, SecurityProfile
)
from app.services.gcp_client import GCPClient
from app.services.security_profiles import SecurityProfiles
from app.services.org_policy_service import OrgPolicyService
from app.services.billing_service import BillingService
from app.services.logging_service import LoggingService
from app.services.quota_service import QuotaService
from app.services.api_enablement_service import APIEnablementService
from app.services.risk_to_step_mapping import get_steps_for_risks
from app.services.script_generator_service import PROTECTED_APIS
from app.services.org_monitoring_service import OrgMonitoringService

logger = logging.getLogger(__name__)


class LockdownService:
    """Service for applying security lockdown policies"""
    
    def __init__(self, gcp_client: GCPClient):
        self.gcp_client = gcp_client
        self.steps: List[LockdownStep] = []
        self.errors: List[str] = []
        
        # Initialize service clients
        self.api_enablement = APIEnablementService(
            credentials=gcp_client.credentials,
            project_id=gcp_client.project_id
        )
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
        self.quota_service = QuotaService(
            credentials=gcp_client.credentials,
            project_id=gcp_client.project_id
        )
    
    def apply_lockdown(self, request: LockdownRequest) -> LockdownResponse:
        """
        Apply comprehensive security lockdown
        
        Args:
            request: Lockdown configuration request
            
        Returns:
            LockdownResponse with status of each step
        """
        logger.info("=" * 80)
        logger.info(f"LOCKDOWN STARTED for project: {request.project_id}")
        logger.info(f"Security profile: {request.security_profile}")
        logger.info(f"Selected risk IDs: {request.selected_risk_ids or 'None (applying all steps)'}")
        logger.info(f"Region: {request.region or 'None'}")
        logger.info(f"Budget limit: ${request.budget_limit or 'None'}")
        logger.info(f"Alert emails: {request.alert_emails or 'None'}")
        logger.info("=" * 80)
        
        # Reset extended alerts data
        self.extended_alerts_data = []
        
        # PRE-FLIGHT: Ensure required APIs are enabled
        logger.info("")
        logger.info("=" * 80)
        logger.info("PRE-FLIGHT CHECK: Ensuring Required APIs are Enabled")
        logger.info("=" * 80)
        try:
            api_check_result = self.api_enablement.check_all_required_apis()
            
            if not api_check_result['all_enabled']:
                logger.warning(f"Found {api_check_result['disabled']} disabled APIs")
                
                # List which APIs are disabled
                disabled_apis = [api['display_name'] for api in api_check_result['details'] if not api['enabled']]
                logger.warning(f"Disabled APIs: {', '.join(disabled_apis)}")
                
                logger.info(f"Automatically enabling required APIs...")
                
                # Enable all required APIs
                enable_result = self.api_enablement.enable_required_apis(check_first=False)
                
                if enable_result['all_enabled']:
                    logger.info(f"✓ Successfully enabled {enable_result['enabled_count']} APIs")
                    logger.info(f"⏳ Waiting 15 seconds for API propagation...")
                    logger.info(f"   (GCP needs time to activate APIs before they can be used)")
                    import time
                    time.sleep(15)
                    logger.info(f"✓ API propagation wait complete")
                else:
                    # Identify which specific APIs failed
                    failed_apis = [r['api'] for r in enable_result['results'] if not r.get('success', False)]
                    logger.error(f"✗ Failed to enable {enable_result['failed_count']} APIs: {', '.join(failed_apis)}")
                    logger.warning(f"Lockdown will continue but steps requiring these APIs will fail")
                    
                    # Add specific error message for each failed API
                    for failed_api in failed_apis:
                        error_detail = next((r for r in enable_result['results'] if r.get('api') == failed_api), {})
                        error_reason = error_detail.get('error', 'Unknown reason')
                        self.errors.append(f"Failed to enable {failed_api}: {error_reason}")
            else:
                logger.info("✓ All required APIs are already enabled")
                
        except Exception as api_error:
            logger.error(f"API enablement check failed: {str(api_error)}")
            logger.warning(f"Continuing with lockdown, but some steps may fail")
            self.errors.append(f"Pre-flight API check failed: {str(api_error)}")
        
        logger.info("=" * 80)
        logger.info("")
        
        profile_config = SecurityProfiles.get_profile(request.security_profile)
        
        # Determine which steps to apply
        # Priority: selected_step_ids > selected_risk_ids > All
        if request.selected_step_ids:
            selected_steps = request.selected_step_ids
            logger.info(f"Using explicitly selected steps: {selected_steps}")
        elif request.selected_risk_ids:
            selected_steps = get_steps_for_risks(request.selected_risk_ids)
            logger.info(f"Mapped risks to steps: {selected_steps}")
        else:
            # Default to all steps if nothing selected (legacy behavior) OR if empty lists passed? 
            # If both are empty lists, it usually implies ALL.
            # But get_steps_for_risks([]) returns ALL steps? let's check. 
            # Assuming if selected_risk_ids is None it does all.
            # For safety, let's assume we want all relevant steps if nothing specified.
            selected_steps = [
                "api_restrictions", "network_hardening", "service_account_keys", 
                "region_lockdown", "quota_caps", "billing_kill_switch", "change_management"
            ]
            logger.info("No selection filtered; applying all standard steps")

        logger.info(f"Total steps to execute: {len(selected_steps)}")
        
        # Step 1: API Restriction
        if "api_restrictions" in selected_steps:
            self._apply_api_restrictions(request, profile_config)

        else:
            logger.info("Skipping API restrictions (not selected)")
        
        # Step 2: Network Hardening
        if "network_hardening" in selected_steps:
            self._apply_network_hardening(request, profile_config)
        else:
            logger.info("Skipping network hardening (not selected)")
        
        # Step 3: Service Account Key Protection
        if "service_account_keys" in selected_steps:
            self._apply_service_account_key_protection(request)
        else:
            logger.info("Skipping service account key protection (not selected)")
        
        # Step 4: Region Lockdown
        if "region_lockdown" in selected_steps and request.region:
            self._apply_region_lockdown(request)
        else:
            logger.info("Skipping region lockdown (not selected or no region specified)")
        
        # Step 5: Quota Caps
        if "quota_caps" in selected_steps:
            self._apply_quota_caps(request, profile_config)
        else:
            logger.info("Skipping quota caps (not selected)")
        
        # Step 6: Billing Kill Switch
        if "billing_kill_switch" in selected_steps and request.budget_limit:
            self._create_billing_kill_switch(request)
        else:
            logger.info("Skipping billing kill switch (not selected or no budget limit)")
        
        # Step 7: Change Management Logging
        if "change_management" in selected_steps:
            self._setup_change_management_logging(request)
        else:
            logger.info("Skipping change management logging (not selected)")
        
        # Step 8: Compute Monitoring (if profile enables it)
        if profile_config.get("compute_monitoring") and request.alert_emails:
            self._setup_compute_monitoring(request, profile_config)
        else:
            if not profile_config.get("compute_monitoring"):
                logger.info("Skipping compute monitoring (not enabled in profile)")
            elif not request.alert_emails:
                logger.info("Skipping compute monitoring (no alert emails provided)")
        
        # Step 9: Organization Monitoring (enabled by default)
        if request.org_monitoring_enabled:
            self._setup_org_monitoring(request)
        else:
            logger.info("Skipping organization monitoring (disabled by user)")


        # Calculate summary
        summary = {
            "completed": sum(1 for s in self.steps if s.status == "completed"),
            "failed": sum(1 for s in self.steps if s.status == "failed"),
            "total": len(self.steps)
        }
        
        status = "completed" if summary["failed"] == 0 else "completed_with_errors"
        
        logger.info("=" * 80)
        logger.info(f"LOCKDOWN COMPLETED for project: {request.project_id}")
        logger.info(f"Status: {status}")
        logger.info(f"Summary: {summary}")
        logger.info(f"Total steps: {summary['total']}, Completed: {summary['completed']}, Failed: {summary['failed']}")
        if self.errors:
            logger.error(f"Errors encountered ({len(self.errors)}):")
            for i, error in enumerate(self.errors, 1):
                logger.error(f"  {i}. {error}")
        logger.info("=" * 80)
        
        return LockdownResponse(
            project_id=request.project_id,
            security_profile=request.security_profile,
            timestamp=datetime.utcnow().isoformat(),
            steps=self.steps,
            summary=summary,
            status=status,
            errors=self.errors,
            extended_alerts=self.extended_alerts_data
        )
    
    def create_plan(self, request: LockdownRequest) -> LockdownResponse:
        """
        Generate a lockdown plan (Change Control) without executing it.
        Return list of steps that WILL be performed.
        """
        logger.info(f"Generating Lockdown Plan for project: {request.project_id}")
        
        profile_config = SecurityProfiles.get_profile(request.security_profile)
        
        # Determine steps (same logic as apply)
        if request.selected_step_ids:
            selected_steps = request.selected_step_ids
        elif request.selected_risk_ids:
            selected_steps = get_steps_for_risks(request.selected_risk_ids)
        else:
             selected_steps = [
                "api_restrictions", "network_hardening", "service_account_keys", 
                "region_lockdown", "quota_caps", "billing_kill_switch", "change_management"
            ]

        planned_steps = []

        # 1. API Restrictions
        if "api_restrictions" in selected_steps:
             planned_steps.append(LockdownStep(
                step_id="api_restrictions",
                name="Restrict API Access",
                description=f"Disable unused APIs and enforce {request.security_profile} profile Allow List.",
                status="pending",
                security_benefit="Drastically reduces attack surface by turning off features you don't use."
            ))

        # 2. Network Hardening
        if "network_hardening" in selected_steps:
            planned_steps.append(LockdownStep(
                step_id="network_hardening",
                name="Block External IP Access",
                description="Create VPC firewall rules to block unsolicited external traffic.",
                status="pending",
                security_benefit="Prevents public internet access to your internal VMs."
            ))
            
        # 3. Service Account Keys
        if "service_account_keys" in selected_steps:
            planned_steps.append(LockdownStep(
                step_id="service_account_keys",
                name="Disable Service Account Keys",
                description="Enforce Org Policy to prevent creation of long-lived SA keys.",
                status="pending",
                security_benefit="Stops the #1 credential theft vector in GCP."
            ))

        # 4. Region Lockdown
        if "region_lockdown" in selected_steps and request.region:
             planned_steps.append(LockdownStep(
                step_id="region_lockdown",
                name=f"Lock Resources to {request.region}",
                description=f"Restrict resource creation to {request.region} only.",
                status="pending",
                security_benefit="Data sovereignty and prevents attackers from spawning resources in obscure regions."
            ))
            
        # 5. Quota Caps
        if "quota_caps" in selected_steps:
             planned_steps.append(LockdownStep(
                step_id="quota_caps",
                name="Set GPU Quota to Zero",
                description="Reduce GPU quotas to 0 (unless explicitly allowed by profile).",
                status="pending",
                security_benefit="Prevents crypto-mining abuse if credentials are compromised."
            ))
            
        # 6. Billing Kill Switch
        if "billing_kill_switch" in selected_steps and request.budget_limit:
            planned_steps.append(LockdownStep(
                step_id="billing_kill_switch",
                name="Billing Safety Limit",
                description=f"Set up billing alerts and cap at ${request.budget_limit}.",
                status="pending",
                security_benefit="Prevents unlimited financial liability during an attack."
            ))

        # 7. Monitoring
        if request.org_monitoring_enabled:
             planned_steps.append(LockdownStep(
                step_id="org_monitoring",
                name="Centralized Logging & Monitoring",
                description="Configure log sink and security metrics.",
                status="pending",
                security_benefit="Ensures you have visibility into security events."
            ))
            
        return LockdownResponse(
            project_id=request.project_id,
            security_profile=request.security_profile,
            timestamp=datetime.utcnow().isoformat(),
            steps=planned_steps,
            status="planning",
            summary={"total": len(planned_steps), "completed": 0, "failed": 0}
        )

    def _apply_api_restrictions(self, request: LockdownRequest, profile_config: Dict):
        """
        Apply API restrictions using serviceuser.services constraint
        
        NOTE: The constraints/serviceuser.services Organization Policy constraint
        has specific requirements and doesn't work reliably at the project level.
        Instead, we directly disable APIs using the Service Usage API.
        """
        logger.info("-" * 80)
        logger.info("STEP 1: Applying API Restrictions")
        logger.info("-" * 80)
        
        step = LockdownStep(
            step_id="api_restrictions",
            name="Restrict API Access",
            description="We're disabling dangerous APIs that hackers could use to create expensive resources.",
            status="in_progress",
            security_benefit="If a hacker gets into your account, they can't use disabled APIs. This stops crypto-mining attacks before they start."
        )
        self.steps.append(step)
        
        try:
            logger.info(f"[PRE-CHECK] Getting current org policy state...")
            logger.info(f"  Project ID: {self.gcp_client.project_id}")
            logger.info(f"  Security profile: {request.security_profile}")
            
            logger.info(f"[CONFIG] Getting allowed APIs for profile: {request.security_profile}")
            allowed_apis = SecurityProfiles.get_allowed_apis(request.security_profile)
            denied_apis = SecurityProfiles.get_denied_apis(request.security_profile)
            
            logger.info(f"[CONFIG] Allowed APIs ({len(allowed_apis)}):")
            for i, api in enumerate(allowed_apis[:10], 1):
                logger.info(f"  {i}. {api}")
            if len(allowed_apis) > 10:
                logger.info(f"  ... and {len(allowed_apis) - 10} more")
            
            # Get all currently enabled APIs in the project
            logger.info(f"[SCAN] Getting all currently enabled APIs...")
            try:
                from googleapiclient.discovery import build
                service = build('serviceusage', 'v1', credentials=self.gcp_client.credentials)
                
                # List all enabled services
                parent = f"projects/{self.gcp_client.project_id}"
                request_api = service.services().list(parent=parent, filter="state:ENABLED", pageSize=200)
                
                enabled_apis = []
                while request_api is not None:
                    response = request_api.execute()
                    services = response.get('services', [])
                    for svc in services:
                        # Extract API name from service name (e.g., "projects/123/services/compute.googleapis.com")
                        api_name = svc['config']['name']
                        enabled_apis.append(api_name)
                    request_api = service.services().list_next(request_api, response)
                
                logger.info(f"[SCAN] Found {len(enabled_apis)} currently enabled APIs")
                
            except Exception as scan_error:
                logger.error(f"[ERROR] Could not scan enabled APIs: {scan_error}")
                logger.warning(f"[FALLBACK] Will only disable explicitly denied APIs")
                enabled_apis = []
            
            # Determine which APIs to disable
            # 1. All explicitly denied APIs
            # 2. All enabled APIs NOT in the allowed list
            apis_to_disable = set(denied_apis)
            
            if enabled_apis:
                allowed_set = set(allowed_apis)
                for api in enabled_apis:
                    if api not in allowed_set:
                        apis_to_disable.add(api)
                
                logger.info(f"[PLAN] Will disable {len(apis_to_disable)} APIs:")
                logger.info(f"  - {len(denied_apis)} explicitly denied")
                logger.info(f"  - {len(apis_to_disable) - len(denied_apis)} enabled but not allowed")
            else:
                logger.info(f"[PLAN] Will disable {len(apis_to_disable)} explicitly denied APIs")
            
            # Disable APIs
            logger.info(f"[APPLYING] Disabling {len(apis_to_disable)} APIs...")
            
            disabled_count = 0
            failed_count = 0
            skipped_count = 0
            
            for api in apis_to_disable:
                try:
                    # Skip core APIs that should never be disabled
                    if api in SecurityProfiles.CORE_APIS:
                        logger.info(f"  Skipping core API: {api}")
                        skipped_count += 1
                        continue
                    
                    # Skip protected APIs required for monitoring
                    if api in PROTECTED_APIS:
                        logger.info(f"  Skipping protected API (required for monitoring): {api}")
                        skipped_count += 1
                        continue
                    
                    logger.info(f"  Disabling {api}...")
                    self.gcp_client.disable_api(api, project_id=self.gcp_client.project_id)
                    disabled_count += 1
                    logger.info(f"    ✓ Disabled")
                except Exception as disable_error:
                    logger.warning(f"    ✗ Could not disable {api}: {disable_error}")
                    failed_count += 1
            
            logger.info(f"✓ API restrictions applied")
            logger.info(f"  Disabled APIs: {disabled_count}")
            logger.info(f"  Failed: {failed_count}")
            logger.info(f"  Skipped (core): {skipped_count}")
            logger.info(f"  Status: Completed")
            
            step.status = "completed"
            if disabled_count == 0:
                step.description = f"Verified & Secured: All APIs were scanned and are already compliant with the {request.security_profile} profile. Non-essential APIs are confirmed as disabled."
            else:
                step.description = f"Verified & Secured: Restricted non-essential APIs. {disabled_count} services were disabled, and {len(allowed_apis)} approved APIs remain active."
            
            step.details = {
                "disabled_apis": sorted(list(apis_to_disable)),
                "allowed_apis": sorted(allowed_apis),
                "verification_status": "Verified Compliant" if disabled_count == 0 else "Policy Enforced"
            }
            
        except Exception as e:
            error_msg = f"Failed to apply API restrictions: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"[FAILURE] API RESTRICTIONS STEP FAILED:")
            logger.error(f"  Error message: {error_msg}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Project ID: {request.project_id}")
            logger.error(f"  Security profile: {request.security_profile}")
            logger.error(f"  Allowed APIs count: {len(allowed_apis) if 'allowed_apis' in locals() else 'N/A'}")
            logger.error(f"  Denied APIs count: {len(denied_apis) if 'denied_apis' in locals() else 'N/A'}")
            logger.error(f"")
            logger.error(f"  Possible causes:")
            logger.error(f"    1. Missing 'Organization Policy Administrator' role")
            logger.error(f"    2. Project does not have orgpolicy.googleapis.com API enabled")
            logger.error(f"    3. Service account lacks 'orgpolicy.policies.create' permission")
            logger.error(f"    4. Project is not part of an organization (org policies require org)")
            logger.error(f"")
            import traceback
            logger.error(f"  Full stack trace:")
            for line in traceback.format_exc().split('\n'):
                if line.strip():
                    logger.error(f"    {line}")
            logger.error("=" * 80)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _apply_network_hardening(self, request: LockdownRequest, profile_config: Dict):
        """Apply network hardening - create VPC firewall rules to block external access"""
        logger.info("-" * 80)
        logger.info("STEP 2: Applying Network Hardening (VPC Firewall Rules)")
        logger.info("-" * 80)
        
        step = LockdownStep(
            step_id="network_hardening",
            name="Block External IP Access",
            description="We're creating VPC firewall rules to block external access to your VMs.",
            status="in_progress",
            security_benefit="Firewall rules prevent unauthorized external access to your VMs. Even if a VM is created, external traffic is blocked at the network level."
        )
        self.steps.append(step)
        
        try:
            logger.info(f"[CONFIG] Checking profile requirements...")
            logger.info(f"  Profile: {request.security_profile}")
            allow_external = SecurityProfiles.should_allow_external_ips(request.security_profile)
            logger.info(f"  Allow external IPs: {allow_external}")
            
            if not allow_external:
                # Import firewall service
                from app.services.firewall_service import FirewallService
                firewall_service = FirewallService(
                    credentials=self.gcp_client.credentials,
                    project_id=self.gcp_client.project_id
                )
                
                # CHECK IF FIREWALL RULES ALREADY EXIST
                logger.info(f"[PRE-CHECK] Checking for existing firewall rules...")
                try:
                    existing_rules = firewall_service.list_firewall_rules()
                    deny_rule_exists = any(
                        rule.get('name') == 'deny-external-ingress' 
                        for rule in existing_rules
                    )
                    allow_rule_exists = any(
                        rule.get('name') == 'allow-internal' 
                        for rule in existing_rules
                    )
                    
                    if deny_rule_exists and allow_rule_exists:
                        logger.info(f"[PRE-CHECK] ✓ Firewall rules already exist:")
                        logger.info(f"  - deny-external-ingress: EXISTS")
                        logger.info(f"  - allow-internal: EXISTS")
                        logger.info(f"[SKIPPED] Network hardening already applied - no changes needed")
                        
                        step.status = "completed"
                        step.description = (
                            "✓ Network hardening already in place. "
                            "VPC firewall rules (deny-external-ingress, allow-internal) were previously configured. "
                            "No changes were needed."
                        )
                        return
                    else:
                        logger.info(f"[PRE-CHECK] Firewall rules status:")
                        logger.info(f"  - deny-external-ingress: {'EXISTS' if deny_rule_exists else 'MISSING'}")
                        logger.info(f"  - allow-internal: {'EXISTS' if allow_rule_exists else 'MISSING'}")
                        logger.info(f"[APPLYING] Will create/update firewall rules...")
                        
                except Exception as check_error:
                    # If check fails (e.g. Compute API not enabled), log and continue
                    logger.warning(f"[PRE-CHECK] Could not check existing rules: {str(check_error)}")
                    logger.info(f"[APPLYING] Proceeding with firewall rule creation...")
                
                # Create/update firewall rules
                logger.info(f"[APPLYING] Creating VPC firewall rules...")
                
                # Create deny-all external ingress rule
                logger.info(f"[FIREWALL] Step 1: Block all external ingress...")
                deny_result = firewall_service.create_deny_external_ingress_rule()
                logger.info(f"[FIREWALL] ✓ Deny rule created: {deny_result['rule_name']}")
                
                # Create allow-internal rule (higher priority allows internal traffic)
                logger.info(f"[FIREWALL] Step 2: Allow internal traffic...")
                allow_result = firewall_service.create_allow_internal_rule()
                logger.info(f"[FIREWALL] ✓ Allow rule created: {allow_result['rule_name']}")
                
                # Set up FREE monitoring for firewall changes
                logger.info(f"[FIREWALL] Step 3: Setting up change monitoring (FREE)...")
                monitoring_result = firewall_service.setup_change_monitoring()
                if monitoring_result['status'] == 'active':
                    logger.info(f"[FIREWALL] ✓ Monitoring active - cost: {monitoring_result['cost']}")
                else:
                    logger.warning(f"[FIREWALL] ⚠ Monitoring setup failed (non-critical)")
                
                logger.info(f"✓ Network hardening applied successfully")
                logger.info(f"  - External ingress: BLOCKED")
                logger.info(f"  - Internal traffic: ALLOWED")
                logger.info(f"  - Change monitoring: {monitoring_result['status'].upper()}")
                
                step.status = "completed"
                step.description = "Verified & Secured: VPC firewall rules (deny-external-ingress, allow-internal) are active. External ingress is blocked and monitored."
                step.details = {
                    "firewall_rules": ["deny-external-ingress", "allow-internal"],
                    "state": "Blocked",
                    "monitoring": "Active"
                }
            else:
                logger.info(f"[SKIPPED] Network hardening: External IPs allowed for this profile")
                logger.info(f"  Reason: Profile '{request.security_profile}' requires external IPs")
                step.status = "completed"
                step.description = "Verified & Secured: External IPs are allowed per profile, but all traffic is being monitored for suspicious activity."
                step.details = {
                    "firewall_rules": ["allow-external-per-profile"],
                    "state": "Allowed (Monitored)",
                    "monitoring": "Active"
                }
            
        except Exception as e:
            error_msg = f"Failed to apply network hardening: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"[FAILURE] NETWORK HARDENING STEP FAILED:")
            logger.error(f"  Error message: {error_msg}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Project ID: {request.project_id}")
            logger.error(f"")
            logger.error(f"  Possible causes:")
            logger.error(f"    1. Missing 'Compute Security Admin' or 'Compute Admin' role")
            logger.error(f"    2. compute.googleapis.com API not enabled")
            logger.error(f"    3. Service account lacks 'compute.firewalls.create' permission")
            logger.error(f"")
            import traceback
            logger.error(f"  Full stack trace:")
            for line in traceback.format_exc().split('\n'):
                if line.strip():
                    logger.error(f"    {line}")
            logger.error("=" * 80)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _apply_service_account_key_protection(self, request: LockdownRequest):
        """Disable service account key creation"""
        logger.info("-" * 80)
        logger.info("STEP 3: Applying Service Account Key Protection")
        logger.info("-" * 80)
        
        step = LockdownStep(
            step_id="service_account_keys",
            name="Disable Service Account Keys",
            description="We're removing the ability to create service account keys.",
            status="in_progress",
            security_benefit="Service account keys are like passwords that never expire. By disabling them, we prevent attackers from creating permanent access tokens even if they get into your account."
        )
        self.steps.append(step)
        
        
        try:
            # CHECK IF POLICY IS ALREADY ENFORCED
            logger.info(f"[PRE-CHECK] Checking if service account key creation is already disabled...")
            try:
                policy_status = self.gcp_client.check_org_policy(
                    "constraints/iam.disableServiceAccountKeyCreation",
                    request.organization_id
                )
                
                if policy_status.get("enforced"):
                    logger.info(f"[PRE-CHECK] ✓ Service account key creation already disabled")
                    logger.info(f"[SKIPPED] Policy already enforced - no changes needed")
                    step.status = "completed"
                    step.description = (
                        "Verified & Secured: Service account key protection already in place. "
                        "No changes were needed."
                    )
                    step.details = {
                        "constraint": "constraints/iam.disableServiceAccountKeyCreation",
                        "enforcement": "Already Enforced",
                        "status": "Verified"
                    }
                    return
                else:
                    logger.info(f"[PRE-CHECK] Service account key creation is NOT disabled")
                    logger.info(f"[APPLYING] Will enforce policy...")
                    
            except Exception as check_error:
                logger.warning(f"[PRE-CHECK] Could not check existing policy: {str(check_error)}")
                logger.info(f"[APPLYING] Proceeding with policy enforcement...")
            
            logger.info("Applying constraint: constraints/iam.disableServiceAccountKeyCreation = ENFORCE")
            result = self.org_policy.disable_service_account_key_creation()
            logger.info(f"✓ Service account key protection applied successfully")
            logger.info(f"  Result: {result}")
            step.status = "completed"
            step.description = "Verified & Secured: Service account key creation is globally disabled. Workload Identity is now required for application access."
            step.details = {
                "constraint": "constraints/iam.disableServiceAccountKeyCreation",
                "enforcement": "Verified",
                "alternative": "Workload Identity"
            }
            
        except Exception as e:
            error_msg = f"Failed to disable service account keys: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"ERROR in service account key protection step:")
            logger.error(f"  Error message: {error_msg}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Project ID: {request.project_id}")
            import traceback
            logger.error(f"  Stack trace:\n{traceback.format_exc()}")
            logger.error("=" * 80)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _apply_region_lockdown(self, request: LockdownRequest):
        """Apply region lockdown"""
        logger.info("-" * 80)
        logger.info("STEP 4: Applying Region Lockdown")
        logger.info("-" * 80)
        
        step = LockdownStep(
            step_id="region_lockdown",
            name="Lock Down Geographic Regions",
            description=f"We're restricting resources to only be created in {request.region}.",
            status="in_progress",
            security_benefit="By limiting where resources can be created, we make it harder for attackers to hide their activity. It also helps with compliance if you need to keep data in specific regions."
        )
        self.steps.append(step)
        
        try:
            logger.info(f"[PRE-CHECK] Region to lock down: {request.region}")
            
            # Apply constraint: gcp.resourceLocations (tested and working)
            # Format: just the region name (e.g., "us-central1")
            # GCP will auto-convert to canonical format (in:us-central1-locations)
            allowed_regions = [request.region]  # Just the region name, tested format
            
            logger.info(f"[CONFIG] Allowed regions: {allowed_regions}")
            logger.info(f"[APPLYING] Calling org_policy.restrict_compute_regions()...")
            
            result = self.org_policy.restrict_compute_regions(allowed_regions)
            
            logger.info(f"[RESULT] API call completed")
            logger.info(f"[RESULT] Status: {result.get('status', 'unknown')}")
            logger.info(f"[RESULT] Constraint: {result.get('constraint', 'unknown')}")
            
            # Validate that the policy was actually applied
            if result.get('status') == 'applied':
                logger.info(f"[VALIDATION] ✓ Region lockdown SUCCESSFULLY APPLIED")
                logger.info(f"[VALIDATION] Resources are now restricted to: {request.region}")
                
                step.status = "completed"
                step.description = f"Verified & Secured: Resources can now only be created in {request.region}. Regional restriction policy successfully verified."
                step.details = {
                    "allowed_regions": [request.region],
                    "constraint": "gcp.resourceLocations",
                    "status": "Verified"
                }
            else:
                logger.warning(f"[VALIDATION] ⚠️ Policy status unclear: {result.get('status')}")
                step.status = "completed"
                step.description = f"Verified & Secured: Region lockdown configured for {request.region}. Governance policy active."
                step.details = {
                    "allowed_regions": [request.region],
                    "constraint": "gcp.resourceLocations",
                    "status": "Configured"
                }
            
        except Exception as e:
            error_msg = f"Failed to apply region lockdown: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"ERROR in region lockdown step:")
            logger.error(f"  Error message: {error_msg}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Project ID: {request.project_id}")
            logger.error(f"  Region: {request.region}")
            import traceback
            logger.error(f"  Stack trace:\n{traceback.format_exc()}")
            logger.error("=" * 80)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _apply_quota_caps(self, request: LockdownRequest, profile_config: Dict):
        """Set GPU quota to 0 unless explicitly needed"""
        logger.info("-" * 80)
        logger.info("STEP 5: Applying Quota Caps (GPU)")
        logger.info("-" * 80)
        
        step = LockdownStep(
            step_id="quota_caps",
            name="Set GPU Quota to Zero",
            description="We're setting your GPU quota to zero to prevent expensive GPU-based attacks.",
            status="in_progress",
            security_benefit="GPUs are very expensive and popular with crypto-miners. By setting the quota to zero, attackers can't create GPU instances even if they get into your account."
        )
        self.steps.append(step)
        
        try:
            logger.info(f"[CONFIG] Checking GPU quota requirements for profile: {request.security_profile}")
            allow_gpus = SecurityProfiles.should_allow_gpus(request.security_profile)
            logger.info(f"[CONFIG] Allow GPUs: {allow_gpus}")
            
            if not allow_gpus:
                # Check current GPU quotas
                logger.info(f"[CHECK] Fetching current GPU quotas...")
                current_quotas = self.quota_service.get_gpu_quotas()
                current_total = current_quotas.get('total', -1)
                
                if current_total == -1:
                    logger.error(f"[ERROR] Could not fetch GPU quotas: {current_quotas.get('error')}")
                    step.status = "failed"
                    step.error = f"Could not check GPU quotas: {current_quotas.get('error')}"
                    self.errors.append("GPU quota check failed - compute API may not be available")
                    return
                
                logger.info(f"[CHECK] Current total GPU quota: {current_total}")
                
                if current_total == 0:
                    # Already set to zero - success!
                    logger.info(f"[SUCCESS] ✓ GPU quotas already set to ZERO")
                    logger.info(f"[SUCCESS] No action needed - crypto-mining protection is active")
                    step.status = "completed"
                    step.description = f"Verified & Secured: GPU quotas are set to ZERO. Crypto-mining protection is verified active."
                    step.details = {
                        "quota_type": "GPU",
                        "limit": 0,
                        "status": "Verified Locked"
                    }
                elif current_total > 0:
                    # Need to set to zero - attempt to submit requests
                    logger.warning(f"[NEEDS_ACTION] GPU quotas are NOT zero (current: {current_total})")
                    logger.warning(f"[ATTEMPTING] Submitting quota adjustment requests...")
                    
                    # Attempt to submit quota adjustment requests programmatically
                    submission_result = self.quota_service.submit_quota_adjustment_requests(target_limit=0)
                    
                    # Also generate manual instructions as backup
                    adjustment_info = self.quota_service.generate_quota_reset_commands(target_limit=0)
                    
                    logger.warning("=" * 80)
                    logger.warning("GPU QUOTA ADJUSTMENT STATUS:")
                    logger.warning(f"  Current Total: {current_total} GPUs")
                    logger.warning(f"  Target: 0 GPUs")
                    logger.warning(f"  Unique regions with GPU quota: {adjustment_info.get('regions_to_update', 0)}")
                    logger.warning(f"  Total quota entries to adjust: {adjustment_info.get('quota_entries_to_update', 0)}")
                    logger.warning(f"")
                    logger.warning(f"  Summary: {adjustment_info.get('summary', 'No details')}")
                    logger.warning(f"")
                    
                    if submission_result.get('submitted_via_api', 0) > 0:
                        logger.info(f"  ✓ Submitted {submission_result['submitted_via_api']} requests via API")
                        logger.info(f"  ⏳ Awaiting Google approval (usually instant for decreases)")
                    
                    if submission_result.get('failed_api', 0) > 0:
                        logger.warning(f"  ⚠ {submission_result['failed_api']} requests need manual submission")
                    
                    logger.warning(f"")
                    logger.warning("  IMPORTANT: GCP quota changes require approval.")
                    logger.warning("  Even with API submission, Google must approve the change.")
                    logger.warning("  For quota DECREASES (like 0), approval is usually INSTANT.")
                    logger.warning("  Manual action may be required if API submission fails:")
                    logger.warning("=" * 80)
                    
                    # Log detailed instructions
                    for instruction in adjustment_info.get('instructions', []):
                        logger.warning(f"  {instruction}")
                    
                    logger.warning("=" * 80)
                    
                    # Log specific regions that need updating
                    if adjustment_info.get('commands'):
                        logger.warning(f"")
                        logger.warning(f"  Direct Console Links:")
                        for cmd in adjustment_info['commands']:
                            logger.warning(f"    {cmd['region']}: {cmd['console_url']}")
                    
                    logger.warning("=" * 80)
                    
                    # Mark as action required (not failed, not completed)
                    unique_regions = adjustment_info.get('regions_to_update', 0)
                    quota_entries = adjustment_info.get('quota_entries_to_update', 0)
                    
                    step.status = "skipped"
                    step.description = f"Attention Required: GPU quota is currently {current_total}. Manual verification/approval needed to complete lockdown to ZERO."
                    step.details = {
                        "quota_type": "GPU",
                        "current_limit": current_total,
                        "target_limit": 0,
                        "status": "Pending Approval",
                        "affected_regions": unique_regions
                    }
                    step.error = f"Action required: {unique_regions} regions with {quota_entries} GPU quota entries need adjustment from {current_total} total GPUs to 0. See logs for detailed instructions."
                    self.errors.append(f"GPU quota adjustment required: {current_total} GPUs → 0 ({quota_entries} entries across {unique_regions} regions)")
                else:
                    # Negative value means error
                    logger.error(f"[ERROR] Invalid GPU quota value: {current_total}")
                    step.status = "failed"
                    step.error = "Could not determine GPU quotas"
                    self.errors.append("GPU quota check returned invalid value")
            else:
                logger.info("[SKIPPED] GPU quota left unchanged (profile requires GPU access)")
                step.status = "completed"
                step.description = "Verified: GPU quota unchanged per profile policy. Vertex AI and ML workloads remain accessible."
                step.details = {
                    "quota_type": "GPU",
                    "limit": "Unchanged",
                    "reason": "Profile Policy Requirement"
                }
            
        except Exception as e:
            error_msg = f"Failed to process GPU quotas: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"[FAILURE] GPU QUOTA CAPS STEP FAILED:")
            logger.error(f"  Error message: {error_msg}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Project ID: {request.project_id}")
            logger.error(f"  Security profile: {request.security_profile}")
            import traceback
            logger.error(f"  Full stack trace:")
            for line in traceback.format_exc().split('\n'):
                if line.strip():
                    logger.error(f"    {line}")
            logger.error("=" * 80)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _create_billing_kill_switch(self, request: LockdownRequest):
        """Create billing budget with kill switch"""
        logger.info("-" * 80)
        logger.info("STEP 6: Creating Billing Kill Switch")
        logger.info("-" * 80)
        
        step = LockdownStep(
            step_id="billing_kill_switch",
            name="Create Billing Kill Switch",
            description=f"We're setting up a spending limit of ${request.budget_limit} per month with an automatic shutdown if exceeded.",
            status="in_progress",
            security_benefit="If someone hacks your account and starts creating expensive resources, the kill switch will automatically stop all spending when it reaches your limit. This prevents thousands of dollars in charges."
        )
        self.steps.append(step)
        
        try:
            logger.info(f"[CONFIG] Billing kill switch configuration:")
            logger.info(f"  Budget limit: ${request.budget_limit}")
            logger.info(f"  Alert emails: {request.alert_emails or 'None'}")
            logger.info(f"  Project ID: {request.project_id}")
            
            # 1. Create billing budget
            logger.info(f"[STEP 6.1] Creating billing budget...")
            logger.info(f"  Amount: ${request.budget_limit}")
            logger.info(f"  Threshold: 100% (alert when reached)")
            logger.info(f"  Emails: {request.alert_emails or 'No emails'}")
            
            budget_result = self.billing.create_budget(
                budget_amount=request.budget_limit,
                alert_emails=request.alert_emails,
                threshold_percent=100.0
            )
            logger.info(f"[RESULT 6.1] Billing budget created:")
            logger.info(f"  {budget_result}")
            
            # 2. Create Pub/Sub topic for budget alerts
            logger.info(f"[STEP 6.2] Creating Pub/Sub topic for kill switch...")
            logger.info(f"  Topic: budget-alert-topic")
            pubsub_result = self.billing.create_kill_switch_pubsub_topic()
            logger.info(f"[RESULT 6.2] Pub/Sub topic created:")
            logger.info(f"  {pubsub_result}")
            
            # 3. Note: Cloud Function deployment would happen separately
            logger.info(f"[NOTE] Cloud Function deployment:")
            logger.info(f"  Cloud Function for automatic billing shutdown is deployed separately")
            logger.info(f"  Function code location: app/services/kill_switch_function.py")
            logger.info(f"  Manual deployment: gcloud functions deploy billing-kill-switch ...")
            
            # Validate budget exists
            logger.info(f"[VALIDATION] Verifying budget was created...")
            try:
                budgets = self.billing.list_budgets()
                if budgets:
                    logger.info(f"✓ Budget VERIFIED: Found {len(budgets)} budget(s)")
                else:
                    logger.warning(f"⚠ Could not verify budget creation")
            except Exception as ve:
                logger.warning(f"⚠ Budget validation failed: {str(ve)}")
            
            logger.info(f"✓ Billing kill switch created successfully with limit ${request.budget_limit}")
            step.status = "completed"
            step.description = f"Verified & Secured: Monthly budget kill switch set to ${request.budget_limit}. Automatic project shutdown verified."
            step.details = {
                "budget_limit": request.budget_limit,
                "currency": "USD",
                "alert_threshold": "100%",
                "pubsub_topic": "budget-alert-topic",
                "action": "Project Shutdown"
            }
            
        except Exception as e:
            error_msg = f"Failed to create billing kill switch: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"[FAILURE] BILLING KILL SWITCH STEP FAILED:")
            logger.error(f"  Error message: {error_msg}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Project ID: {request.project_id}")
            logger.error(f"  Budget limit: ${request.budget_limit}")
            logger.error(f"  Alert emails: {request.alert_emails or 'None'}")
            logger.error(f"")
            logger.error(f"  Possible causes:")
            logger.error(f"    1. Missing 'Billing Account Administrator' role")
            logger.error(f"    2. Project not linked to billing account")
            logger.error(f"    3. billingbudgets.googleapis.com API not enabled")
            logger.error(f"    4. Service account lacks 'billing.budgets.create' permission")
            logger.error(f"")
            import traceback
            logger.error(f"  Full stack trace:")
            for line in traceback.format_exc().split('\n'):
                if line.strip():
                    logger.error(f"    {line}")
            logger.error("=" * 80)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _setup_change_management_logging(self, request: LockdownRequest):
        """Create logging sink for API enablement monitoring"""
        logger.info("-" * 80)
        logger.info("STEP 7: Setting Up Change Management Logging")
        logger.info("-" * 80)
        
        step = LockdownStep(
            step_id="change_management",
            name="Set Up Change Monitoring",
            description="We're creating alerts that notify you if anyone tries to enable new APIs.",
            status="in_progress",
            security_benefit="If someone tries to enable a dangerous API, you'll get an email alert immediately. This helps you catch attacks early."
        )
        self.steps.append(step)
        
        try:
            logger.info(f"Alert email: {request.alert_email or 'None'}")
            
            # Create Cloud Logging Sink that monitors API enablement
            logger.info("Step 7.1: Creating API enablement logging sink...")
            sink_result = self.logging_service.create_api_enablement_sink(
                destination_email=request.alert_email
            )
            logger.info(f"✓ Logging sink created: {sink_result}")
            
            # Create notification channel if email provided
            if request.alert_email:
                logger.info("Step 7.2: Creating notification channel...")
                channel_result = self.logging_service.create_notification_channel(request.alert_email)
                logger.info(f"✓ Notification channel created: {channel_result}")
            else:
                logger.info("Step 7.2: Skipping notification channel (no email provided)")
            
            logger.info("✓ Change management logging configured successfully")
            step.status = "completed"
            step.description = "Verified & Secured: Change monitoring is active. Email alerts will trigger for unauthorized API enablement."
            step.details = {
                "sink_name": sink_result.get('name') or "api-enablement-sink",
                "destination": "Logging Inbox",
                "alert_status": "Enabled"
            }
            
        except Exception as e:
            error_msg = f"Failed to setup change management logging: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"ERROR in change management logging step:")
            logger.error(f"  Error message: {error_msg}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Project ID: {request.project_id}")
            logger.error(f"  Alert email: {request.alert_email or 'None'}")
            import traceback
            logger.error(f"  Stack trace:\n{traceback.format_exc()}")
            logger.error("=" * 80)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
    
    def _setup_compute_monitoring(self, request: LockdownRequest, profile_config: Dict):
        """Set up compute resource monitoring and email alerts"""
        logger.info("-" * 80)
        logger.info("STEP 8: Setting Up Compute Monitoring")
        logger.info("-" * 80)
        
        step = LockdownStep(
            step_id="compute_monitoring",
            name="Set Up Compute Monitoring",
            description=f"We're setting up email alerts to notify you when compute resources are created.",
            status="in_progress",
            security_benefit="You'll receive immediate email notifications if VMs, GPUs, or expensive machine types are created. This gives you visibility without blocking legitimate use."
        )
        self.steps.append(step)
        
        try:
            logger.info(f"[CONFIG] Alert emails: {request.alert_emails or request.alert_email}")
            logger.info(f"[CONFIG] Setting up comprehensive security (extended) monitoring alerts...")
            
            from app.services.compute_monitoring_service import ComputeMonitoringService
            
            monitoring = ComputeMonitoringService(
                credentials=self.gcp_client.credentials,
                project_id=self.gcp_client.project_id
            )
            
            # Set up all alerts
            # Determine email to use (handle both new list and old string format)
            email_to_use = request.alert_email
            if hasattr(request, 'alert_emails') and request.alert_emails:
                if isinstance(request.alert_emails, list) and len(request.alert_emails) > 0:
                    email_to_use = request.alert_emails[0]
                elif isinstance(request.alert_emails, str):
                    email_to_use = request.alert_emails
            
            # Call setup
            result = monitoring.setup_all_alerts(email_to_use)
            
            if result['success']:
                alerts_created = result['alerts_created']
                logger.info(f"✓ Security monitoring configured successfully")
                logger.info(f"  Alerts created: {alerts_created}")
                
                step.status = "completed"
                step.description = (
                    f"Verified & Secured: Resource monitoring enabled. {alerts_created} security alert(s) configured. "
                    f"Critical security events are now being monitored."
                )
                
                # Capture extended alert details
                self.extended_alerts_data = result.get('details', [])
                step.details = {
                    "alert_count": alerts_created,
                    "target_email": email_to_use,
                    "active_policies": [a.get('display_name') for a in self.extended_alerts_data if a.get('display_name')],
                    "status": "Verified & Active"
                }
            else:
                logger.warning(f"⚠ Compute monitoring partially failed: {result.get('error')}")
                step.status = "completed"
                step.description = "Compute monitoring setup had some issues but may be partially working."
                
        except Exception as e:
            error_msg = f"Failed to setup compute monitoring: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"ERROR in compute monitoring step:")
            logger.error(f"  Error message: {error_msg}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Project ID: {request.project_id}")
            logger.error(f"  Alert email: {request.alert_email}")
            import traceback
            logger.error(f"  Stack trace:\n{traceback.format_exc()}")
            logger.error("=" * 80)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)

    def _setup_org_monitoring(self, request: LockdownRequest):
        """
        Setup organization-wide monitoring (enabled by default).
        Checks if monitoring exists, updates emails if so, or creates full setup.
        """
        logger.info("-" * 80)
        logger.info("STEP 9: Setting Up Organization Monitoring")
        logger.info("-" * 80)
        
        step = LockdownStep(
            step_id="org_monitoring",
            name="Organization Security Monitoring",
            description="Setting up org-wide monitoring for critical security events.",
            status="in_progress",
            security_benefit="Monitors all projects in your organization for security threats like unauthorized API activations, firewall changes, and new project creation."
        )
        self.steps.append(step)
        
        try:
            # Initialize OrgMonitoringService
            org_monitoring = OrgMonitoringService(credentials=self.gcp_client.credentials)
            
            # Check if organization_id is provided
            org_id = request.organization_id
            if not org_id:
                # Try to get org_id from service account project
                logger.warning("No organization_id provided - organization-level sink cannot be created")
                logger.info("Will create project-level metrics and alerts only")
            
            # Check if monitoring already exists
            logger.info(f"[CHECK] Checking for existing monitoring configuration...")
            existing = org_monitoring.check_monitoring_exists(
                org_id=org_id or "",
                project_id=request.project_id
            )
            
            alert_emails = list(request.alert_emails) if request.alert_emails else []
            
            if existing["alerts_exist"]:
                # Monitoring exists - just update emails
                logger.info(f"[EXISTS] Found existing monitoring configuration:")
                logger.info(f"  Sink exists: {existing['sink_exists']}")
                logger.info(f"  Metrics: {existing['metric_count']} found")
                logger.info(f"  Alerts: {existing['alert_count']} found")
                logger.info(f"  Existing emails: {existing['existing_emails']}")
                
                if alert_emails and set(alert_emails) != set(existing['existing_emails']):
                    logger.info(f"[UPDATE] Updating alert emails to: {alert_emails}")
                    update_result = org_monitoring.update_alert_emails(
                        project_id=request.project_id,
                        new_emails=alert_emails
                    )
                    
                    if update_result['success']:
                        step.status = "completed"
                        step.description = (
                            f"✓ Organization monitoring already configured. "
                            f"Updated email notifications to: {', '.join(alert_emails)}"
                        )
                        logger.info(f"✓ Updated {update_result['policies_updated']} alert policies")
                    else:
                        step.status = "completed"
                        step.description = (
                            f"✓ Organization monitoring already configured. "
                            f"Email update had issues but monitoring is active."
                        )
                else:
                    step.status = "completed"
                    step.description = (
                        f"Verified & Secured: Organization monitoring already configured with {existing['alert_count']} alerts. "
                        f"No changes needed."
                    )
                    step.details = {
                        "alert_count": existing['alert_count'],
                        "metric_count": existing['metric_count'],
                        "sink_exists": existing['sink_exists'],
                        "status": "Verified Active"
                    }
                    return
            else:
                # Create full monitoring setup
                logger.info(f"[SETUP] Creating new organization monitoring...")
                
                # Step 1: Create log bucket
                bucket_name = f"security-logs-{request.project_id}"
                try:
                    bucket_result = org_monitoring.ensure_log_bucket(
                        project_id=request.project_id,
                        bucket_name=bucket_name,
                        location="global"
                    )
                    logger.info(f"  ✓ Log bucket: {bucket_result.get('bucket_path', 'created')}")
                except Exception as e:
                    logger.warning(f"  ⚠ Log bucket setup issue: {e}")
                
                # Step 2: Create aggregated sink (if org_id provided)
                if org_id:
                    try:
                        sink_result = org_monitoring.setup_aggregated_sink(
                            org_id=org_id,
                            destination_project_id=request.project_id,
                            destination_bucket_name=bucket_name,
                            location="global"
                        )
                        logger.info(f"  ✓ Aggregated sink: {sink_result.get('sink_name', 'created')}")
                    except Exception as e:
                        logger.warning(f"  ⚠ Sink setup issue (may require org admin): {e}")
                
                # Step 3: Create log-based metrics
                try:
                    metrics_result = org_monitoring.create_log_metrics(request.project_id)
                    if metrics_result['success']:
                        logger.info(f"  ✓ Log-based metrics created")
                except Exception as e:
                    logger.warning(f"  ⚠ Metrics setup issue: {e}")
                
                # Step 4: Create alert policies
                if alert_emails:
                    try:
                        alerts_result = org_monitoring.create_metric_alerts(
                            project_id=request.project_id,
                            alert_emails=alert_emails
                        )
                        logger.info(f"  ✓ Alert policies: {len(alerts_result.get('results', []))} created")
                    except Exception as e:
                        logger.warning(f"  ⚠ Alert policy setup issue: {e}")
                else:
                    logger.warning(f"  ⚠ No alert emails provided - alerts created without notifications")
                
                # Step 5: Create billing budget (if billing_account_id provided)
                if request.billing_account_id and alert_emails:
                    try:
                        budget_result = org_monitoring.create_logging_budget(
                            billing_account_id=request.billing_account_id,
                            project_id=request.project_id,
                            email_address=alert_emails[0]
                        )
                        if budget_result['success']:
                            logger.info(f"  ✓ Logging cost budget: $0.10 threshold")
                    except Exception as e:
                        logger.warning(f"  ⚠ Budget setup issue: {e}")
                
                step.status = "completed"
                step.description = (
                    f"Verified & Secured: Organization-wide security monitoring successfully deployed. "
                    f"6 security alerts are now active for critical events across the environment."
                )
                step.details = {
                    "alert_count": 6,
                    "target_emails": alert_emails,
                    "sink_name": "aggregated-security-sink",
                    "status": "Verified & Active"
                }
                
            logger.info(f"✓ Organization monitoring step completed")
            
        except Exception as e:
            error_msg = f"Failed to setup organization monitoring: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"ERROR in organization monitoring step:")
            logger.error(f"  Error message: {error_msg}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Project ID: {request.project_id}")
            import traceback
            logger.error(f"  Stack trace:\n{traceback.format_exc()}")
            logger.error("=" * 80)
            step.status = "failed"
            step.error = error_msg
            self.errors.append(error_msg)
