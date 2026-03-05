"""
Script Generator Service
Generates executable lockdown scripts in multiple formats
"""
import logging
import hashlib
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
from app.config.monitoring_config import EXTENDED_ALERTS


# Monitoring/Alert Configurations
# Imported from shared config

# Protected APIs - These must NEVER be disabled as they are required for monitoring
# Used by both script_generator_service and lockdown_service
PROTECTED_APIS = [
    "logging.googleapis.com",           # Required for Aggregated Log Sink
    "monitoring.googleapis.com",        # Required for Alert Policies
    "billingbudgets.googleapis.com",    # Required for Cost Safety Budgets
    "serviceusage.googleapis.com",      # Required for API enablement detection
    "pubsub.googleapis.com",            # Required for Notifications
]

logger = logging.getLogger(__name__)

class ScriptGeneratorService:
    """Service for generating lockdown scripts"""
    
    def __init__(self):
        pass
    
    def generate_lockdown_script(
        self,
        project_id: str,
        organization_id: Optional[str],
        apis_to_disable: List[str],
        apply_network_hardening: bool,
        apply_org_policies: bool,
        region_lockdown: Optional[str],
        budget_limit: Optional[float],
        alert_emails: Optional[List[str]],
        compute_monitoring: bool,
        format: str = "python"
    ) -> Dict[str, Any]:
        """
        Generate complete lockdown script in specified format
        
        Args:
            format: Script format - "python", "terraform", or "pulumi"
            
        Returns:
            Dict with script, hash, summary, and metadata
        """
        logger.info(f"[SCRIPT GEN] Generating {format.upper()} script for project: {project_id}")
        
       # Route to appropriate generator
        if format == "terraform":
            return self._generate_terraform(
                project_id, organization_id, apis_to_disable, apply_network_hardening,
                apply_org_policies, region_lockdown, budget_limit, alert_emails, compute_monitoring
            )
        elif format == "pulumi":
            return self._generate_pulumi(
                project_id, organization_id, apis_to_disable, apply_network_hardening,
                apply_org_policies, region_lockdown, budget_limit, alert_emails, compute_monitoring
            )
        else:  # Default to Python
            return self._generate_python(
                project_id, organization_id, apis_to_disable, apply_network_hardening,
                apply_org_policies, region_lockdown, budget_limit, alert_emails, compute_monitoring
            )
    
    def _generate_python(
        self,
        project_id: str,
        organization_id: Optional[str],
        apis_to_disable: List[str],
        apply_network_hardening: bool,
        apply_org_policies: bool,
        region_lockdown: Optional[str],
        budget_limit: Optional[float],
        alert_emails: Optional[List[str]],
        compute_monitoring: bool
    ) -> Dict[str, Any]:
        """
        Generate Python lockdown script
        
        Returns:
            Dict with script, hash, summary, and metadata
        """
        """
        Generate complete lockdown script
        
        Returns:
            Dict with script, hash, summary, and metadata
        """
        logger.info(f"[SCRIPT GEN] Generating lockdown script for project: {project_id}")
        logger.info(f"[SCRIPT GEN] APIs to disable: {len(apis_to_disable)}")
        logger.info(f"[SCRIPT GEN] Network hardening: {apply_network_hardening}")
        logger.info(f"[SCRIPT GEN] Org policies: {apply_org_policies}")
        
        # Build script sections
        sections = []
        
        # Header
        sections.append(self._generate_header(project_id, organization_id))
        
        # Imports
        sections.append(self._generate_imports())
        
        # Report Class
        sections.append(self._generate_report_class())
        
        # Logging setup
        sections.append('''
# Logging Configuration
# Use a valid directory in user home to avoid CWD issues
home_dir = os.path.expanduser("~")
log_dir = os.path.join(home_dir, "GCP_Security_Logs")
try:
    os.makedirs(log_dir, exist_ok=True)
except Exception:
    # Fallback to temp dir if home is not writable
    import tempfile
    log_dir = tempfile.gettempdir()

log_filename = os.path.join(log_dir, f"lockdown_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}.log")
# Configure logging explicitly to ensure stdout is captured
# We avoid basicConfig because it might no-op if google libraries pre-configured logging
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

# File Handler
file_handler = logging.FileHandler(log_filename)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
root_logger.addHandler(file_handler)

# Stream Handler (stdout)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
root_logger.addHandler(stream_handler)

logger = logging.getLogger(__name__)


# Configuration
PROJECT_ID = "{project_id}"
ORGANIZATION_ID = "{organization_id}"
REGION = "{region_lockdown}"
BUDGET_LIMIT = {budget_limit}
ALERT_EMAILS = {alert_emails}

# Monitoring/Alert Configurations
# Monitoring/Alert Configurations
EXTENDED_ALERTS = {extended_alerts_json}

logger.info("="*80)
logger.info("GCP Security Lockdown - Project: %s", PROJECT_ID)
logger.info("Log file: %s", log_filename)
logger.info("="*80)
''')
        
        # Main function start
        sections.append("def main():")
        sections.append('    """Execute GCP security lockdown"""')
        sections.append("    global report_gen")
        sections.append(f"    report_gen = ReportGenerator('{project_id}')")
        sections.append("    try:")
        sections.append("        logger.info('='*80)")
        sections.append(f"        logger.info('GCP Security Lockdown - Project: {project_id}')")
        sections.append("        logger.info('='*80)")
        
        # Verify Identity (Debug)
        sections.append('''
        try:
            import google.auth
            credentials, project = google.auth.default()
            email = getattr(credentials, "service_account_email", "unknown")
            logger.info("DEBUG: Active Service Account: %s", email)
            if hasattr(credentials, "service_account_email"):
               logger.info("DEBUG: Auth Type: Service Account")
            else:
               logger.info("DEBUG: Auth Type: Default/Other")
        except Exception as e:
            logger.info("DEBUG: Failed to verify identity: %s", e)
''')

            
        sections.append("")
        
        step_count = 1
        
        # Network Hardening - MUST BE BEFORE API DISABLING
        # But skip if compute API is being disabled anyway (as per user feedback)
        if apply_network_hardening and "compute.googleapis.com" not in apis_to_disable:
            sections.append(self._generate_firewall_code(step_count))
            step_count += 1
        
        # API Disabling
        if apis_to_disable:
            sections.append(self._generate_api_disable_code(apis_to_disable, step_count))
            step_count += 1
        
        # Organization Policies
        if apply_org_policies:
            sections.append(self._generate_org_policy_code(project_id, organization_id, step_count))
            step_count += 1
        
        # Region Lockdown
        if region_lockdown:
            sections.append(self._generate_region_lockdown_code(project_id, region_lockdown, organization_id, step_count))
            step_count += 1
        
        # Billing Budget
        if budget_limit and alert_emails:
            sections.append(self._generate_billing_code(budget_limit, alert_emails, step_count))
            step_count += 1
        
        # Compute Monitoring
        if compute_monitoring:
            sections.append(self._generate_monitoring_code(alert_emails or [], step_count))
            step_count += 1
        
        # Completion
        sections.append("        logger.info('='*80)")
        sections.append("        logger.info('✅ Lockdown complete!')")
        sections.append("        logger.info('='*80)")
        sections.append("        report_gen.set_status('success')")
        sections.append("        report_gen.save()")
        sections.append("    except Exception as e:")
        sections.append("        logger.error('❌ Lockdown failed: %s', e, exc_info=True)")
        sections.append("        logger.error('Check the log file for details')")
        sections.append("        if report_gen:")
        sections.append("            report_gen.set_status('failed')")
        sections.append("            report_gen.save()")
        sections.append("        sys.exit(1)")
        sections.append("")
        sections.append("")
        sections.append("if __name__ == '__main__':")
        sections.append("    main()")
        
        # Join all sections
        script_template = "\n".join(sections)
        
        # Replace template placeholders with actual values
        script = script_template.format(
            project_id=project_id,
            organization_id=organization_id or "",
            region_lockdown=region_lockdown or "us-central1",
            budget_limit=budget_limit or 0.0,
            alert_emails=json.dumps(alert_emails or []),
            extended_alerts_json=json.dumps(EXTENDED_ALERTS, indent=4),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        # Calculate hash
        script_hash = hashlib.sha256(script.encode()).hexdigest()
        
        # Generate summary
        summary = {
            "steps": step_count - 1,
            "apis_to_disable": len(apis_to_disable),
            "network_hardening": apply_network_hardening,
            "org_policies": apply_org_policies,
            "region_lockdown": region_lockdown,
            "budget_configured": budget_limit is not None,
            "monitoring_enabled": compute_monitoring
        }
        
        # Estimate duration
        estimated_minutes = (
            len(apis_to_disable) * 0.5 +  # 30 sec per API
            (2 if apply_network_hardening else 0) +  # 2 min for firewalls
            (2 if apply_org_policies else 0) +  # 2 min for policies
            (1 if region_lockdown else 0) +  # 1 min for region
            (1 if budget_limit else 0) +  # 1 min for budget
            (2 if compute_monitoring else 0)  # 2 min for monitoring
        )
        
        estimated_duration = f"{int(estimated_minutes)}-{int(estimated_minutes + 2)} minutes"
        
        # Generate warnings
        warnings = []
        if apis_to_disable:
            warnings.append(f"Disabling {len(apis_to_disable)} APIs may affect existing resources")
        if apply_network_hardening:
            warnings.append("Firewall rules will block all external ingress traffic")
        if region_lockdown:
            warnings.append(f"Resources can only be created in {region_lockdown}")
        
        logger.info(f"[SCRIPT GEN] ✓ Generated script: {len(script)} characters, {step_count-1} steps")
        
        return {
            "script": script,
            "script_hash": script_hash,
            "summary": summary,
            "estimated_duration": estimated_duration,
            "warnings": warnings
        }
    
    def _generate_report_class(self) -> str:
        """Generate ReportGenerator class code"""
        return '''
import json

class ReportGenerator:
    """Generates structured JSON report of lockdown actions"""
    def __init__(self, project_id):
        self.report = {{
            "timestamp": datetime.now().isoformat(),
            "project_id": project_id,
            "status": "pending",
            "actions": {{
                "apis_disabled": [],
                "policies_enforced": [],
                "firewall_rules": [],
                "notifications": [],
                "extended_alerts": []
            }},
            "summary": {{
                "apis_count": 0,
                "policies_count": 0,
                "firewalls_count": 0,
                "alerts_count": 0
            }}
        }}
        
    def add_action(self, category, item):
        if category in self.report["actions"]:
            self.report["actions"][category].append(item)
            
    def set_status(self, status):
        self.report["status"] = status
        
    def save(self, filename="lockdown_report.json"):
        # Calculate summary counts
        self.report["summary"]["apis_count"] = len(self.report["actions"]["apis_disabled"])
        self.report["summary"]["policies_count"] = len(self.report["actions"]["policies_enforced"])
        self.report["summary"]["firewalls_count"] = len(self.report["actions"]["firewall_rules"])
        self.report["summary"]["alerts_count"] = len(self.report["actions"]["extended_alerts"])
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.report, f, indent=2)
            logger.info(f"Report saved to {{filename}}")
        except Exception as e:
            logger.error(f"Failed to save report: {{e}}")

# Initialize global report generator
report_gen = None
'''

    def _generate_header(self, project_id: str, organization_id: Optional[str]) -> str:
        """Generate script header with metadata"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header = f'''#!/usr/bin/env python3
"""
GCP Security Lockdown Script
Auto-generated by GCP Security Hardener

Project: {project_id}
Organization: {organization_id or "N/A"}
Generated: {timestamp}

IMPORTANT: Review this script before executing!
This script will make security changes to your GCP project.
"""
'''
        return header
    
    def _generate_imports(self) -> str:
        """Generate import statements"""
        return '''
# Imports
import logging
import sys
import os
import json
from datetime import datetime
from google.cloud import compute_v1
from google.cloud import orgpolicy_v2
from google.cloud import billing_v1
from google.cloud import monitoring_v3
from google.api_core import exceptions
'''
    
    def _generate_config(
        self,
        project_id: str,
        organization_id: Optional[str],
        region: Optional[str],
        budget_limit: Optional[float],
        alert_emails: Optional[List[str]]
    ) -> str:
        """Generate configuration section"""
        return f'''
# Configuration
PROJECT_ID = "{project_id}"
ORGANIZATION_ID = "{organization_id or ""}"
REGION = "{region or "us-central1"}"
BUDGET_LIMIT = {budget_limit or 0.0}
ALERT_EMAILS = {alert_emails or []}
'''

    def _generate_api_disable_code(self, apis: List[str], step_num: int) -> str:
        """Generate code to disable APIs"""
        # CRITICAL: Always whitelist these APIs for monitoring/safety
        IGNORED_APIS = {
            "logging.googleapis.com", 
            "monitoring.googleapis.com", 
            "serviceusage.googleapis.com", 
            "billingbudgets.googleapis.com", 
            "pubsub.googleapis.com"
        }
        
        filtered_apis = [api for api in apis if api not in IGNORED_APIS]
        
        if not filtered_apis:
            return f'''
        # Step {step_num}: Disable APIs (Skipped)
        logger.info("Step {step_num}: No APIs to disable (Protected APIs were filtered out)")
'''

        apis_str = '",\n        "'.join(filtered_apis)
        
        # Use simple string template to avoid f-string escaping confusion
        # We need quadruple braces {{{{var}}}} to survive two rounds of .format()
        # Round 1 (here): {{{{var}}}} -> {{var}}
        # Round 2 (final script gen): {{var}} -> {var}
        template = '''
        # Step {step_num}: Disable APIs
        logger.info(f"Step {step_num}: Disabling {num_apis_filtered} APIs...")
        
        apis_to_disable = [
            "{apis_str}"
        ]
        
        # Use service usage API to disable
        from googleapiclient.discovery import build
        service = build('serviceusage', 'v1')

        for api in apis_to_disable:
            try:
                logger.info(f"  Disabling {{{{api}}}}...")
                service_name = f"projects/{{{{PROJECT_ID}}}}/services/{{{{api}}}}"
                # Force disable dependent services to avoid 400 errors
                # Must be passed in body dict, not as kwarg
                # Quadruple braces needed because of 2-pass formatting
                request = service.services().disable(
                    name=service_name, 
                    body={{{{'disableDependentServices': True}}}}
                )
                request.execute()
                logger.info(f"    ✓ Disabled {{{{api}}}}")
                report_gen.add_action('apis_disabled', api)
            except Exception as e:
                logger.info(f"    ✗ Failed to disable {{{{api}}}}: {{{{e}}}}")
        
        logger.info(f"✓ Step {step_num} complete")
'''
        return template.format(
            step_num=step_num,
            num_apis_filtered=len(filtered_apis),
            apis_str=apis_str
        )

    def _generate_firewall_code(self, step_num: int) -> str:
        """Generate code to create firewall rules"""
        return f'''
        # Step {step_num}: Create Firewall Rules
        # Check if compute API is enabled before trying to manage firewalls
        from googleapiclient.discovery import build as su_build
        compute_api_enabled = False
        try:
            su_service = su_build('serviceusage', 'v1')
            comp_service = su_service.services().get(name=f"projects/{{{{PROJECT_ID}}}}/services/compute.googleapis.com").execute()
            if comp_service.get('state') == 'ENABLED':
                compute_api_enabled = True
            else:
                logger.info("  ⚠ Compute Engine API is disabled. Skipping firewall rules.")
        except Exception as e:
            logger.info(f"  ⚠ Could not verify Compute API status: {{{{e}}}}. Attempting firewalls anyway...")
            compute_api_enabled = True

        if compute_api_enabled:
            firewall_client = compute_v1.FirewallsClient()
            
            # Rule 1: Deny all external ingress
            deny_rule = compute_v1.Firewall(
                name="deny-external-ingress",
                description="Block all external ingress traffic (GCP Security Hardener)",
                network=f"projects/{{{{PROJECT_ID}}}}/global/networks/default",
                direction="INGRESS",
                priority=100,
                denied=[compute_v1.Denied(I_p_protocol="all")],
                source_ranges=["0.0.0.0/0"]
            )
            
            try:
                logger.info("  Creating deny-external-ingress rule...")
                operation = firewall_client.insert(
                    project=PROJECT_ID,
                    firewall_resource=deny_rule
                )
                operation.result()  # Wait for completion
                logger.info("    ✓ Created deny-external-ingress")
                report_gen.add_action('firewall_rules', 'deny-external-ingress')
            except exceptions.AlreadyExists:
                logger.info("    ⚠ Rule already exists, skipping")
            except Exception as e:
                logger.info(f"    ✗ Failed: {{{{e}}}}")
            
            # Rule 2: Allow internal traffic
            allow_rule = compute_v1.Firewall(
                name="allow-internal",
                description="Allow internal VPC traffic (GCP Security Hardener)",
                network=f"projects/{{{{PROJECT_ID}}}}/global/networks/default",
                direction="INGRESS",
                priority=90,
                allowed=[compute_v1.Allowed(I_p_protocol="all")],
                source_ranges=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            )
            
            try:
                logger.info("  Creating allow-internal rule...")
                operation = firewall_client.insert(
                    project=PROJECT_ID,
                    firewall_resource=allow_rule
                )
                operation.result()
                logger.info("    ✓ Created allow-internal")
                report_gen.add_action('firewall_rules', 'allow-internal')
            except exceptions.AlreadyExists:
                logger.info("    ⚠ Rule already exists, skipping")
            except Exception as e:
                logger.info(f"    ✗ Failed: {{{{e}}}}")
            
        logger.info(f"✓ Step {step_num} complete")
'''
    
    def _generate_org_policy_code(self, project_id: str, organization_id: Optional[str], step_num: int) -> str:
        """Generate code to set organization policies"""
        parent = f"organizations/{organization_id}" if organization_id else f"projects/{project_id}"
        
        # Use template without f-strings to avoid escaping complexity
        template = '''
        # Step {step_num}: Set Organization Policies
        logger.info(f"Step {step_num}: Setting organization policies...")
        
        org_policy_client = orgpolicy_v2.OrgPolicyClient()
        parent = "{parent}"
        
        # Disable service account key creation
        try:
            logger.info("  Setting iam.disableServiceAccountKeyCreation...")
            policy_name = f"{{{{parent}}}}/policies/iam.disableServiceAccountKeyCreation"
            policy = orgpolicy_v2.Policy(
                name=policy_name,
                spec=orgpolicy_v2.PolicySpec(
                    rules=[orgpolicy_v2.PolicySpec.PolicyRule(enforce=True)]
                )
            )
            
            # Try to create first (if no override exists)
            try:
                org_policy_client.create_policy(parent=parent, policy=policy)
                logger.info("    ✓ Created policy: Disable SA Key Creation")
                report_gen.add_action('policies_enforced', 'iam.disableServiceAccountKeyCreation')
            except Exception as e:
                # If already exists, update it
                if "409" in str(e) or "ALREADY_EXISTS" in str(e):
                    logger.info("    ⚠ Policy override exists, updating...")
                    org_policy_client.update_policy(policy=policy)
                    logger.info("    ✓ Updated policy: Disable SA Key Creation")
                    report_gen.add_action('policies_enforced', 'iam.disableServiceAccountKeyCreation')
                else:
                    raise e
                    
        except Exception as e:
            logger.info(f"    ✗ Failed SA Key Creation policy: {{{{e}}}}")

        # Restrict VM external IP access (LIST CONSTRAINT)
        try:
            logger.info("  Setting compute.vmExternalIpAccess...")
            policy_name = f"{{{{parent}}}}/policies/compute.vmExternalIpAccess"
            policy = orgpolicy_v2.Policy(
                name=policy_name,
                spec=orgpolicy_v2.PolicySpec(
                    rules=[orgpolicy_v2.PolicySpec.PolicyRule(deny_all=True)]
                )
            )
            
            try:
                org_policy_client.create_policy(parent=parent, policy=policy)
                logger.info("    ✓ Created policy: Restrict VM External IPs")
                report_gen.add_action('policies_enforced', 'compute.vmExternalIpAccess')
            except Exception as e:
                if "409" in str(e) or "ALREADY_EXISTS" in str(e):
                    logger.info("    ⚠ Policy override exists, updating...")
                    org_policy_client.update_policy(policy=policy)
                    logger.info("    ✓ Updated policy: Restrict VM External IPs")
                    report_gen.add_action('policies_enforced', 'compute.vmExternalIpAccess')
                else:
                    raise e
                    
        except Exception as e:
            logger.info(f"    ✗ Failed VM External IP policy: {{{{e}}}}")
        
        logger.info(f"✓ Step {step_num} complete")
'''
        return template.format(
            step_num=step_num,
            parent=parent
        )    
    def _generate_region_lockdown_code(self, project_id: str, region: str, organization_id: Optional[str], step_num: int) -> str:
        """Generate code to restrict resources to a specific region"""
        parent = f"organizations/{organization_id}" if organization_id else f"projects/{project_id}"
        
        template = '''
        # Step {step_num}: Lock Down to Region
        logger.info(f"Step {step_num}: Locking down to region {region}...")
        
        org_policy_client = orgpolicy_v2.OrgPolicyClient()
        parent = "{parent}"
        
        try:
            logger.info(f"  Restricting resources to {{{{REGION}}}}...")
            policy_name = f"{{{{parent}}}}/policies/gcp.resourceLocations"
            policy = orgpolicy_v2.Policy(
                name=policy_name,
                spec=orgpolicy_v2.PolicySpec(
                    rules=[
                        orgpolicy_v2.PolicySpec.PolicyRule(
                            values=orgpolicy_v2.PolicySpec.PolicyRule.StringValues(
                                allowed_values=["{region}"]
                            )
                        )
                    ]
                )
            )
            
            # Try to create first (if no override exists)
            try:
                org_policy_client.create_policy(parent=parent, policy=policy)
                logger.info(f"    ✓ Created policy: Lock to {region}")
                report_gen.add_action('policies_enforced', 'gcp.resourceLocations')
            except Exception as e:
                # If already exists, update it
                if "409" in str(e) or "ALREADY_EXISTS" in str(e):
                    logger.info("    ⚠ Policy override exists, updating...")
                    org_policy_client.update_policy(policy=policy)
                    logger.info(f"    ✓ Updated policy: Lock to {region}")
                    report_gen.add_action('policies_enforced', 'gcp.resourceLocations')
                else:
                    raise e

        except Exception as e:
            logger.info(f"    ✗ Failed: {{{{e}}}}")
        
        logger.info(f"✓ Step {step_num} complete")
'''
        return template.format(
            step_num=step_num,
            parent=parent,
            region=region
        )
    
    def _generate_billing_code(self, budget_limit: float, alert_emails: List[str], step_num: int) -> str:
        """Generate code for billing budget setup"""
        return f'''
        # Step {step_num}: Set Up Billing Budget
        logger.info(f"Step {step_num}: Creating billing budget (${budget_limit})...")
        
        # Note: This requires billing account access
        # Manual step required - see GCP Console
        logger.info(f"  ⚠ Manual step required:")
        logger.info(f"    1. Go to GCP Console > Billing > Budgets")
        logger.info(f"    2. Create budget with ${budget_limit} limit")
        logger.info(f"    3. Add alert emails: {alert_emails}")
        
        # NOTE: This is just a manual action log for now
        report_gen.add_action('notifications', f"Budget Alert: {alert_emails}")
'''
    
    
    def _generate_monitoring_code(self, alert_emails: List[str], step_num: int) -> str:
        """Generate code for ORGANIZATION-LEVEL monitoring with aggregated sink"""
        return f'''
        # Step {step_num}: Set Up ORGANIZATION-LEVEL Monitoring (Aggregated Sink)
        logger.info(f"Step {step_num}: Setting up organization-level monitoring...")
        logger.info("  This will monitor ALL projects in your organization.")
        
        from googleapiclient.discovery import build
        from google.api_core import exceptions as gcp_exceptions
        import google.auth
        
        # Get credentials explicitly for all clients
        credentials, _ = google.auth.default()
        
        # Log which service account is being used
        sa_email = getattr(credentials, 'service_account_email', 'unknown (not SA credentials)')
        logger.info(f"  Using credentials: {{{{sa_email}}}}")
        
        # Ensure Monitoring API is enabled before using it
        try:
            from googleapiclient.discovery import build as su_build
            serviceusage = su_build('serviceusage', 'v1', credentials=credentials)
            logger.info("  Ensuring monitoring.googleapis.com is enabled...")
            serviceusage.services().enable(
                name=f"projects/{{{{PROJECT_ID}}}}/services/monitoring.googleapis.com"
            ).execute()
            logger.info("    ✓ Monitoring API enabled")
        except Exception as e:
            if "already enabled" in str(e).lower() or "ALREADY_ENABLED" in str(e):
                logger.info("    ✓ Monitoring API already enabled")
            else:
                logger.warning(f"    ⚠ Could not enable Monitoring API: {{{{e}}}}")
        
        # Use REST API for all operations (more reliable than gRPC clients)
        logging_service = build('logging', 'v2', credentials=credentials)
        monitoring_service = build('monitoring', 'v3', credentials=credentials)
        
        try:
            # === Auto-detect Organization ID if not provided ===
            detected_org_id = ORGANIZATION_ID
            if not detected_org_id:
                logger.info("  Auto-detecting Organization ID from project...")
                try:
                    from googleapiclient.discovery import build as crm_build
                    crm_service = crm_build('cloudresourcemanager', 'v1')
                    project_info = crm_service.projects().get(projectId=PROJECT_ID).execute()
                    parent = project_info.get('parent', {{{{}}}})
                    if parent.get('type') == 'organization':
                        detected_org_id = parent.get('id')
                        logger.info(f"    ✓ Detected Organization ID: {{{{detected_org_id}}}}")
                    elif parent.get('type') == 'folder':
                        # Traverse folders to find org
                        folders_service = crm_build('cloudresourcemanager', 'v2')
                        folder_id = parent.get('id')
                        for _ in range(10):
                            folder = folders_service.folders().get(name=f"folders/{{{{folder_id}}}}").execute()
                            folder_parent = folder.get('parent', '')
                            if folder_parent.startswith('organizations/'):
                                detected_org_id = folder_parent.replace('organizations/', '')
                                logger.info(f"    ✓ Detected Organization ID via folder: {{{{detected_org_id}}}}")
                                break
                            elif folder_parent.startswith('folders/'):
                                folder_id = folder_parent.replace('folders/', '')
                            else:
                                break
                except Exception as e:
                    logger.warning(f"    ⚠ Could not auto-detect org ID: {{{{e}}}}")
            
            # === STEP A: Create Log Bucket in Central Project ===
            logger.info("  Step A: Creating log bucket for aggregated logs...")
            bucket_name = "security-org-logs"
            # Use us-central1 instead of global to comply with gcp.resourceLocations org policy
            bucket_location = "us-central1"
            bucket_path = f"projects/{{{{PROJECT_ID}}}}/locations/{{{{bucket_location}}}}/buckets/{{{{bucket_name}}}}"
            
            try:
                # Check if bucket exists
                logging_service.projects().locations().buckets().get(name=bucket_path).execute()
                logger.info(f"    ✓ Log bucket already exists: {{{{bucket_path}}}}")
            except Exception as e:
                if "404" in str(e) or "NotFound" in str(e):
                    # Create the bucket
                    logging_service.projects().locations().buckets().create(
                        parent=f"projects/{{{{PROJECT_ID}}}}/locations/{{{{bucket_location}}}}",
                        bucketId=bucket_name,
                        body={{{{"retentionDays": 30}}}}
                    ).execute()
                    logger.info(f"    ✓ Created log bucket: {{{{bucket_path}}}}")
                else:
                    logger.warning(f"    ⚠ Step A failed: {{{{e}}}}")
            
            if 'bucket_path' in dir():
                report_gen.add_action('log_bucket', bucket_path)
            
            # === STEP B: Create Aggregated Sink at Organization Level ===
            if detected_org_id:
                logger.info("  Step B: Creating aggregated sink at organization level...")
                sink_name = "security-hardener-org-sink"
                org_parent = f"organizations/{{{{detected_org_id}}}}"
                destination = f"logging.googleapis.com/projects/{{{{PROJECT_ID}}}}/locations/{{{{bucket_location}}}}/buckets/{{{{bucket_name}}}}"
                
                # Filter for security events - using AuditLog type for robustness
                sink_filter = (
                    'protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog" AND ('
                    'protoPayload.methodName=~"EnableService" OR '
                    'protoPayload.methodName=~"SetPolicy" OR '
                    'protoPayload.methodName=~"SetOrgPolicy" OR '
                    'protoPayload.methodName=~"UpdatePolicy" OR '
                    'protoPayload.serviceName="billingbudgets.googleapis.com" OR '
                    'protoPayload.methodName=~"UpdateQuota" OR '
                    'protoPayload.serviceName="cloudbilling.googleapis.com" OR '
                    'resource.type="gce_firewall_rule" OR '
                    'protoPayload.methodName=~"CreateProject"'
                    ')'
                )
                
                sink_body = {{{{
                    "name": sink_name,
                    "destination": destination,
                    "filter": sink_filter,
                    "includeChildren": True  # CRITICAL: Aggregates from all child projects
                }}}}
                
                try:
                    # Try to update existing sink
                    sink_full_name = f"{{{{org_parent}}}}/sinks/{{{{sink_name}}}}"
                    created_sink = logging_service.organizations().sinks().patch(
                        sinkName=sink_full_name,
                        body=sink_body
                    ).execute()
                    logger.info(f"    ✓ Updated aggregated sink: {{{{created_sink.get('name')}}}}") 
                except Exception as e:
                    if "404" in str(e) or "NotFound" in str(e):
                        # Create new sink
                        created_sink = logging_service.organizations().sinks().create(
                            parent=org_parent,
                            body=sink_body
                        ).execute()
                        logger.info(f"    ✓ Created aggregated sink: {{{{created_sink.get('name')}}}}") 
                    else:
                        logger.warning(f"    ⚠ Step B failed: {{{{e}}}}")
                
                writer_identity = created_sink.get('writerIdentity', 'unknown')
                logger.info(f"    Writer identity: {{{{writer_identity}}}}")
                
                # Auto-grant bucketWriter permission to the sink's writer identity
                if writer_identity and writer_identity != 'unknown':
                    try:
                        from googleapiclient.discovery import build as crm_build
                        crm = crm_build('cloudresourcemanager', 'v1', credentials=credentials)
                        
                        # Get current IAM policy
                        policy = crm.projects().getIamPolicy(
                            resource=PROJECT_ID,
                            body={{{{}}}},
                        ).execute()
                        
                        # Add the binding
                        member = writer_identity.replace('serviceAccount:', '')
                        new_binding = {{{{'role': 'roles/logging.bucketWriter', 'members': [writer_identity]}}}}
                        
                        # Check if binding already exists
                        binding_exists = False
                        for binding in policy.get('bindings', []):
                            if binding.get('role') == 'roles/logging.bucketWriter':
                                if writer_identity not in binding.get('members', []):
                                    binding['members'].append(writer_identity)
                                binding_exists = True
                                break
                        
                        if not binding_exists:
                            policy.setdefault('bindings', []).append(new_binding)
                        
                        # Set the updated policy
                        crm.projects().setIamPolicy(
                            resource=PROJECT_ID,
                            body={{{{'policy': policy}}}},
                        ).execute()
                        logger.info(f"    ✓ Granted roles/logging.bucketWriter to sink writer identity")
                    except Exception as e:
                        logger.warning(f"    ⚠ Could not auto-grant bucketWriter: {{{{e}}}}")
                        logger.info(f"    Manual step: gcloud projects add-iam-policy-binding {{{{PROJECT_ID}}}} --member='{{{{writer_identity}}}}' --role='roles/logging.bucketWriter'")
                
                report_gen.add_action('aggregated_sink', {{{{
                    "sink_name": created_sink.get('name'),
                    "writer_identity": writer_identity,
                    "destination": destination
                }}}})
            else:
                logger.warning("  ⚠ No ORGANIZATION_ID set - skipping aggregated sink (project-level only)")
            
            # === STEP C: Create BUCKET-SCOPED Log-Based Metrics ===
            # Bucket-scoped metrics read from the log bucket where aggregated sink routes logs
            logger.info("  Step C: Creating bucket-scoped log-based metrics...")
            metrics = [
                ("api_enablement_count", 'protoPayload.serviceName="serviceusage.googleapis.com" AND protoPayload.methodName=~"EnableService"', "API enablement events"),
                ("org_policy_change_count", 'protoPayload.methodName=~"SetPolicy" OR protoPayload.methodName=~"SetOrgPolicy" OR protoPayload.methodName=~"UpdatePolicy"', "Org policy changes"),
                ("billing_budget_change_count", 'protoPayload.serviceName="billingbudgets.googleapis.com" OR protoPayload.methodName=~"UpdateQuota" OR protoPayload.serviceName="cloudbilling.googleapis.com"', "Billing and Quota changes"),
                ("firewall_change_count", 'protoPayload.serviceName="compute.googleapis.com" AND (protoPayload.methodName=~"compute.firewalls" OR resource.type="gce_firewall_rule")', "Firewall rule changes"),
                ("inbound_rdp_count", 'resource.type="gce_firewall_rule" AND protoPayload.methodName=~"insert" AND protoPayload.request.allowed.ports:"3389"', "Inbound RDP rules enabled"),
                ("project_creation_count", 'protoPayload.methodName=~"CreateProject"', "Project creation events"),
            ]
            
            # Bucket path for bucket-scoped metrics
            bucket_full_path = f"projects/{{{{PROJECT_ID}}}}/locations/{{{{bucket_location}}}}/buckets/{{{{bucket_name}}}}"
            
            for metric_name, metric_filter, description in metrics:
                try:
                    metric_body = {{{{
                        "name": metric_name,
                        "filter": metric_filter,
                        "description": description,
                        "bucketName": bucket_full_path,
                        "metricDescriptor": {{{{
                            "metricKind": "DELTA",
                            "valueType": "INT64",
                            "labels": [
                                {{{{ "key": "service_name", "valueType": "STRING", "description": "Service name" }}}},
                                {{{{ "key": "method_name", "valueType": "STRING", "description": "Method name" }}}},
                                {{{{ "key": "project_id", "valueType": "STRING", "description": "Impacted Project ID" }}}},
                                {{{{ "key": "principal", "valueType": "STRING", "description": "Performing user" }}}}
                            ]
                        }}}},
                        "labelExtractors": {{{{
                            "service_name": "EXTRACT(protoPayload.serviceName)",
                            "method_name": "EXTRACT(protoPayload.methodName)",
                            "project_id": "EXTRACT(resource.labels.project_id)",
                            "principal": "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
                        }}}}
                    }}}}
                    logging_service.projects().metrics().create(
                        parent=f"projects/{{{{PROJECT_ID}}}}",
                        body=metric_body
                    ).execute()
                    logger.info(f"    ✓ Created bucket-scoped metric: {{{{metric_name}}}}")
                except Exception as e:
                    if "AlreadyExists" in str(e) or "409" in str(e):
                        try:
                            # Update existing metric to reflect new filter and labels
                            metric_full_name = f"projects/{{{{PROJECT_ID}}}}/metrics/{{{{metric_name}}}}"
                            logger.info(f"    ✓ Updating existing metric: {{{{metric_name}}}}")
                            logging_service.projects().metrics().update(
                                metricName=metric_full_name,
                                body=metric_body
                            ).execute()
                            logger.info(f"    ✓ Updated metric with new labels and filters.")
                        except Exception as patch_e:
                            logger.warning(f"    ⚠ Could not update metric {{{{metric_name}}}}: {{{{patch_e}}}}")
                    else:
                        logger.warning(f"    ⚠ Could not create metric {{{{metric_name}}}}: {{{{e}}}}")
            
            report_gen.add_action('log_metrics', [m[0] for m in metrics])
            
            # === STEP D: Create Notification Channels ===
            logger.info("  Step D: Creating notification channels...")
            channel_names = []
            project_name = f"projects/{{{{PROJECT_ID}}}}"
            
            for email in ALERT_EMAILS:
                try:
                    channel_body = {{{{
                        "type": "email",
                        "displayName": f"Security Alert - {{{{email}}}}",
                        "labels": {{{{"email_address": email}}}}
                    }}}}
                    created_channel = monitoring_service.projects().notificationChannels().create(
                        name=project_name,
                        body=channel_body
                    ).execute()
                    channel_names.append(created_channel.get('name'))
                    logger.info(f"    ✓ Created channel: {{{{email}}}}")
                except Exception as e:
                    if "409" in str(e) or "AlreadyExists" in str(e):
                        # Find existing channel
                        try:
                            channels_resp = monitoring_service.projects().notificationChannels().list(
                                name=project_name
                            ).execute()
                            for ch in channels_resp.get('notificationChannels', []):
                                if ch.get('labels', {{{{}}}}).get('email_address') == email:
                                    channel_names.append(ch.get('name'))
                                    logger.info(f"    ✓ Channel exists: {{{{email}}}}")
                                    break
                        except:
                            pass
                    else:
                        logger.warning(f"    ⚠ Could not create channel for {{{{email}}}}: {{{{e}}}}")
            
            # === STEP E: Create Alert Policies ===
            logger.info("  Step E: Creating alert policies...")
            
            alert_configs = [
                ("API Enablement Alert", "api_enablement_count", "API was enabled in the organization"),
                ("Org Policy Change Alert", "org_policy_change_count", "Organization policy was modified"),
                ("Billing Budget Change Alert", "billing_budget_change_count", "Billing budget or quota was modified"),
                ("Firewall Change Alert", "firewall_change_count", "Firewall rule was modified"),
                ("Inbound RDP Alert", "inbound_rdp_count", "Inbound RDP (3389) was allowed in a firewall rule"),
                ("Project Creation Alert", "project_creation_count", "New project was created"),
            ]
            
            for alert_name, metric_name, doc_content in alert_configs:
                try:
                    policy_body = {{{{
                        "displayName": alert_name,
                        "conditions": [{{{{
                            "displayName": f"{{{{alert_name}}}} Condition",
                            "conditionThreshold": {{{{
                                "filter": f'metric.type="logging.googleapis.com/user/{{{{metric_name}}}}" AND resource.type="logging_bucket"',
                                "comparison": "COMPARISON_GT",
                                "thresholdValue": 0,
                                "duration": "0s",
                                "aggregations": [{{{{
                                    "alignmentPeriod": "60s",
                                    "perSeriesAligner": "ALIGN_SUM"
                                }}}}]
                            }}}}
                        }}}}],
                        "severity": "WARNING",
                        "combiner": "OR",
                        "notificationChannels": channel_names,
                        "documentation": {{{{
                            "content": f"## {{{{alert_name}}}}\\n\\n"
                                       f"**Description:** {{{{doc_content}}}}\\n\\n"
                                       f"**Source:** Aggregated Logs in `security-org-logs` bucket.\\n"
                                       "**Impacted Project:** `${{{{metric.label.project_id}}}}`\\n"
                                       "**Action Taken:** `${{{{metric.label.method_name}}}}` on `${{{{metric.label.service_name}}}}`\\n"
                                       "**User:** `${{{{metric.label.principal}}}}`\\n\\n"
                                       f"**Monitoring Project:** {{{{PROJECT_ID}}}}\\n\\n"
                                       f"### Next Steps\\n"
                                       f"1. Open [Cloud Logging Explorer](https://console.cloud.google.com/logs/query;query=resource.type%3D%22logging_bucket%22%20logName:%22projects/{{{{PROJECT_ID}}}}/locations/us-central1/buckets/security-org-logs%22;project={{{{PROJECT_ID}}}}) to review the event details.\\n"
                                       f"2. Verify if this change was authorized.\\n"
                                       f"3. Revert the change if it violates security policy.",
                            "mimeType": "text/markdown"
                        }}}}
                    }}}}
                    
                    monitoring_service.projects().alertPolicies().create(
                        name=project_name,
                        body=policy_body
                    ).execute()
                    logger.info(f"    ✓ Created alert: {{{{alert_name}}}}")
                    report_gen.add_action('alert_policies', alert_name)
                except Exception as e:
                    if "AlreadyExists" in str(e) or "409" in str(e):
                        try:
                            # Search for ALL policies with this display name (fixes duplicates)
                            policies_resp = monitoring_service.projects().alertPolicies().list(
                                name=project_name,
                                filter=f'displayName="{{{{alert_name}}}}"'
                            ).execute()
                            
                            found = False
                            for p in policies_resp.get('alertPolicies', []):
                                found = True
                                policy_id = p['name']
                                logger.info(f"    ✓ Updating existing alert: {{{{alert_name}}}} ({{{{policy_id.split('/')[-1]}}}})")
                                # Use patch to forcefully update severity and documentation
                                monitoring_service.projects().alertPolicies().patch(
                                    name=policy_id,
                                    updateMask="severity,documentation",
                                    body=policy_body
                                ).execute()
                            
                            if not found:
                                logger.warning(f"    ⚠ Alert was reported existing but list filter missed it. Manual check recommended.")
                            else:
                                logger.info(f"    ✓ Successfully updated alert(s) severity and details")
                        except Exception as patch_e:
                            logger.warning(f"    ⚠ Could not update alert {{{{alert_name}}}}: {{{{patch_e}}}}")
                    else:
                        logger.warning(f"    ⚠ Could not create alert {{{{alert_name}}}}: {{{{str(e)[:100]}}}}")
            
            logger.info("  ✓ Organization-level monitoring configured!")
            logger.info("  Events from ALL child projects will now trigger alerts.")
            
        except Exception as e:
            logger.error(f"  ✗ Monitoring setup failed: {{{{e}}}}")
        
        logger.info(f"✓ Step {step_num} complete")
'''

    def _generate_terraform(
        self,
        project_id: str,
        organization_id: Optional[str],
        apis_to_disable: List[str],
        apply_network_hardening: bool,
        apply_org_policies: bool,
        region_lockdown: Optional[str],
        budget_limit: Optional[float],
        alert_emails: Optional[List[str]],
        compute_monitoring: bool
    ) -> Dict[str, Any]:
        """Generate Terraform configuration"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        sections = []
        
        # Header
        sections.append(f"""# GCP Security Lockdown - Terraform
# Generated by GCP Security Hardener
# Project: {project_id}
# Generated: {timestamp}

terraform {{
  required_providers {{
    google = {{
      source  = "hashicorp/google"
      version = "~> 5.0"
    }}
  }}
}}

provider "google" {{
  project = var.project_id
  region  = var.region
}}

variable "project_id" {{
  description = "GCP Project ID"
  type        = string
  default     = "{project_id}"
}}

variable "region" {{
  description = "Default region"
  type        = string  
  default     = "{region_lockdown or 'us-central1'}"
}}
""")
        
        # API Disabling
        if apis_to_disable:
            sections.append("\n# Disabled APIs")
            for api in apis_to_disable:
                # Use a safe name for the resource
                safe_api_name = api.replace(".", "_").replace("-", "_")
                sections.append(f"""
resource "google_project_service" "disable_{safe_api_name}" {{
  project = var.project_id
  service = "{api}"
  disable_on_destroy = true
  # Explicitly disable the service
  # Note: In Terraform, removing the resource will re-enable it if not careful
  # but here we are generating a script to actively MANAGE the state to disabled.
}}""")
        
        # Firewall Rules
        if apply_network_hardening and "compute.googleapis.com" not in apis_to_disable:
            sections.append("""
# Firewall Rules - Network Hardening
resource "google_compute_firewall" "deny_external_ingress" {
  name        = "deny-external-ingress"
  network     = "default"
  description = "Block all external ingress traffic (GCP Security Hardener)"
  priority    = 100
  direction   = "INGRESS"

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_internal" {
  name        = "allow-internal"
  network     = "default"
  description = "Allow internal VPC traffic (GCP Security Hardener)"
  priority    = 90
  direction   = "INGRESS"

  allow {
    protocol = "all"
  }

  source_ranges = ["10.0.0.0/8"]
}
""")
        
        # Organization Policies
        if apply_org_policies:
            parent = f'organizations/{organization_id}' if organization_id else f'projects/{project_id}'
            sections.append(f"""
# Organization Policy - Disable Service Account Key Creation
resource "google_org_policy_policy" "disable_sa_key_creation" {{
  name   = "{parent}/policies/iam.disableServiceAccountKeyCreation"
  parent = "{parent}"

  spec {{
    rules {{
      enforce = "TRUE"
    }}
  }}
}}

# Organization Policy - Disable VM External IP Access
resource "google_org_policy_policy" "disable_vm_external_ips" {{
  name   = "{parent}/policies/compute.vmExternalIpAccess"
  parent = "{parent}"

  spec {{
    rules {{
      enforce = "TRUE"
    }}
  }}
}}
""")
        
        # Region Lockdown
        if region_lockdown:
            parent = f'organizations/{organization_id}' if organization_id else f'projects/{project_id}'
            sections.append(f"""
# Organization Policy - Resource Location Restriction
resource "google_org_policy_policy" "resource_locations" {{
  name   = "{parent}/policies/gcp.resourceLocations"
  parent = "{parent}"

  spec {{
    rules {{
      values {{
        allowed_values = ["{region_lockdown}"]
      }}
    }}
  }}
}}
""")
        
        # Compute Monitoring
        if compute_monitoring and alert_emails:
            sections.append(f"""
# Monitoring - Email Notification Channels
resource "google_monitoring_notification_channel" "security_alerts" {{
  for_each     = toset({json.dumps(alert_emails)})
  display_name = "GCP Security Hardener - ${{each.value}}"
  type         = "email"
  
  labels = {{
    email_address = each.value
  }}
}}

resource "google_monitoring_alert_policy" "vm_creation" {{
  display_name = "VM Instance Created"
  combiner     = "OR"
  
  notification_channels = [for c in google_monitoring_notification_channel.security_alerts : c.id]
  
  documentation {{
    content = "A new VM instance was created"
  }}
  
  conditions {{
    display_name = "VM created"
    condition_threshold {{
      filter     = "resource.type = \\"gce_instance\\" AND metric.type = \\"compute.googleapis.com/instance/disk/write_bytes_count\\""
      duration   = "60s"
      
      comparison = "COMPARISON_GT"
      
      aggregations {{
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }}
    }}
  }}
}}
""")

        # Add extended alerts loop for Terraform
        for i, alert in enumerate(EXTENDED_ALERTS):
            # Escape filter quotes for Terraform string
            tf_filter = alert['filter'].replace('"', '\\"')
            
            sections.append(f"""
resource "google_monitoring_alert_policy" "extended_alert_{{i}}" {{
  display_name = "{{alert['display_name']}}"
  combiner     = "OR"
  
  notification_channels = [for c in google_monitoring_notification_channel.security_alerts : c.id]
  
  documentation {{
    content = "{{alert['doc_content']}}"
  }}
  
  conditions {{
    display_name = "{{alert['condition_name']}}"
    condition_matched_log {{
      filter = "{{tf_filter}}"
    }}
  }}
}}
""")
        
        script = "\n".join(sections)
        script_hash = hashlib.sha256(script.encode()).hexdigest()
        
        return {
            "script": script,
            "script_hash": script_hash,
            "summary": {
                "format": "terraform",
                "resources": len([s for s in sections if "resource" in s]),
            },
            "estimated_duration": "1-2 minutes (terraform apply)",
            "warnings": ["Review Terraform plan before applying"]
        }
    
    def _generate_pulumi(
        self,
        project_id: str,
        organization_id: Optional[str],
        apis_to_disable: List[str],
        apply_network_hardening: bool,
        apply_org_policies: bool,
        region_lockdown: Optional[str],
        budget_limit: Optional[float],
        alert_emails: Optional[List[str]],
        compute_monitoring: bool
    ) -> Dict[str, Any]:
        """Generate Pulumi program (Python)"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        sections = []
        
        # Header and imports
        sections.append(f'''"""
GCP Security Lockdown - Pulumi Program
Generated by GCP Security Hardener

Project: {project_id}
Generated: {timestamp}
"""
import pulumi
import pulumi_gcp as gcp

# Configuration
config = pulumi.Config()
project_id = config.get("project_id") or "{project_id}"
region = config.get("region") or "{region_lockdown or 'us-central1'}"
alert_emails = {alert_emails}

# Disabled APIs
apis_to_disable = {json.dumps(apis_to_disable)}
for api in apis_to_disable:
    safe_name = api.replace(".", "-")
    gcp.projects.Service(f"disable-{{safe_name}}",
        project=project_id,
        service=api,
        disable_on_destroy=True
    )
''')
        
        # Firewall Rules
        if apply_network_hardening and "compute.googleapis.com" not in apis_to_disable:
            sections.append('''
# Firewall Rules - Network Hardening
deny_external = gcp.compute.Firewall("deny-external-ingress",
    network="default",
    description="Block all external ingress traffic (GCP Security Hardener)",
    priority=100,
    direction="INGRESS",
    denies=[gcp.compute.FirewallDenyArgs(
        protocol="all",
    )],
    source_ranges=["0.0.0.0/0"]
)

allow_internal = gcp.compute.Firewall("allow-internal",
    network="default",
    description="Allow internal VPC traffic (GCP Security Hardener)",
    priority=90,
    direction="INGRESS",
    allows=[gcp.compute.FirewallAllowArgs(
        protocol="all",
    )],
    source_ranges=["10.0.0.0/8"]
)
''')
        
        # Organization Policies
        if apply_org_policies:
            parent = f'organizations/{organization_id}' if organization_id else f'projects/{project_id}'
            sections.append(f'''
# Organization Policy - Disable Service Account Key Creation
disable_sa_keys = gcp.orgpolicy.Policy("disable-sa-key-creation",
    name="{parent}/policies/iam.disableServiceAccountKeyCreation",
    parent="{parent}",
    spec=gcp.orgpolicy.PolicySpecArgs(
        rules=[gcp.orgpolicy.PolicySpecRuleArgs(
            enforce="TRUE",
        )],
    )
)

# Organization Policy - Disable VM External IP Access
disable_external_ips = gcp.orgpolicy.Policy("disable-vm-external-ips",
    name="{parent}/policies/compute.vmExternalIpAccess",
    parent="{parent}",
    spec=gcp.orgpolicy.PolicySpecArgs(
        rules=[gcp.orgpolicy.PolicySpecRuleArgs(
            enforce="TRUE",
        )],
    )
)
''')
        
        # Region Lockdown
        if region_lockdown:
            parent = f'organizations/{organization_id}' if organization_id else f'projects/{project_id}'
            sections.append(f'''
# Organization Policy - Resource Location Restriction
resource_locations = gcp.orgpolicy.Policy("resource-locations",
    name="{parent}/policies/gcp.resourceLocations",
    parent="{parent}",
    spec=gcp.orgpolicy.PolicySpecArgs(
        rules=[gcp.orgpolicy.PolicySpecRuleArgs(
            values=gcp.orgpolicy.PolicySpecRuleStringValuesArgs(
                allowed_values=["{region_lockdown}"],
            ),
        )],
    )
)
''')
        
        # Monitoring
        if compute_monitoring and alert_emails:
            sections.append(f'''
# Notification Channels
channel_ids = []
alert_emails_list = {alert_emails}

for i, email in enumerate(alert_emails_list):
    channel = gcp.monitoring.NotificationChannel(f"security-alerts-{{i}}",
        display_name=f"GCP Security Hardener - {{email}}",
        type="email",
        labels={{
            "email_address": email,
        }}
    )
    channel_ids.append(channel.name)

# Alert Policy
vm_creation_alert = gcp.monitoring.AlertPolicy("vm-creation-alert",
    display_name="VM Instance Created",
    combiner="OR",
    notification_channels=channel_ids,
    documentation=gcp.monitoring.AlertPolicyDocumentationArgs(
        content="A new VM instance was created",
    ),
    conditions=[gcp.monitoring.AlertPolicyConditionArgs(
        display_name="VM created",
        condition_threshold=gcp.monitoring.AlertPolicyConditionConditionThresholdArgs(
            filter='resource.type = "gce_instance" AND metric.type = "compute.googleapis.com/instance/disk/write_bytes_count"',
            duration="60s",
            comparison="COMPARISON_GT",
            threshold_value=1,
            aggregations=[gcp.monitoring.AlertPolicyConditionConditionThresholdAggregationArgs(
                alignment_period="60s",
                per_series_aligner="ALIGN_RATE",
            )],
        ),
    )]
)

# Extended Alerts
for i, alert in enumerate(EXTENDED_ALERTS):
    safe_display_name = alert['display_name'].lower().replace(" ", "_")
    
    gcp.monitoring.AlertPolicy(f"extended-alert-{{i}}",
        display_name=alert['display_name'],
        combiner="OR",
        notification_channels=channel_ids,
        documentation=gcp.monitoring.AlertPolicyDocumentationArgs(
            content=alert['doc_content'],
        ),
        conditions=[gcp.monitoring.AlertPolicyConditionArgs(
            display_name=alert['condition_name'],
            condition_matched_log=gcp.monitoring.AlertPolicyConditionConditionMatchedLogArgs(
                filter=alert['filter'],
            ),
        )]
    )
''')
        
        # Exports
        sections.append('''
# Export resource names
pulumi.export("firewall_rules", {
    "deny_external": deny_external.name if 'deny_external' in locals() else None,
    "allow_internal": allow_internal.name if 'allow_internal' in locals() else None,
})
''')
        
        script = "\n".join(sections)
        script_hash = hashlib.sha256(script.encode()).hexdigest()
        
        return {
            "script": script,
            "script_hash": script_hash,
            "summary": {
                "format": "pulumi",
                "language": "python",
                "resources": script.count("gcp."),
            },
            "estimated_duration": "1-2 minutes (pulumi up)",
            "warnings": ["Review Pulumi preview before applying"]
        }
