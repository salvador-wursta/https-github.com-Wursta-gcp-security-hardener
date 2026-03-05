"""
FinOps Protection Scanner Service
Focuses on Anti-Hijacking, Billing Segregation, and "Anti-Build" Constraints.
"""
import logging
from typing import Dict, Any, List, Optional
from app.services.gcp_client import GCPClient
from app.models.scan_models import RiskCard, RiskLevel

logger = logging.getLogger(__name__)

class FinOpsScannerService:
    """
    Dedicated scanner for FinOps Security & Anti-Hijacking.
    This scanner specifically looks for:
    1. Financial Segregation of Duties (Billing Admin vs Tech)
    2. "Anti-Build" Constraints (Preventing unauthorized resource creation)
    3. Real-Time "Build" Alerts (Log-based)
    """
    
    def __init__(self, gcp_client: GCPClient):
        self.gcp_client = gcp_client

    def run_finops_scan(self, organization_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Run the full suite of FinOps scans for the current project.
        """
        logger.info(f"Starting FinOps Scan for project {self.gcp_client.project_id} (Org: {organization_id})")
        risks: List[RiskCard] = []
        
        # 1. Domain A: Financial Segregation & Access Governance
        risks.extend(self._scan_iam_segregation(organization_id))
        
        # 2. Domain B: Anti-Build Constraints
        risks.extend(self._scan_build_constraints(organization_id))
        
        # 3. Domain C: Real-Time Alerts & Quotas
        risks.extend(self._scan_realtime_alerts())
        risks.extend(self._scan_quota_safety())

        # 4. Domain D: Super Admin Hygiene (MFA & Org Admins)
        risks.extend(self._scan_org_hygiene(organization_id))

        logger.info(f"FinOps Scan complete. Found {len(risks)} risks.")
        
        # Summarize by Severity
        summary = {
            "critical": sum(1 for r in risks if r.risk_level == RiskLevel.CRITICAL),
            "high": sum(1 for r in risks if r.risk_level == RiskLevel.HIGH),
            "medium": sum(1 for r in risks if r.risk_level == RiskLevel.MEDIUM),
            "low": sum(1 for r in risks if r.risk_level == RiskLevel.LOW),
            "total": len(risks)
        }

        return {
            "risks": risks,
            "summary": summary,
            "scan_type": "finops"
        }

    def _scan_iam_segregation(self, organization_id: Optional[str]) -> List[RiskCard]:
        """
        Domain A: Check if Billing Admins are segregated from Technical/Owner roles.
        """
        risks = []
        try:
            # Fetch Policy (Project or Org level if possible, but focused on Project Context mostly for the scan run)
            # Ideally checks Org Policy for deeper analysis, but we start with Project IAM
            policy = self.gcp_client.get_iam_policy(project_id=self.gcp_client.project_id)
            bindings = policy.get('bindings', [])
            
            # Map Members to Roles
            member_roles = {}
            for binding in bindings:
                role = binding.get('role')
                members = binding.get('members', [])
                for m in members:
                    if m not in member_roles:
                        member_roles[m] = set()
                    member_roles[m].add(role)

            for member, roles in member_roles.items():
                is_billing_admin = "roles/billing.admin" in roles
                is_owner = "roles/owner" in roles or "roles/editor" in roles
                is_tech_admin = any(r.startswith("roles/compute.admin") or r.startswith("roles/iam.serviceAccountAdmin") for r in roles)

                # Toxic Combination: Billing Admin + Owner/Tech Admin
                if is_billing_admin and (is_owner or is_tech_admin):
                    start_msg = "User" if "user:" in member else ("Service Account" if "serviceAccount:" in member else "Member")
                    script_content = f"""#!/bin/bash
# Remediation Script: Fix Toxic Billing Roles
# Target User: {member}
# Action: Remove billing.admin, assign billing.viewer

ROLE_TO_REMOVE="roles/billing.admin"
ROLE_TO_ADD="roles/billing.viewer"
MEMBER="{member}"
PROJECT_ID="{self.gcp_client.project_id}"

echo "Remediating toxic combination for $MEMBER on project $PROJECT_ID..."

# Remove Admin
gcloud projects remove-iam-policy-binding $PROJECT_ID \\
    --member="$MEMBER" \\
    --role="$ROLE_TO_REMOVE"

# Add Viewer
gcloud projects add-iam-policy-binding $PROJECT_ID \\
    --member="$MEMBER" \\
    --role="$ROLE_TO_ADD"

echo "Done. User is now Billing Viewer."
"""
                    risks.append(RiskCard(
                        id=f"toxic_billing_role_{member.replace(':', '_')}",
                        title=f"Toxic Combination: {start_msg} has Billing Admin + Tech Admin",
                        description=f"{member} holds both 'Billing Administrator' and high-privilege technical roles (Owner/Editor/Admin). This violates Segregation of Duties.",
                        risk_level=RiskLevel.HIGH,
                        category="governance",
                        recommendation="Remove 'Billing Admin'. Assign 'Billing Viewer' if cost visibility is needed.",
                        current_state={"roles": list(roles), "member": member},
                        affected_resources=[member],
                        remediation_script_filename=f"fix_billing_role_{member.split(':')[-1].split('@')[0]}.sh",
                        remediation_script_content=script_content
                    ))

        except Exception as e:
            logger.warning(f"IAM Segregation scan failed: {e}")
            
        return risks

    def _scan_build_constraints(self, organization_id: Optional[str]) -> List[RiskCard]:
        """
        Domain B: Check Org Policies (Constraint/Anti-Build)
        """
        risks = []
        constraints_to_check = [
            ("constraints/iam.disableServiceAccountKeyCreation", "Service Account Key Creation", True),
            ("constraints/resourcemanager.projects.create", "Project Creation", True),
            ("constraints/billing.restrictAccountProjectLinks", "Billing Account Linking", True),
            ("constraints/compute.restrictMachineType", "Restrict Machine Types", True),
            ("constraints/compute.vmExternalIpAccess", "Disable VM External IP", True),
            ("constraints/compute.restrictSharedVpcHostProjects", "Restrict Shared VPC Host", True)
        ]

        for constraints, name, should_be_enforced in constraints_to_check:
            try:
                # Check effective policy on the project
                policy = self.gcp_client.check_org_policy(constraints, None)
                enforced = policy.get('enforced', False)
                parent = policy.get('parent', 'unknown')
                
                # Special handling for list constraints (machine types)
                # If it's a list constraint, 'enforced' might not be the boolean we expect, need to check allowed_values
                is_list_constraint = constraints in ["constraints/compute.restrictMachineType", "constraints/compute.vmExternalIpAccess"]
                
                # Simple boolean enforcement logic for boolean constraints
                violation = False
                if not is_list_constraint:
                    if should_be_enforced and not enforced:
                        violation = True
                else:
                    # For list constraints, we assume if it's not set at all, it's open (violation)
                    # This is a simplification; robust checking would analyze the allow/deny lists
                    if not policy: 
                        violation = True

                if violation:
                     script_content = f"""#!/bin/bash
# Remediation Script: Enforce {name}
# Constraint: {constraints}

PROJECT_ID="{self.gcp_client.project_id}"

echo "Enforcing {constraints} on project $PROJECT_ID..."

if [[ "{constraints}" == "constraints/compute.restrictMachineType" ]]; then
    # Allow only E2 Micro and N2 Standard 2
    gcloud resource-manager org-policies allow \\
        {constraints} \\
        --project=$PROJECT_ID \\
        --allowed-values=e2-micro,n2-standard-2
else
    # Standard Boolean Enforcement
    gcloud resource-manager org-policies enable-enforce \\
        {constraints} \\
        --project=$PROJECT_ID
fi

echo "Constraint enforced."
"""
                     risks.append(RiskCard(
                        id=f"missing_constraint_{constraints.split('/')[-1]}",
                        title=f"Missing Constraint: {name}",
                        description=f"The organization policy '{constraints}' is NOT enforced. Use restrictions are critical for 'Anti-Build' protection.",
                        risk_level=RiskLevel.HIGH,
                        category="governance",
                        recommendation=f"Enforce '{constraints}' in Organization Policies.",
                        current_state={"enforced": False, "scope": parent},
                        affected_resources=["Organization Policy"],
                        remediation_script_filename=f"enforce_{constraints.split('/')[-1]}.sh",
                        remediation_script_content=script_content
                    ))

            except Exception as e:
                logger.warning(f"Constraint scan {constraints} failed: {e}")

        return risks

    def _scan_realtime_alerts(self) -> List[RiskCard]:
        """
        Domain C: Check for Log-Based Alerts on 'Build' events
        """
        risks = []
        try:
            metrics = self.gcp_client.list_log_metrics()
            # We look for filters containing specific API calls
            critical_events = [
                ("google.iam.admin.v1.CreateServiceAccount", "SA Creation Alert"),
                ("google.iam.admin.v1.CreateServiceAccountKey", "SA Key Creation Alert"),
                ("serviceusage.services.enable", "API Enablement Alert"),
                ("beta.compute.instances.insert", "VM Creation Burst Alert")
            ]

            found_events = set()
            for m in metrics:
                f_str = m.get('filter', '')
                for event, tag in critical_events:
                    if event in f_str:
                        found_events.add(tag)
            
            missing_events = [tag for _, tag in critical_events if tag not in found_events]

            if missing_events:
                 script_content = """import argparse
from google.cloud import logging_v2
from google.cloud import monitoring_v3

def create_alert(project_id):
    # Setup Logic for Realtime Alerts
    # 1. Create Log Metric
    # 2. Create Alert Policy
    print(f"Applying Free-Tier Realtime Alerts to {project_id}...")
    # (Simplified for template)
    print("Please run this with valid credentials to create Log Metrics.")

if __name__ == "__main__":
    import os
    create_alert(os.environ.get("GOOGLE_CLOUD_PROJECT"))
"""
                 risks.append(RiskCard(
                        id="missing_realtime_build_alerts",
                        title=f"Missing Real-Time Anti-Hijack Alerts",
                        description=f"No Log-Based Metrics found for critical build events: {', '.join(missing_events)}. Billing alerts are too slow to stop a hijacker.",
                        risk_level=RiskLevel.HIGH,
                        category="monitoring",
                        recommendation="Configure Log-Based Alerts regarding Build Events and enable free Cost Anomaly Detection in Billing Console.",
                        current_state={"missing_alerts": missing_events},
                        affected_resources=["Cloud Logging", "Billing Console"],
                        remediation_script_filename="setup_realtime_alerts.py",
                        remediation_script_content=script_content
                    ))

        except Exception as e:
            logger.warning(f"Real-time alert scan failed: {e}")

        return risks

    def _scan_quota_safety(self) -> List[RiskCard]:
        """
        Scan for Safety Gaps in Quotas (specifically GPU/CPU)
        """
        risks = []
        try:
             # Re-use Quota Service logic if possible, or direct client call
             from app.services.quota_service import QuotaService
             qs = QuotaService(self.gcp_client.credentials, self.gcp_client.project_id)
             gpu_info = qs.get_gpu_quotas()
             
             total_limit = gpu_info.get('total', 0)
             if total_limit > 0:
                 script_content = f"""#!/bin/bash
# Clamp GPU Quotas
PROJECT_ID="{self.gcp_client.project_id}"
echo "Clamping GPU Quotas for $PROJECT_ID..."
# Logic to update quotas
echo "Please request quota decrease via Console or API"
"""
                 risks.append(RiskCard(
                        id="finops_gpu_safety_gap",
                        title=f"GPU Quota Safety Gap Detected ({total_limit})",
                        description=f"Project has a Global GPU quota of {total_limit}. Unless you are actively training models, this should be 0 to preventing cryptojacking.",
                        risk_level=RiskLevel.HIGH,
                        category="quota",
                        recommendation="Clamp GPU quotas to 0 via the Quotas page.",
                        current_state={"quota": total_limit},
                        affected_resources=["Compute Engine Quotas"],
                        remediation_script_filename="clamp_gpu_quotas.sh",
                        remediation_script_content=script_content
                    ))

        except Exception as e:
             logger.warning(f"Quota safety scan failed: {e}")
        return risks

    def _scan_org_hygiene(self, organization_id: Optional[str]) -> List[RiskCard]:
        """
        Domain D: Super Admin Hygiene & MFA
        """
        risks = []
        try:
            # 1. Check permissions (Org Admin Count)
            # Need to get IAM policy for Organization if ID is available
            if organization_id:
                policy = self.gcp_client.get_iam_policy(organization_id=organization_id)
                bindings = policy.get('bindings', [])
                
                org_admins = []
                for b in bindings:
                    if b.get('role') == 'roles/resourcemanager.organizationAdmin':
                        org_admins = b.get('members', [])
                        break
                
                # Risk 1: Service Accounts as Org Admin
                sa_admins = [m for m in org_admins if "serviceAccount:" in m]
                if sa_admins:
                    script_content = f"""#!/bin/bash
# Remove Service Account from Org Admin
# Target: {sa_admins[0]}
ORG_ID="{organization_id}"
MEMBER="{sa_admins[0]}"

echo "Removing Org Admin from $MEMBER..."
gcloud organizations remove-iam-policy-binding $ORG_ID \\
    --member="$MEMBER" \\
    --role="roles/resourcemanager.organizationAdmin"
"""
                    risks.append(RiskCard(
                        id="sa_org_admin_detected",
                        title=f"Service Account has Org Admin ({len(sa_admins)})",
                        description=f"Service Accounts ({', '.join(sa_admins[:3])}) have Organization Admin permissions. This is a massive security risk. SAs should generally have least-privilege.",
                        risk_level=RiskLevel.CRITICAL,
                        category="governance",
                        recommendation="Remove Org Admin from Service Accounts immediately.",
                        current_state={"sa_admins": sa_admins},
                        affected_resources=sa_admins,
                        remediation_script_filename="remove_sa_org_admin.sh",
                        remediation_script_content=script_content
                    ))

                # Risk 2: Too many admins
                if len(org_admins) > 3:
                     risks.append(RiskCard(
                        id="excessive_org_admins",
                        title=f"Excessive Org Admins ({len(org_admins)})",
                        description=f"Found {len(org_admins)} Organization Admins. Recommended max is 2-3.",
                        risk_level=RiskLevel.MEDIUM,
                        category="governance",
                        recommendation="Review and reduce Org Admin count.",
                        current_state={"count": len(org_admins)},
                        affected_resources=org_admins
                    ))
            else:
                # If no Org ID, we can't check Org IAM, but we can check finding below (Project level)
                pass

            # 2. MFA Check (via SCC)
            # We query SCC for "MFA_NOT_ENFORCED"
            # Note: list_scc_findings handles the "MFA_NOT_ENFORCED" filter if org_id is passed
            findings = self.gcp_client.list_scc_findings(
                project_id=self.gcp_client.project_id, 
                organization_id=organization_id
            )
            
            mfa_finding = next((f for f in findings if "MFA" in f.get('category', '').upper()), None)
            
            if mfa_finding:
                risks.append(RiskCard(
                    id="mfa_not_enforced_scc",
                    title="MFA Not Enforced (SCC Confirmed)",
                    description="Security Command Center found 'MFA_NOT_ENFORCED' or similar finding. MFA is critical for preventing account takeover.",
                    risk_level=RiskLevel.CRITICAL,
                    category="iam",
                    recommendation="Enable MFA in Google Workspace or Cloud Identity.",
                    current_state={"state": mfa_finding.get('state'), "finding": mfa_finding.get('resource_name')},
                    affected_resources=[mfa_finding.get('resource_name', 'Organization')]
                ))

        except Exception as e:
             logger.warning(f"Org Hygiene scan failed: {e}")
        return risks
