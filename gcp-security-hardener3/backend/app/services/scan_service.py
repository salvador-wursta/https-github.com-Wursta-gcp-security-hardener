"""
Deep Scan Service - Performs comprehensive security analysis
Security: All sensitive data handling follows secure practices
"""
import logging
import concurrent.futures
from typing import List, Dict, Any, Tuple
from datetime import datetime
from app.models.scan_models import (
    RiskCard, RiskLevel, ScanResponse, BillingInfo, 
    GPUQuotaInfo, ComputeInstanceInfo, UnusedAPIsInfo,
    SCCInfo, SCCFinding, InventorySummary
)
from app.services.gcp_client import GCPClient
from app.services.billing_service import BillingService
from app.services.quota_service import QuotaService
from app.services.compute_instance_service import ComputeInstanceService
from app.services.billing_analysis_service import BillingAnalysisService
from app.services.api_analysis_service import ApiAnalysisService
from app.services.iam_analysis_service import IamAnalysisService
from app.services.firewall_service import FirewallService
from app.services.monitoring_analysis_service import MonitoringAnalysisService
from app.services.privilege_manager_service import PrivilegeManagerService
from app.services.change_control_audit_service import ChangeControlAuditService
from app.services.iam_narrative_service import IamNarrativeService
from app.services.asset_inventory_service import AssetInventoryService
from app.services.security_architect_service import SecurityArchitectService
from app.services.ai_service import AIService
from app.services.resource_graph_service import ResourceGraphService
from app.services.finops_scanner_service import FinOpsScannerService

logger = logging.getLogger(__name__)


class ScanService:
    """Service for performing deep security scans with parallel execution"""
    
    def __init__(self, gcp_client: GCPClient):
        self.gcp_client = gcp_client
    
    def perform_scan(self, organization_id: str = None, scan_modules: List[str] = None) -> ScanResponse:
        """
        Perform comprehensive security scan
        
        Args:
            organization_id: Optional organization ID for org-level checks
            scan_modules: Optional list of modules to scan. If None, scans all.
            
        Returns:
            ScanResponse with all findings
        """
        risks: List[RiskCard] = []
        errors: List[str] = []
        
        # Result containers
        enabled_apis: List[str] = []
        api_analysis_result: Dict[str, Any] = None
        unused_apis_model: UnusedAPIsInfo = None
        billing_info: BillingInfo = None
        gpu_quota_info: GPUQuotaInfo = None
        compute_instance_info: ComputeInstanceInfo = None
        iam_analysis_result: Dict[str, Any] = None
        monitoring_results: Dict[str, Any] = None
        change_control_info: Dict[str, Any] = None
        scc_info_model: SCCInfo = None
        architecture_info_model: Any = None # ArchitectureInfo
        inventory_summary_model: InventorySummary = None
        organization_name: str = None
        all_assets: List[Dict[str, Any]] = []
        
        # Initialize Services (SaaS Refactor: Keyless identity-based AI)
        ai_service = AIService()
        asset_service = AssetInventoryService(self.gcp_client)
        architect_service = SecurityArchitectService(asset_service, ai_service)
        
        # 0. Discovery: Try to find Organization ID/Name if not provided
        if not organization_id:
            try:
                 logger.info("Organization ID not provided. Attempting discovery via project ancestry...")
                 ancestry = self.gcp_client.get_project_ancestry()
                 logger.info(f"Ancestry result: {ancestry}")
                 for ancestor in ancestry:
                      resource_id = ancestor.get('resourceId', {})
                      if resource_id.get('type') == 'organization':
                          organization_id = resource_id.get('id')
                          logger.info(f"Discovered Organization ID: {organization_id}")
                          break
                 if not organization_id:
                     logger.warning("No Organization ID could be found in project ancestry.")
            except Exception as e:
                 logger.warning(f"Organization discovery failed: {e}")
            
        if organization_id:
            try:
                logger.info(f"Fetching details for Organization ID: {organization_id}")
                org_details = self.gcp_client.get_organization(organization_id)
                organization_name = org_details.get('display_name')
                if organization_name:
                    logger.info(f"Resolved Organization Name: {organization_name}")
                else:
                    logger.warning(f"Could not resolve Organization Name for ID {organization_id} (missing permissions?)")
            except Exception as e:
                 logger.warning(f"Organization name resolution failed: {e}")
        
        def should_run(module_name: str) -> bool:
            if not scan_modules: 
                return True 
            return module_name in scan_modules

        # 1. Foundation: Get Enabled APIs (Synchronous - Critical Dependency)
        try:
            if should_run('api'):
                logger.info("Starting API Security analysis...")
                api_service = ApiAnalysisService(self.gcp_client)
                api_analysis_result = api_service.analyze_apis(self.gcp_client.project_id)
                
                # Extract enabled APIs list
                enabled_apis = [api.name for api in api_analysis_result.get('enabled_apis', [])]
                
                # Generate risks from analysis
                for api in api_analysis_result.get('enabled_apis', []):
                    if api.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                        risks.append(RiskCard(
                            id=f"risky_api_{api.name}",
                            title=f"Risky API Enabled: {api.display_name}",
                            description=f"We found that '{api.display_name}' is enabled. {api.reason_enabled}. "
                                        f"This presents a significant attack surface.",
                            risk_level=api.risk_level,
                            category="api",
                            recommendation=f"Disable {api.name} immediately if not strictly required.",
                            current_state={"api": api.name, "status": "enabled", "cost_est": api.monthly_cost_estimate},
                            affected_resources=[api.name]
                        ))
            else:
                logger.info("Fetching enabled APIs inventory (API module skipped)...")
                enabled_apis = self.gcp_client.get_enabled_apis()
                
        except Exception as e:
            error_msg = f"Failed to scan enabled APIs: {str(e)}"
            logger.error(error_msg)
            errors.append(error_msg)

        # 2. CAI Master Inventory & Architecture (Parallel)
        def fetch_inventory_and_arch_task():
            inv_risks = []
            inv_summary = None
            arch_info = None
            arch_findings = []
            
            try:
                if should_run('inventory') or should_run('architectural_foundations'):
                    logger.info("Fetching Master Inventory from CAI...")
                    target_types = [
                        "compute.googleapis.com/Instance", 
                        "compute.googleapis.com/Disk",
                        "compute.googleapis.com/Firewall",
                        "storage.googleapis.com/Bucket",
                        "sqladmin.googleapis.com/Instance",
                        "container.googleapis.com/Cluster",
                        "compute.googleapis.com/Address" 
                    ]
                    all_assets = asset_service.search_all_resources(
                        scope=f"projects/{self.gcp_client.project_id}", 
                        asset_types=target_types
                    )
                    
                    counts = {}
                    for asset in all_assets:
                        t = asset.get('asset_type')
                        counts[t] = counts.get(t, 0) + 1
                    
                    graph_service = ResourceGraphService(all_assets)
                    
                    inv_summary = InventorySummary(
                        total_assets=len(all_assets),
                        resource_counts=counts,
                        public_ip_count=graph_service.count_public_ips(), 
                        storage_buckets=counts.get("storage.googleapis.com/Bucket", 0),
                        sql_instances=counts.get("sqladmin.googleapis.com/Instance", 0),
                        firewall_rules=counts.get("compute.googleapis.com/Firewall", 0)
                    )
                    logger.info(f"Master Inventory: {len(all_assets)} assets found")
                    
                    # Check for Orphaned Disks
                    orphaned_disks = graph_service.find_orphaned_disks()
                    if orphaned_disks:
                        inv_risks.append(RiskCard(
                            id="orphaned_disks_cai",
                            title=f"{len(orphaned_disks)} Orphaned Disks Detected",
                            description=f"We found {len(orphaned_disks)} persistent disks that are not attached to any VM.",
                            risk_level=RiskLevel.MEDIUM,
                            category="waste",
                            recommendation="Snapshot and delete these disks if not needed.",
                            current_state={"count": len(orphaned_disks)},
                            affected_resources=[d.get('name') for d in orphaned_disks[:5]]
                        ))
                    
                    # Run Architectural Review (reusing assets)
                    if should_run('architectural_foundations'):
                         # Ensure architect_service is available in scope
                         # If it's a service method on self, use that. If it's global/local var, use that.
                         # Assuming 'architect_service' was a local var in scan_project
                         arch_info = architect_service.perform_architectural_review(
                             self.gcp_client.project_id, 
                             all_assets
                         )
                         if arch_info and arch_info.findings:
                             arch_findings = arch_info.findings

            except Exception as e:
                logger.warning(f"Inventory/Arch scan failed: {e}")
            
            return {
                'summary': inv_summary, 
                'risks': inv_risks,
                'arch_info': arch_info,
                'arch_findings': arch_findings
            }

        # 3. Parallel Execution of Independent Modules
        logger.info("Starting parallel scan execution...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            future_to_task = {}
            
            # --- Inventory & Arch (Parallel) ---
            future_to_task[executor.submit(fetch_inventory_and_arch_task)] = 'inventory_scan'

            # --- API & Billing ---
            future_to_task[executor.submit(
                self._analyze_unused_apis, enabled_apis
            )] = 'unused_apis'
            
            if should_run('billing') or should_run('waste'):
                future_to_task[executor.submit(self._analyze_waste)] = 'waste_analysis'
            
            future_to_task[executor.submit(
                self._analyze_billing_health, organization_id
            )] = 'billing_health'

            # --- IAM & Governance ---
            future_to_task[executor.submit(
                self._check_foundation_iam, organization_id
            )] = 'iam_foundation'
            
            if should_run('iam'):
                future_to_task[executor.submit(
                    self._analyze_iam_deep, organization_id
                )] = 'iam_deep'
                
                future_to_task[executor.submit(
                     self._audit_org_admin, organization_id
                )] = 'iam_admin_audit'
            
            future_to_task[executor.submit(
                self._audit_change_control
            )] = 'change_control'

            # --- Network & Compute ---
            if "compute.googleapis.com" in enabled_apis:
                future_to_task[executor.submit(self._check_legacy_firewall)] = 'legacy_firewall'
                future_to_task[executor.submit(self._check_gpu_quotas)] = 'gpu_quota'
                future_to_task[executor.submit(self._scan_compute_resources)] = 'compute_resources'
                future_to_task[executor.submit(self._analyze_firewall_config)] = 'firewall_analysis'
            
            # --- Monitoring ---
            if should_run('monitoring'):
                future_to_task[executor.submit(self._analyze_monitoring)] = 'monitoring'
                
            # --- SCC ---
            future_to_task[executor.submit(
                self._analyze_scc, organization_id
            )] = 'scc_analysis'

            # (Architectural Review logic moved into inventory_scan)
            
            future_to_task[executor.submit(
                self._analyze_billing_health, organization_id
            )] = 'billing_health'

            # --- IAM & Governance ---
            future_to_task[executor.submit(
                self._check_foundation_iam, organization_id
            )] = 'iam_foundation'
            
            if should_run('iam'):
                future_to_task[executor.submit(
                    self._analyze_iam_deep, organization_id
                )] = 'iam_deep'
                
                future_to_task[executor.submit(
                     self._audit_org_admin, organization_id
                )] = 'iam_admin_audit'
            
            future_to_task[executor.submit(
                self._audit_change_control
            )] = 'change_control'

            # --- Network & Compute ---
            if "compute.googleapis.com" in enabled_apis:
                future_to_task[executor.submit(self._check_legacy_firewall)] = 'legacy_firewall'
                future_to_task[executor.submit(self._check_gpu_quotas)] = 'gpu_quota'
                future_to_task[executor.submit(self._scan_compute_resources)] = 'compute_resources'
                future_to_task[executor.submit(self._analyze_firewall_config)] = 'firewall_analysis'
            
            # --- Monitoring ---
            if should_run('monitoring'):
                future_to_task[executor.submit(self._analyze_monitoring)] = 'monitoring'
                
            # --- SCC ---
            future_to_task[executor.submit(
                self._analyze_scc, organization_id
            )] = 'scc_analysis'

            # --- Architecture ---
            if should_run('architectural_foundations'):
                future_to_task[executor.submit(
                    architect_service.perform_architectural_review, 
                    self.gcp_client.project_id, 
                    all_assets
                )] = 'architectural_review'

            # --- Solution Scans ---
            if should_run('finops'):
                 finops_service = FinOpsScannerService(self.gcp_client)
                 future_to_task[executor.submit(
                     finops_service.run_finops_scan,
                     organization_id
                 )] = 'finops_scan'

            # --- Collect Results ---
            for future in concurrent.futures.as_completed(future_to_task):
                task_name = future_to_task[future]
                try:
                    result = future.result()
                    
                    # Handle Merged Inventory/Arch Task
                    if task_name == 'inventory_scan':
                        inventory_summary = result.get('summary')
                        if result.get('risks'):
                            risks.extend(result.get('risks'))
                            
                        # Handle Architectural Review Results inside Inventory Scan
                        if result.get('arch_info'):
                            architecture_info_model = result.get('arch_info')
                            
                        if result.get('arch_findings'):
                            for f in result.get('arch_findings'):
                                try:
                                    r_level = RiskLevel[f.severity.upper()]
                                except:
                                    r_level = RiskLevel.MEDIUM
                                
                                risks.append(RiskCard(
                                    id=f"arch_{f.title.lower().replace(' ', '_')[:20]}",
                                    title=f"Arch: {f.title}",
                                    description=f"Standard: {f.standard_violation}. {f.recommendation[:100]}...",
                                    risk_level=r_level,
                                    category="architecture",
                                    recommendation=f.recommendation,
                                    current_state={"standard": f.standard_violation},
                                    affected_resources=["Project Architecture"]
                                ))
                        continue

                    # Standard Module Processing (Dict results)
                    if isinstance(result, dict):
                        # Merge Lists
                        if result.get('risks'):
                            risks.extend(result['risks'])
                        if result.get('errors'):
                            errors.extend(result['errors'])
                            
                        # Capture Data Models
                        if task_name == 'unused_apis':
                            unused_apis_model = result.get('model')
                        elif task_name == 'billing_health':
                            billing_info = result.get('model')
                        elif task_name == 'gpu_quota':
                            gpu_quota_info = result.get('model')
                        elif task_name == 'compute_resources':
                            compute_instance_info = result.get('model')
                        elif task_name == 'iam_deep':
                            iam_analysis_result = result.get('data')
                        elif task_name == 'monitoring':
                            monitoring_results = result.get('data')
                        elif task_name == 'change_control':
                            change_control_info = result.get('data')
                        elif task_name == 'scc_analysis':
                            scc_info_model = result.get('model')
                    
                except Exception as e:
                    logger.error(f"Task {task_name} failed: {str(e)}", exc_info=True)
                    errors.append(f"{task_name} scan failed: {str(e)}")

        # 3. Post-Process: Combine Billing IAM results into Billing Info
        # The parallel billing health check does not check IAM (to keep tasks focused)
        # We need to run the Billing IAM check (which depends on billing ID)
        try:
             # If we have a billing account ID from the parallel task, we can check its IAM
             # NOTE: Making this synchronous/sequential here to avoid complexity of passing 
             # the discovered billing ID between parallel tasks.
             if billing_info and billing_info.billing_account_id:
                 iam_risks, iam_users = self._analyze_billing_iam(billing_info.billing_account_id)
                 risks.extend(iam_risks)
                 billing_info.iam_users = iam_users
        except Exception as e:
            logger.warning(f"Post-process billing IAM check failed: {str(e)}")

        # 4. Post-Process: Bridge SCC Findings to Domain Modules
        # Specifically, move MFA findings to IAM category if found
        if scc_info_model and scc_info_model.findings:
            # DEBUG: Log all categories to help diagnose mismatch
            categories = [f.category for f in scc_info_model.findings]
            logger.info(f"DEBUG: Found SCC Categories: {categories}")

            # Flexible search for ANY finding related to MFA
            mfa_finding = next((f for f in scc_info_model.findings if "MFA" in f.category.upper()), None)
            
            if mfa_finding:
                # 1. Create definitive IAM risk
                mfa_risk = RiskCard(
                    id="iam_mfa_scc_confirmed",
                    title="MFA Not Enforced",
                    description="Security Command Center has confirmed that Multi-Factor Authentication is not enforced for users in this project. NIST 800-63B requires MFA for all privileged access.",
                    risk_level=RiskLevel.CRITICAL,
                    category="iam",
                    recommendation="Enable MFA in Google Workspace / Cloud Identity immediately.",
                    current_state={"status": "Not Enforced", "source": "Security Command Center"},
                    affected_resources=[mfa_finding.resource_name]
                )
                risks.append(mfa_risk)
                
            # We can bridge other findings here if needed (e.g. key rotation)

        # Calculate summary
        summary = {
            "critical": sum(1 for r in risks if r.risk_level == RiskLevel.CRITICAL),
            "high": sum(1 for r in risks if r.risk_level == RiskLevel.HIGH),
            "medium": sum(1 for r in risks if r.risk_level == RiskLevel.MEDIUM),
            "low": sum(1 for r in risks if r.risk_level == RiskLevel.LOW),
            "info": sum(1 for r in risks if r.risk_level == RiskLevel.INFO),
            "total": len(risks)
        }
        
        return ScanResponse(
            project_id=self.gcp_client.project_id,
            organization_id=organization_id,  # Include discovered ID
            organization_name=organization_name,
            scan_timestamp=datetime.utcnow().isoformat(),
            risks=risks,
            summary=summary,
            enabled_apis=enabled_apis,
            scan_status="completed",
            errors=errors,
            billing_info=billing_info,
            gpu_quota=gpu_quota_info,
            compute_instances=compute_instance_info,
            unused_apis=unused_apis_model,
            api_analysis=api_analysis_result,
            iam_analysis=iam_analysis_result,
            monitoring_analysis=monitoring_results,
            change_control_info=change_control_info,
            scc_info=scc_info_model,
            architecture_info=architecture_info_model,
            inventory_summary=inventory_summary_model
        )

    # --- Helper Worker Methods ---

    def _analyze_unused_apis(self, enabled_apis: List[str]) -> Dict[str, Any]:
        result = {'risks': [], 'model': None}
        try:
            billing_analysis = BillingAnalysisService(self.gcp_client.credentials, self.gcp_client.project_id)
            analysis = billing_analysis.analyze_unused_apis(enabled_apis)
            
            # Create Model
            result['model'] = UnusedAPIsInfo(
                apis=analysis.get('unused_high_cost_apis', []),
                summary=analysis.get('summary', {}),
                billing_data=analysis.get('billing_data', {})
            )
            
            # Create Risks
            high_cost_apis = analysis.get('unused_high_cost_apis', [])
            if high_cost_apis:
                high_cnt = len([a for a in high_cost_apis if a['risk_level'] == 'high'])
                result['risks'].append(RiskCard(
                    id="unused_high_cost_apis",
                    title=f"{len(high_cost_apis)} High-Cost APIs Enabled",
                    description=f"We found {high_cnt} high-cost APIs enabled that appear unused. An attacker could use these to rack up large bills.",
                    risk_level=RiskLevel.HIGH if high_cnt > 0 else RiskLevel.MEDIUM,
                    category="api",
                    recommendation="Review and disable unused APIs.",
                    current_state={"high_cost_apis_enabled": len(high_cost_apis)},
                    affected_resources=[api['service'] for api in high_cost_apis[:10]]
                ))
        except Exception as e:
            logger.warning(f"Unused API analysis failed: {e}")
        return result

    def _analyze_waste(self) -> Dict[str, Any]:
        result = {'risks': []}
        try:
            recommendations = self.gcp_client.get_recommendations()
            cost_savings = [r for r in recommendations if r.get("primary_impact") == "COST"]
            
            if cost_savings:
                result['risks'].append(RiskCard(
                    id="idle_resources_detected",
                    title="Idle Resources Detected",
                    description=f"Google found {len(cost_savings)} potential cost savings. You may have forgotten resources running.",
                    risk_level=RiskLevel.MEDIUM,
                    category="waste",
                    recommendation="Review Google Cloud Recommendations.",
                    current_state={"recommendation_count": len(cost_savings)},
                    affected_resources=[r.get("name", "unknown") for r in cost_savings[:5]]
                ))
        except Exception as e:
            logger.warning(f"Waste analysis failed: {e}")
        return result

    def _analyze_billing_health(self, organization_id: str) -> Dict[str, Any]:
        result = {'risks': [], 'model': None}
        try:
            # 1. Project Info
            project_number = None
            try:
                p_info = self.gcp_client.get_project_info()
                project_number = p_info.get('project_number')
            except: pass
            
            service = BillingService(self.gcp_client.credentials, self.gcp_client.project_id, self.gcp_client)
            
            # ── STEP 1: Always call getBillingInfo (equivalent to gcloud billing projects describe)
            # This works even if the SA only has resourcemanager.projectViewer.
            # It returns: billing_account_id, billing_enabled, billing_account_full_name
            proj_billing = service.get_project_billing_info()
            billing_account_id = proj_billing.get('billing_account_id')
            billing_enabled = proj_billing.get('billing_enabled', False)
            billing_proj_error = proj_billing.get('error')
            
            billing_account_name = None
            budgets = []
            budgets_permission_denied = False  # True when list_budgets returns None (403)
            current_budget_limit = None
            budget_recommendation = None
            current_month_spend = 0.0
            prior_month_spend = 0.0
            spend_trend = "unknown"
            
            # ── STEP 2: If we have the billing account ID, try to get more details
            if billing_account_id:
                billing_account_name = service.get_billing_account_name(billing_account_id)
                raw_budgets = service.list_budgets(billing_account_id)
                # raw_budgets is None → 403 Permission Denied (external billing account)
                # raw_budgets is []   → no budgets configured
                # raw_budgets is [..] → budgets found
                budgets_permission_denied = (raw_budgets is None)
                budgets = raw_budgets if raw_budgets is not None else []  # safe for iteration
                
                # Filter Budgets
                filter_id = f"projects/{project_number}" if project_number else None
                applicable_budgets = []
                for b in budgets:
                    b_projs = b.get('projects', [])
                    if not b_projs or (filter_id and filter_id in b_projs):
                        applicable_budgets.append(b)
                
                # Determine limit
                if applicable_budgets:
                    amounts = [b.get('amount', 0) for b in applicable_budgets]
                    if amounts: current_budget_limit = max(amounts)
                
                # Recommendation
                if budgets_permission_denied:
                    budget_recommendation = "Permissions insufficient to check budgets (external billing account)."
                elif not budgets:
                    budget_recommendation = "No budgets found."
                elif not applicable_budgets:
                    budget_recommendation = "No budget applies to this project."
                else:
                    budget_recommendation = "Budget configured."

                    
                # Spending
                try:
                    s_data = service.get_monthly_spending(billing_account_id)
                    current_month_spend = s_data.get('current_month_spend', 0.0)
                    prior_month_spend = s_data.get('prior_month_spend', 0.0)
                    spend_trend = s_data.get('spend_trend', 'unknown')
                except: pass
            
            # ── STEP 3: Build Risk Cards based on what we found
            if not billing_account_id and not billing_enabled:
                # Truly no billing linked at all
                result['risks'].append(RiskCard(
                    id="no_billing_account",
                    title="No Billing Account Linked",
                    description="This project does not have a billing account linked. Without billing, you can't set up budget alerts.",
                    risk_level=RiskLevel.MEDIUM,
                    category="billing",
                    recommendation="Link a billing account to this project in the GCP Console.",
                    current_state={"billing_account": None, "billing_enabled": False}
                ))
            elif billing_account_id and not budgets and not budgets_permission_denied:
                # Billing linked but no budgets set (and we know this for sure because we had permissions to read them)
                result['risks'].append(RiskCard(
                    id="no_budgets",
                    title="No Budget Limits Configured",
                    description="A billing account is linked but no budgets are configured. Unexpected costs could accumulate without alerts.",
                    risk_level=RiskLevel.HIGH,
                    category="billing",
                    recommendation="Create a billing budget with alert thresholds to protect against runaway costs.",
                    current_state={"billing_account": billing_account_id, "budgets": []}
                ))
            
            # ── STEP 4: Always build the model — include billing info even if budget access failed
            result['model'] = BillingInfo(
                billing_account_id=billing_account_id or "",
                billing_account_name=billing_account_name,
                has_project_billing=billing_enabled,
                has_org_billing=bool(organization_id),
                budgets=budgets,  # Always a list now (None handled via budgets_permission_denied flag)
                current_budget_limit=current_budget_limit,
                budget_recommendation=budget_recommendation,
                current_month_spend=current_month_spend,
                prior_month_spend=prior_month_spend,
                spend_trend=spend_trend
            )
            
        except Exception as e:
            logger.error(f"Billing health check failed: {e}")
        return result


    def _check_foundation_iam(self, organization_id: str) -> Dict[str, Any]:
        result = {'risks': []}
        try:
            # SA Key Policy
            sa_policy = self.gcp_client.check_org_policy("constraints/iam.disableServiceAccountKeyCreation", organization_id)
            if not sa_policy.get("enforced") and not organization_id:
                # Check project level
                sa_policy = self.gcp_client.check_org_policy("constraints/iam.disableServiceAccountKeyCreation", None)
            
            if not sa_policy.get("enforced"):
                result['risks'].append(RiskCard(
                    id="service_account_keys_allowed",
                    title="Service Account Keys Can Be Created",
                    description="Service account key creation is enabled. These are long-lived credentials that are often leaked.",
                    risk_level=RiskLevel.CRITICAL, # Escalate to critical (common breach vector)
                    category="iam",
                    recommendation="Enforce constraint to disable SA key creation.",
                    current_state={"policy_enforced": False},
                    affected_resources=["Project IAM"]
                ))
        except Exception as e:
            logger.warning(f"Foundation IAM check failed: {e}")
        return result

    def _check_legacy_firewall(self) -> Dict[str, Any]:
        result = {'risks': []}
        try:
            fw_service = FirewallService(self.gcp_client.credentials, self.gcp_client.project_id)
            rules = fw_service.list_firewall_rules()
            deny_exists = any(r.get('name') == 'deny-external-ingress' for r in rules)
            
            if not deny_exists:
                result['risks'].append(RiskCard(
                    id="no_network_hardening",
                    title="No 'deny-external-ingress' Rule",
                    description="Default firewall rules do not explicitly block all external ingress. This implies a 'default-allow' posture if other rules are missing.",
                    risk_level=RiskLevel.CRITICAL, # Escalate - fundamental control
                    category="network",
                    recommendation="Create a deny-all external ingress rule.",
                    current_state={"external_access_blocked": False},
                    affected_resources=["VPC Network"]
                ))
        except Exception as e:
            logger.warning(f"Legacy firewall check failed: {e}")
        return result

    def _check_gpu_quotas(self) -> Dict[str, Any]:
        result = {'risks': [], 'model': None}
        try:
            service = QuotaService(self.gcp_client.credentials, self.gcp_client.project_id)
            quotas = service.get_gpu_quotas()
            total = quotas.get('total', 0)
            
            risk_level = "safe"
            if total > 10: risk_level = "high"
            elif total > 0: risk_level = "warning"
            
            result['model'] = GPUQuotaInfo(
                total_quota=total,
                regions_with_quota=len([r for r in quotas.get('regions', []) if r['limit'] > 0]),
                quota_by_region=quotas.get('regions', []),
                summary=quotas.get('summary'),
                risk_level=risk_level,
                recommendation="Set to 0 if not used."
            )
            
            if total > 0:
                result['risks'].append(RiskCard(
                    id="gpu_quota_unlimited",
                    title=f"GPU Quota is {total} (Should be 0)",
                    description="High GPU quotas increase risk of expensive crypto-mining attacks.",
                    risk_level=RiskLevel.HIGH if total > 10 else RiskLevel.MEDIUM,
                    category="quota",
                    recommendation="Set GPU quota to 0.",
                    current_state={"total_quota": total},
                    affected_resources=["Compute Quotas"]
                ))
        except Exception as e:
             logger.warning(f"GPU Quota check failed: {e}")
        return result

    def _scan_compute_resources(self) -> Dict[str, Any]:
        # Combines Instance Scan (N2/C2) and Security Services (IDS/Armor)
        result = {'risks': [], 'model': None}
        try:
            service = ComputeInstanceService(self.gcp_client.credentials, self.gcp_client.project_id)
            
            # 1. Instance Scan
            scan = service.scan_instances()
            rec = service.generate_restriction_recommendation(scan)
            policy = service.check_restriction_policy()
            
            result['model'] = ComputeInstanceInfo(
                n2_instances=scan.get('n2_instances', 0),
                c2_instances=scan.get('c2_instances', 0),
                total_restricted_instances=scan.get('total_restricted_instances', 0),
                instances_by_zone=scan.get('instances_by_zone', []),
                policy_enabled=policy,
                risk_level=rec.get('risk_level', 'info'),
                recommendation=rec.get('recommendation')
            )
            
            # 2. IDS/Armor
            external_ips = service.detect_external_ips()
            sec_services = service.check_security_services()
            
            if external_ips:
                # Inventory of Exposed IPs
                ip_details = [f"{i['name']}: {i['external_ip']} ({i.get('type', 'Unknown')})" for i in external_ips]
                result['risks'].append(RiskCard(
                    id="exposed_ip_inventory",
                    title=f"Exposed External IPs Detected ({len(external_ips)})",
                    description=f"Found {len(external_ips)} instances with public IP addresses. These are directly reachable from the internet.",
                    risk_level=RiskLevel.MEDIUM,
                    category="network",
                    recommendation="Review necessity. Prefer Cloud NAT for outbound and Load Balancers for inbound access.",
                    current_state={"count": len(external_ips)},
                    affected_resources=ip_details[:10]
                ))

                missing = []
                if not sec_services["cloud_ids"]["enabled"]: missing.append("Cloud IDS")
                if not sec_services["cloud_armor"]["enabled"]: missing.append("Cloud Armor")
                
                if missing:
                    result['risks'].append(RiskCard(
                        id="missing_advanced_security",
                        title="Advanced Network Security Missing",
                        description=f"Public-facing resources found but missing: {', '.join(missing)}.",
                        risk_level=RiskLevel.HIGH, # Could be CRITICAL if open to world, sticking to HIGH for now
                        category="network",
                        recommendation="Enable Cloud IDS/Armor.",
                        is_fixable=False,
                        current_state={"missing": missing},
                        affected_resources=[i['name'] for i in external_ips[:5]]
                    ))
                else:
                     result['risks'].append(RiskCard(
                        id="advanced_security_verified",
                        title="✓ Advanced Network Defense Active",
                        description="External IPs are protected by IDS/Armor.",
                        risk_level=RiskLevel.INFO,
                        category="network",
                        recommendation="Maintain protections.",
                        is_fixable=False,
                        affected_resources=["Cloud IDS", "Cloud Armor"]
                    ))
        except Exception as e:
            logger.warning(f"Compute resource scan failed: {e}")
        return result

    def _analyze_firewall_config(self) -> Dict[str, Any]:
        result = {'risks': []}
        try:
            service = FirewallService(self.gcp_client.credentials, self.gcp_client.project_id)
            analysis = service.inspect_firewall_configuration()
            status = analysis.get('status')
            
            if status in ['RISK', 'VULNERABILITY']:
                # Analyze severity based on 'reason'
                severity = RiskLevel.HIGH
                reason = analysis.get('reason', '')
                if "0.0.0.0/0" in reason and ("22" in reason or "3389" in reason):
                     severity = RiskLevel.CRITICAL # Public Management Ports
                
                result['risks'].append(RiskCard(
                    id=f"firewall_config_{status.lower()}",
                    title="VPC Firewall Risk/Vulnerability",
                    description=reason,
                    risk_level=severity,
                    category="network",
                    recommendation=analysis.get('recommendation'),
                    is_fixable=False,
                    current_state={"status": status},
                    affected_resources=["VPC Firewall"]
                ))
            elif status == 'SECURED':
                 result['risks'].append(RiskCard(
                    id="firewall_config_secured",
                    title="✓ VPC Firewall is Secured",
                    description=analysis.get('reason'),
                    risk_level=RiskLevel.INFO,
                    category="network",
                    recommendation=analysis.get('recommendation'),
                    is_fixable=False,
                    current_state={"status": "SECURED"}
                ))
        except Exception as e:
            logger.warning(f"Firewall analysis failed: {e}")
        return result

    def _analyze_scc(self, organization_id: str) -> Dict[str, Any]:
        result = {'risks': [], 'model': None}
        try:
            # If no org ID provided, try to discover it
            if not organization_id:
                try:
                    logger.info("No organization ID provided for SCC check - attempting discovery...")
                    ancestry = self.gcp_client.get_project_ancestry()
                    for ancestor in ancestry:
                         resource_id = ancestor.get('resourceId', {})
                         if resource_id.get('type') == 'organization':
                             organization_id = resource_id.get('id')
                             logger.info(f"Discovered Organization ID: {organization_id}")
                             break
                except Exception as discovery_error:
                    logger.warning(f"Failed to discover organization ID: {discovery_error}")

            status = "UNKNOWN"
            tier = "UNKNOWN"
            
            if organization_id:
                settings = self.gcp_client.get_scc_settings(organization_id)
                status = settings.get("status", "UNKNOWN")
                tier = settings.get("tier", "UNKNOWN")
            else:
                logger.info("No Organization ID found - SCC is Organization-level service. Status UNKNOWN.")
                
            findings_data = self.gcp_client.list_scc_findings(self.gcp_client.project_id, organization_id=organization_id)
            
            scc_findings = []
            for f in findings_data:
                scc_findings.append(SCCFinding(
                    category=f.get('category', 'Unknown'),
                    state=f.get('state', 'ACTIVE'),
                    severity=f.get('severity', 'UNKNOWN'),
                    event_time=f.get('event_time', ''),
                    resource_name=f.get('resource_name', ''),
                    external_uri=f.get('external_uri', '')
                ))
            
            result['model'] = SCCInfo(status=status, tier=tier, findings=scc_findings)
            
            if scc_findings:
                high_sev = sum(1 for f in scc_findings if f.severity in ['CRITICAL', 'HIGH'])
                if high_sev > 0:
                     result['risks'].append(RiskCard(
                        id="scc_findings_detected",
                        title=f"SCC: {high_sev} High/Critical Issues",
                        description=f"Security Command Center found {len(scc_findings)} issues.",
                        risk_level=RiskLevel.HIGH,
                        category="scc",
                        recommendation="Review SCC dashboard.",
                        current_state={"finding_count": len(scc_findings)},
                        affected_resources=[f.category for f in scc_findings[:5]]
                    ))
        except Exception as e:
            logger.warning(f"SCC analysis failed: {e}")
        return result

    def _analyze_iam_deep(self, organization_id: str) -> Dict[str, Any]:
        result = {'risks': [], 'data': None}
        try:
            iam_service = IamAnalysisService(self.gcp_client)
            iam_data = iam_service.analyze_iam(self.gcp_client.project_id)
            
            # Assign early so frontend gets data even if narrative/risk parsing crashes
            result['data'] = iam_data
            
            try:
                # Narratives
                narrative_service = IamNarrativeService()
                iam_data['principal_narratives'] = narrative_service.generate_narratives(iam_data)
                
                # Risks
                basic = iam_data.get('basic_roles', [])
                if basic:
                    # Check if any are specifically 'roles/owner' to warrant CRITICAL
                    has_owner = any(r.get('role') == 'roles/owner' for r in basic)
                    risk_level = RiskLevel.CRITICAL if has_owner else RiskLevel.HIGH
                    
                    result['risks'].append(RiskCard(
                        id="iam_basic_roles",
                        title="Primitive IAM Roles Detected",
                        description=f"{len(basic)} users found with Owner/Editor roles. 'Owner' roles are extremely dangerous.",
                        risk_level=risk_level,
                        category="iam",
                        recommendation="Use predefined roles.",
                        current_state={"count": len(basic)},
                        affected_resources=[r['member'] for r in basic[:5]]
                    ))

                keys = iam_data.get('service_account_keys', [])
                if keys:
                    result['risks'].append(RiskCard(
                        id="iam_sa_keys",
                        title="Risky Service Account Keys",
                        description=f"{len(keys)} user-managed keys > 90 days found. User-managed keys are a primary vector for compromise.",
                        risk_level=RiskLevel.CRITICAL, # Escalated to CRITICAL per user request
                        category="iam",
                        recommendation="Rotate keys.",
                        current_state={"count": len(keys)},
                        affected_resources=[k['account'] for k in keys[:5]]
                    ))
            except Exception as inner_e:
                logger.error(f"IAM deep scan risk processing failed: {inner_e}")

            # MFA / Org Policy - Removed (SCC is Source of Truth)
            # mfa_policy = self.gcp_client.check_org_policy("constraints/iam.allowedPolicyMemberDomains", organization_id)
            
        except Exception as e:
            logger.error(f"IAM deep scan failed: {e}")
        return result

    def _audit_org_admin(self, organization_id: str) -> Dict[str, Any]:
        result = {'risks': []}
        try:
            service = PrivilegeManagerService(self.gcp_client.credentials)
            audit = service.audit_iam_segmentation(self.gcp_client.project_id, organization_id)
            
            if audit.get('offenders'):
                offenders = [o['email'] for o in audit['offenders']]
                result['risks'].append(RiskCard(
                    id="iam_org_admin_direct_access",
                    title="Org Admin with Direct Access",
                    description=f"{len(offenders)} Org Admins have direct project access.",
                    risk_level=RiskLevel.HIGH,
                    category="iam",
                    recommendation="Remove direct access.",
                    is_fixable=False,
                    current_state={"count": len(offenders)},
                    affected_resources=offenders
                ))
            else:
                 result['risks'].append(RiskCard(
                    id="iam_org_admin_verified",
                    title="✓ IAM Segmentation Verified",
                    description="No Org Admins have direct project access.",
                    risk_level=RiskLevel.INFO,
                    category="iam",
                    recommendation="Maintain segmentation.",
                    is_fixable=False,
                    affected_resources=["IAM Policy"]
                ))
        except Exception as e:
            logger.warning(f"Org admin audit failed: {e}")
        return result

    def _analyze_monitoring(self) -> Dict[str, Any]:
        result = {'risks': [], 'data': None}
        try:
            service = MonitoringAnalysisService(self.gcp_client)
            data = service.analyze_monitoring()
            result['data'] = data
            
            for r in data.get("risks", []):
                level = RiskLevel.MEDIUM
                if r['severity'] == "CRITICAL": level = RiskLevel.CRITICAL
                elif r['severity'] == "HIGH": level = RiskLevel.HIGH
                elif r['severity'] == "LOW": level = RiskLevel.LOW
                
                result['risks'].append(RiskCard(
                    id=r['id'],
                    title=r['title'],
                    description=r['description'],
                    risk_level=level,
                    category="monitoring",
                    recommendation="Enable API or alert.",
                    current_state={"enabled": False},
                    affected_resources=["Cloud Monitoring"]
                ))
        except Exception as e:
            logger.error(f"Monitoring scan failed: {e}")
        return result

    def _audit_change_control(self) -> Dict[str, Any]:
        result = {'risks': [], 'data': None}
        try:
            service = ChangeControlAuditService(self.gcp_client)
            info = service.audit_change_control()
            result['data'] = info
            
            if info.get('level') == 'Ad-Hoc':
                result['risks'].append(RiskCard(
                    id="poor_change_control",
                    title="Ad-Hoc Change Management",
                    description="No formal pipelines detected.",
                    risk_level=RiskLevel.HIGH,
                    category="process",
                    recommendation="Adopt Terraform.",
                    current_state={"score": info.get('score')},
                    affected_resources=["Governance"]
                ))
        except Exception as e:
            logger.warning(f"Change control audit failed: {e}")
        return result

    def _analyze_billing_iam(self, billing_account_id: str) -> Tuple[List[RiskCard], List[Dict]]:
        risks = []
        iam_users = []
        try:
            service = BillingService(self.gcp_client.credentials, self.gcp_client.project_id, self.gcp_client)
            policy = service.get_billing_iam_policy(billing_account_id)
            
            direct_users = {}
            target_roles = [
                'roles/billing.admin', 'roles/billing.viewer', 'roles/billing.user', 
                'roles/billing.costsManager', 'roles/billing.creator'
            ]
            
            for b in policy.get('bindings', []):
                if b['role'] in target_roles:
                    for m in b.get('members', []):
                        if m.startswith('user:'):
                            u = m.replace('user:', '')
                            if u not in direct_users: direct_users[u] = []
                            direct_users[u].append(b['role'])
                            
            iam_users = [{'user': u, 'roles': r} for u, r in direct_users.items()]
            
            if direct_users:
                 risks.append(RiskCard(
                    id="direct_billing_iam_users",
                    title="Direct Billing Access Detected",
                    description=f"{len(direct_users)} users have direct billing roles.",
                    risk_level=RiskLevel.HIGH,
                    category="governance",
                    recommendation="Use groups instead.",
                    current_state={"count": len(direct_users)},
                    affected_resources=list(direct_users.keys())[:5]
                ))
        except Exception as e:
             logger.warning(f"Billing IAM check failed: {e}")
        return risks, iam_users
