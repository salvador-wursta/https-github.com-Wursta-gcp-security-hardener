"""
Change Control Audit Service
Scans the project for change management maturity signals, including:
1. Human vs. Machine modifications (Manual Change detection)
2. Infrastructure as Code (IaC) usage indicators
3. CI/CD Pipeline presence
4. Approval Gates (Binary Authorization)
"""
import logging
from typing import Dict, Any, List
from app.services.gcp_client import GCPClient
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ChangeControlAuditService:
    def __init__(self, gcp_client: GCPClient):
        self.gcp_client = gcp_client
        self.project_id = gcp_client.project_id

    def audit_change_control(self) -> Dict[str, Any]:
        """
        Performs a comprehensive audit of change control practices.
        """
        results = {
            "score": 0, # 0-100 maturity score
            "signals": {
                "manual_changes": None,
                "iac_usage": False,
                "ci_cd_adoption": False,
                "approval_gates": False
            },
            "recommendations": []
        }
        
        # 1. Detect Human vs Machine Activity (Last 7 days)
        # We need a robust logging client for this. Assuming we have permissions.
        try:
            manual_stats = self._analyze_modification_logs()
            results["signals"]["manual_changes"] = manual_stats
        except Exception as e:
            logger.warning(f"Could not analyze modification logs: {e}")
            results["signals"]["manual_changes"] = {"error": "Insufficient permissions to read logs"}

        # 2. Detect IaC Usage
        try:
            iac_found = self._detect_iac_indicators()
            results["signals"]["iac_usage"] = iac_found
        except Exception as e:
            logger.warning(f"Could not detect IaC: {e}")

        # 3. Detect CI/CD (Cloud Build / Cloud Deploy)
        try:
            cicd_found = self._detect_pipelines()
            results["signals"]["ci_cd_adoption"] = cicd_found
        except Exception as e:
            logger.warning(f"Could not detect pipelines: {e}")

        # 4. Detect Binary Authorization
        try:
            binauth_enabled = self._check_binary_authorization()
            results["signals"]["approval_gates"] = binauth_enabled
        except Exception as e:
            logger.warning(f"Could not check binary authorization: {e}")

        # Calculate Score & Generate Recommendations
        self._calculate_maturity(results)
        
        # 5. Generate Maturity Plan (AI-Drafted Strategy)
        results["maturity_plan"] = self._generate_maturity_plan(results["level"], results["signals"])
        
        return results

    def _generate_maturity_plan(self, level: str, signals: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates a strategic roadmap based on the current maturity level.
        """
        plan = {
            "title": "",
            "description": "",
            "immediate_actions": [],
            "long_term_goals": []
        }
        
        if level == "Ad-Hoc":
            plan["title"] = "Phase 1: Standardization & Visibility"
            plan["description"] = "Your organization is currently managing GCP using manual processes. This scales poorly and lacks auditability. The goal of this phase is to stop the bleeding by enforcing observability and introducing basic code-based management."
            
            plan["immediate_actions"] = [
                "**Stop Manual Edits:** Enforce a 'Read-Only' policy for Console users in production projects.",
                "**Enable Cloud Logging:** Ensure all admin activity is logged (Audit Logs).",
                "**Adopt Terraform:** Begin importing critical resources (VPC, IAM) into Terraform state."
            ]
            plan["long_term_goals"] = [
                "Migrate 100% of network configuration to Infrastructure as Code.",
                "Establish a central 'Security Operations' repository for policy definitions."
            ]
            
        elif level == "Developing":
            plan["title"] = "Phase 2: Automation & Guardrails"
            plan["description"] = "You have some automation in place, but gaps exist. The goal now is to remove human friction and enforce security programmatically before deployment."
            
            if not signals.get("ci_cd_adoption"):
                plan["immediate_actions"].append("**Deploy CI/CD:** Move Terraform execution from local laptops to Cloud Build automation.")
            
            if not signals.get("approval_gates"):
                plan["immediate_actions"].append("**Implement Approval Gates:** Require peer review (Pull Request approval) before any infrastructure change is applied.")
                
            plan["long_term_goals"] = [
                "Enable Binary Authorization to prevent unverified containers from launching.",
                "Implement Policy-as-Code (e.g., OPA Gatekeeper or Org Policy constraints) in the pipeline."
            ]
            
        elif level == "Advanced":
            plan["title"] = "Phase 3: Continuous Compliance"
            plan["description"] = "Your change control usage is mature. Focus completely on drift detection and automated remediation."
             
            plan["immediate_actions"] = [
                "**Drift Detection:** Schedule hourly Terraform plans to detect unauthorized out-of-band changes.",
                "**Automated Rollbacks:** If a deployment fails health checks, automatically revert to the previous known-good state."
            ]
            plan["long_term_goals"] = [
                "Move towards GitOps for all application workloads.",
                "Implement Just-In-Time (JIT) access for all 'Break Glass' scenarios."
            ]
            
        return plan

    def _analyze_modification_logs(self) -> Dict[str, Any]:
        """
        Queries Cloud Logging to compare human vs service account mutation events.
        """
        from google.cloud import logging_v2
        
        # We need the logging client. The GCPClient might not expose it directly as a property,
        # but we can initialize one with credentials.
        client = logging_v2.Client(credentials=self.gcp_client.credentials, project=self.project_id)
        
        # Look back 7 days
        start_time = (datetime.utcnow() - timedelta(days=7)).isoformat() + "Z"
        
        # Filter for "Set", "Update", "Insert", "Delete", "Patch" methods
        # Exclude "Get", "List"
        filter_str = (
            f'timestamp >= "{start_time}" AND '
            'protoPayload.methodName:("Set" OR "Update" OR "Insert" OR "Delete" OR "Patch") AND '
            'NOT protoPayload.methodName:("Get" OR "List")'
        )
        
        human_count = 0
        machine_count = 0
        
        # Sample query (limit to avoid timeouts)
        try:
            entries = client.list_entries(filter_=filter_str, page_size=500, max_results=500)
            
            for entry in entries:
                payload = entry.payload
                if not payload:
                    continue
                    
                auth_info = payload.get('authenticationInfo', {})
                principal = auth_info.get('principalEmail', '')
                
                if not principal:
                    continue
                    
                if 'gserviceaccount.com' in principal:
                    machine_count += 1
                elif 'google-analytics' in principal or 'system' in principal:
                    machine_count += 1 # System accounts
                else:
                    human_count += 1 # Likely a user
                    
            total = human_count + machine_count
            human_ratio = (human_count / total) if total > 0 else 0
            
            return {
                "total_events_analyzed": total,
                "human_events": human_count,
                "machine_events": machine_count,
                "human_ratio": human_ratio
            }
            
        except Exception as e:
            logger.warning(f"Log analysis failed: {e}")
            raise

    def _detect_iac_indicators(self) -> bool:
        """
        Checks for:
        1. Buckets named *tfstate*
        2. Resources with 'managed-by' labels (check a few instances/buckets)
        """
        # Check buckets
        from google.cloud import storage
        storage_client = storage.Client(credentials=self.gcp_client.credentials, project=self.project_id)
        
        iac_bucket_found = False
        try:
            buckets = list(storage_client.list_buckets(prefix="terraform", max_results=20))
            if not buckets:
                # Try suffix via iterator if prefix fails (list_buckets prefix is starts_with)
                # Just list some and check names
                for b in storage_client.list_buckets(max_results=50):
                    if "tfstate" in b.name or "terraform" in b.name:
                        iac_bucket_found = True
                        break
            else:
                iac_bucket_found = True
        except Exception:
            pass
            
        return iac_bucket_found

    def _detect_pipelines(self) -> bool:
        """
        Checks for Cloud Build Triggers or Cloud Deploy Targets.
        """
        # Check Cloud Build Triggers
        # Requires 'cloudbuild.builds.list'
        try:
            from google.cloud.devtools import cloudbuild_v1
            client = cloudbuild_v1.CloudBuildClient(credentials=self.gcp_client.credentials)
            # Use parent format: projects/{project_id}
            triggers = list(client.list_build_triggers(parent=f"projects/{self.project_id}")) # returns a pager
            if len(triggers) > 0:
                logger.info(f"Found {len(triggers)} Cloud Build triggers")
                return True
        except Exception as e:
            logger.warning(f"Cloud Build check failed: {e}")
            
        return False

    def _check_binary_authorization(self) -> bool:
        """
        Checks if Binary Authorization is enabled for GKE.
        """
        # This requires binaryauthorization.googleapis.com
        # Using discovery client as it's easier for simple policy check
        try:
            from googleapiclient.discovery import build
            service = build('binaryauthorization', 'v1', credentials=self.gcp_client.credentials)
            policy = service.projects().getPolicy(name=f"projects/{self.project_id}").execute()
            
            # If default admission rule is not ALLOW_ALL, it counts as enabled/configured
            default_rule = policy.get('defaultAdmissionRule', {})
            evaluation_mode = default_rule.get('evaluationMode', 'ALWAYS_ALLOW')
            
            if evaluation_mode != 'ALWAYS_ALLOW':
                return True
                
        except Exception as e:
            logger.warning(f"Binary Auth check failed (API might be disabled): {e}")
            
        return False

    def _calculate_maturity(self, results: Dict[str, Any]):
        """
        Calculates maturity score and adds recommendations.
        """
        score = 0
        recs = []
        
        signals = results["signals"]
        
        # 1. Manual Changes (Max 40 pts)
        manual_data = signals.get("manual_changes")
        if manual_data and isinstance(manual_data, dict) and "human_ratio" in manual_data:
            ratio = manual_data["human_ratio"]
            if ratio < 0.1:
                score += 40 # Excellent, almost all automated
            elif ratio < 0.3:
                score += 30 # Good
            elif ratio < 0.5:
                score += 10 # Needs improvement
                recs.append("We detected significant manual activity (User-initiated changes). Shift to automated pipelines to reduce human error.")
            else:
                score += 0 # Poor
                recs.append("CRITICAL: The majority of changes effectively appear to be manual. This implies a lack of Change Control. Adopt Infrastructure as Code (IaC) immediately.")
        else:
            recs.append("Could not analyze log activity. Ensure Cloud Logging API is enabled and logs are retained.")

        # 2. IaC Usage (Max 20 pts)
        if signals.get("iac_usage"):
            score += 20
        else:
            recs.append("No Terraform state buckets or IaC signals found. Managing infrastructure via code is the industry standard for auditability.")

        # 3. CI/CD (Max 20 pts)
        if signals.get("ci_cd_adoption"):
            score += 20
        else:
            recs.append("No Cloud Build triggers found. CI/CD pipelines are essential for enforcing pre-deployment checks and approvals.")

        # 4. Approval Gates (Max 20 pts)
        if signals.get("approval_gates"):
            score += 20
        else:
            recs.append("Binary Authorization is not enforcing rules. Consider enabling it to prevent unauthorized workloads on GKE.")

        results["score"] = score
        results["recommendations"] = recs

        # Maturity Level Label
        if score >= 80:
            results["level"] = "Advanced"
        elif score >= 50:
            results["level"] = "Developing"
        else:
            results["level"] = "Ad-Hoc"
