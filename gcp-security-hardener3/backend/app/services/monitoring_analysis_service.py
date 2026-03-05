"""
Monitoring Analysis Service
Analyzes the state of Cloud Logging and Cloud Monitoring in the project.
Checks for CIS Benchmark compliance regarding log metrics and alerts.
"""
import logging
from typing import Dict, Any, List, Optional
from app.services.gcp_client import GCPClient
from app.models.scan_models import RiskCard, RiskLevel

logger = logging.getLogger(__name__)

class MonitoringAnalysisService:
    def __init__(self, gcp_client: GCPClient):
        self.gcp_client = gcp_client
        self.project_id = gcp_client.project_id
        
    def analyze_monitoring(self) -> Dict[str, Any]:
        """
        Analyzes logging and monitoring configuration.
        """
        results = {
            "apis_enabled": {
                "logging": False,
                "monitoring": False
            },
            "audit_logs_enabled": False, # Basic check
            "alert_policies": [],
            "cis_benchmark_coverage": {}, # Map of CIS requirement -> Satisfied?
            "risks": []
        }
        
        try:
            # 1. Check APIs
            enabled_apis = self.gcp_client.get_enabled_apis()
            results["apis_enabled"]["logging"] = "logging.googleapis.com" in enabled_apis
            results["apis_enabled"]["monitoring"] = "monitoring.googleapis.com" in enabled_apis
            
            if not results["apis_enabled"]["logging"]:
                results["risks"].append({
                    "id": "logging_api_disabled",
                    "title": "Cloud Logging API Disabled",
                    "description": "The Logging API is not enabled. No centralized logs are being collected.",
                    "severity": "CRITICAL"
                })
                return results # Cannot proceed further
                
            if not results["apis_enabled"]["monitoring"]:
                results["risks"].append({
                    "id": "monitoring_api_disabled",
                    "title": "Cloud Monitoring API Disabled",
                    "description": "The Monitoring API is not enabled. You cannot receive alerts for security events.",
                    "severity": "HIGH"
                })
                # We can still check logging, but not alerts
            
            # 2. List Existing Alert Policies
            if results["apis_enabled"]["monitoring"]:
                try:
                    from google.cloud import monitoring_v3
                    # Use a fresh client to avoid thread/loop issues if any
                    client = monitoring_v3.AlertPolicyServiceClient(credentials=self.gcp_client.credentials)
                    request = monitoring_v3.ListAlertPoliciesRequest(
                        name=f"projects/{self.project_id}",
                        page_size=100
                    )
                    policies = client.list_alert_policies(request=request)
                    
                    for p in policies:
                        results["alert_policies"].append({
                            "name": p.name,
                            "display_name": p.display_name,
                            "enabled": p.enabled,
                            "combiner": p.combiner.name
                        })
                except Exception as e:
                    logger.warning(f"Failed to list alert policies: {e}")
            
            # 3. Analyze CIS Benchmark Coverage
            # We look for alert policies that seem to cover these topics (by name or simple heuristics)
            # A rigorous check matches the filter string, but name matching is a decent proxy for existence
            
            cis_requirements = {
                "vpc_changes": ["vpc", "network", "firewall"],
                "iam_changes": ["iam", "role", "permission", "policy"],
                "project_ownership": ["ownership", "owner"],
                "audit_config": ["audit", "logging"],
                "custom_role": ["custom role", "role"],
                "crypto_keys": ["kms", "key", "crypto", "destroy"]
            }
            
            existing_alert_names = [p["display_name"].lower() for p in results["alert_policies"]]
            
            for requirement, keywords in cis_requirements.items():
                satisfied = False
                for name in existing_alert_names:
                    if any(k in name for k in keywords):
                        satisfied = True
                        break
                results["cis_benchmark_coverage"][requirement] = satisfied
                
                if not satisfied:
                    risk_level = "MEDIUM"
                    if requirement in ["vpc_changes", "iam_changes"]:
                        risk_level = "HIGH"
                        
                    results["risks"].append({
                        "id": f"missing_alert_{requirement}",
                        "title": f"Missing Alert: {requirement.replace('_', ' ').title()}",
                        "description": f"No alert policy found for {requirement.replace('_', ' ')}. CIS Benchmarks recommend alerting on these critical changes.",
                        "severity": risk_level
                    })

        except Exception as e:
            logger.error(f"Error analyzing monitoring: {e}")
            results["error"] = str(e)
            
        return results
