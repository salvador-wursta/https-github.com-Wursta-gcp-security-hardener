"""
API Analysis Service
Analyzes enabled APIs in a project and provides recommendations
"""
import logging
from typing import List, Dict, Any
from app.models.script_models import ApiInfo, ApiCategory, ApiRiskLevel
from app.services.security_profiles import SecurityProfiles

logger = logging.getLogger(__name__)


class ApiAnalysisService:
    """Service for analyzing APIs and providing recommendations"""
    
    # API categorization and risk mapping
    API_METADATA = {
        # Compute & Infrastructure ( HIGH RISK)
        "compute.googleapis.com": {
            "display_name": "Compute Engine API",
            "category": ApiCategory.COMPUTE,
            "risk_level": ApiRiskLevel.HIGH,
            "cost_estimate": "$50-500/month",
            "reason": "VM instances and infrastructure"
        },
        "container.googleapis.com": {
            "display_name": "Google Kubernetes Engine API",
            "category": ApiCategory.COMPUTE,
            "risk_level": ApiRiskLevel.HIGH,
            "cost_estimate": "$100-1000/month",
            "reason": "Kubernetes clusters"
        },
        "run.googleapis.com": {
            "display_name": "Cloud Run API",
            "category": ApiCategory.COMPUTE,
            "risk_level": ApiRiskLevel.MEDIUM,
            "cost_estimate": "$10-100/month",
            "reason": "Serverless containers"
        },
        
        # AI/ML (CRITICAL RISK - GPUs)
        "aiplatform.googleapis.com": {
            "display_name": "Vertex AI API",
            "category": ApiCategory.AI_ML,
            "risk_level": ApiRiskLevel.CRITICAL,
            "cost_estimate": "$500-5000/month",
            "reason": "ML training with GPUs"
        },
        "ml.googleapis.com": {
            "display_name": "Machine Learning API (Legacy)",
            "category": ApiCategory.AI_ML,
            "risk_level": ApiRiskLevel.HIGH,
            "cost_estimate": "$100-1000/month",
            "reason": "Legacy ML workloads"
        },
        
        # Storage (MEDIUM RISK)
        "storage.googleapis.com": {
            "display_name": "Cloud Storage API",
            "category": ApiCategory.STORAGE,
            "risk_level": ApiRiskLevel.MEDIUM,
            "cost_estimate": "$5-50/month",
            "reason": "Object storage"
        },
        "bigtable.googleapis.com": {
            "display_name": "Cloud Bigtable API",
            "category": ApiCategory.DATABASE,
            "risk_level": ApiRiskLevel.HIGH,
            "cost_estimate": "$100-1000/month",
            "reason": "NoSQL database"
        },
        
        # Databases (MEDIUM-HIGH RISK)
        "sqladmin.googleapis.com": {
            "display_name": "Cloud SQL Admin API",
            "category": ApiCategory.DATABASE,
            "risk_level": ApiRiskLevel.MEDIUM,
            "cost_estimate": "$50-500/month",
            "reason": "Managed SQL databases"
        },
        "spanner.googleapis.com": {
            "display_name": "Cloud Spanner API",
            "category": ApiCategory.DATABASE,
            "risk_level": ApiRiskLevel.HIGH,
            "cost_estimate": "$200-2000/month",
            "reason": "Globally distributed database"
        },
        
        # Networking (LOW-MEDIUM RISK)
        "vpcaccess.googleapis.com": {
            "display_name": "Serverless VPC Access API",
            "category": ApiCategory.NETWORKING,
            "risk_level": ApiRiskLevel.LOW,
            "cost_estimate": "$5-20/month",
            "reason": "VPC connectors"
        },
        "dns.googleapis.com": {
            "display_name": "Cloud DNS API",
            "category": ApiCategory.NETWORKING,
            "risk_level": ApiRiskLevel.LOW,
            "cost_estimate": "$1-10/month",
            "reason": "DNS management"
        }
    }
    
    def __init__(self, gcp_client):
        self.gcp_client = gcp_client
    
    def analyze_apis(self, project_id: str) -> Dict[str, Any]:
        """
        Analyze all enabled APIs in a project
        
        Returns:
            Dict with enabled_apis, core_apis, and recommendations
        """
        logger.info(f"[API ANALYSIS] Analyzing APIs for project: {project_id}")
        
        # Get all enabled APIs
        enabled_api_names = self._get_enabled_apis(project_id)
        logger.info(f"[API ANALYSIS] Found {len(enabled_api_names)} enabled APIs")
        
        # Build ApiInfo objects
        enabled_apis = []
        core_apis = list(SecurityProfiles.CORE_APIS)
        
        for api_name in enabled_api_names:
            api_info = self._build_api_info(api_name, core_apis)
            enabled_apis.append(api_info)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(enabled_apis)
        
        # Count high risk
        high_risk_count = sum(
            1 for api in enabled_apis 
            if api.risk_level in [ApiRiskLevel.HIGH, ApiRiskLevel.CRITICAL]
        )
        
        logger.info(f"[API ANALYSIS] High risk APIs: {high_risk_count}")
        logger.info(f"[API ANALYSIS] Recommended to disable: {len(recommendations['disable'])}")
        
        return {
            "enabled_apis": enabled_apis,
            "core_apis": core_apis,
            "recommendations": recommendations,
            "total_apis": len(enabled_apis),
            "high_risk_count": high_risk_count
        }
    
    def _get_enabled_apis(self, project_id: str) -> List[str]:
        """Get list of enabled API names"""
        try:
            from googleapiclient.discovery import build
            service = build('serviceusage', 'v1', credentials=self.gcp_client.credentials)
            
            parent = f"projects/{project_id}"
            request = service.services().list(
                parent=parent,
                filter="state:ENABLED",
                pageSize=200
            )
            
            enabled_apis = []
            while request is not None:
                response = request.execute()
                services = response.get('services', [])
                for svc in services:
                    api_name = svc['config']['name']
                    enabled_apis.append(api_name)
                request = service.services().list_next(request, response)
            
            return enabled_apis
            
        except Exception as e:
            logger.error(f"[API ANALYSIS] Failed to list APIs: {e}")
            return []
    
    def _build_api_info(self, api_name: str, core_apis: List[str]) -> ApiInfo:
        """Build ApiInfo object for an API"""
        metadata = self.API_METADATA.get(api_name, {
            "display_name": api_name.replace(".googleapis.com", "").title(),
            "category": ApiCategory.OTHER,
            "risk_level": ApiRiskLevel.LOW,
            "cost_estimate": "Unknown",
            "reason": "Unknown"
        })
        
        can_disable = api_name not in core_apis
        
        # Determine recommended action
        if not can_disable:
            recommended_action = "keep"
        elif metadata["risk_level"] in [ApiRiskLevel.HIGH, ApiRiskLevel.CRITICAL]:
            recommended_action = "disable"
        elif metadata["risk_level"] == ApiRiskLevel.MEDIUM:
            recommended_action = "monitor"
        else:
            recommended_action = "keep"
        
        return ApiInfo(
            name=api_name,
            display_name=metadata["display_name"],
            category=metadata["category"],
            risk_level=metadata["risk_level"],
            can_disable=can_disable,
            is_enabled=True,
            monthly_cost_estimate=metadata["cost_estimate"],
            reason_enabled=metadata["reason"],
            recommended_action=recommended_action,
            used_by=[],  # TODO: Query actual resource usage
            dependencies=[]  # TODO: Build dependency graph
        )
    
    def _generate_recommendations(self, apis: List[ApiInfo]) -> Dict[str, List[str]]:
        """Generate recommendations based on API analysis"""
        disable = []
        keep = []
        monitor = []
        
        for api in apis:
            if api.recommended_action == "disable":
                disable.append(api.name)
            elif api.recommended_action == "monitor":
                monitor.append(api.name)
            else:
                keep.append(api.name)
        
        return {
            "disable": disable,
            "keep": keep,
            "monitor": monitor
        }
