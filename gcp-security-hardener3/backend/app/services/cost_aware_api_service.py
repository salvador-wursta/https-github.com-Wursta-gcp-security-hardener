"""
Cost-Aware API Enablement Service
Prevents expensive APIs from being enabled without explicit user approval
"""
import logging
from typing import Dict, Any, List, Optional
from google.oauth2.credentials import Credentials

logger = logging.getLogger(__name__)

# APIs that cost money or require paid features
PAID_APIS = {
    # Premium/Enterprise only
    "accessapproval.googleapis.com": {
        "cost": "Premium Support ($12,500+/month)",
        "alternative": "Use IAM policies and manual approval workflow"
    },
    "accesscontextmanager.googleapis.com": {
        "cost": "VPC Service Controls (~$5,000+/month)",
        "alternative": "Use VPC firewall rules and organization policies"
    },
    "assuredworkloads.googleapis.com": {
        "cost": "Assured Workloads (~$2,500+/month)",
        "alternative": "Standard compliance using org policies"
    },
    
    # Pay-per-use APIs (can get expensive)
    "videointelligence.googleapis.com": {
        "cost": "Pay-per-use (varies)",
        "alternative": "N/A - Request user approval"
    },
    "speech.googleapis.com": {
        "cost": "Pay-per-use ($0.006/15s audio)",
        "alternative": "N/A - Request user approval"
    },
    "translate.googleapis.com": {
        "cost": "Pay-per-use ($20/million chars)",
        "alternative": "N/A - Request user approval"
    },
    
    # High-volume APIs
    "containeranalysis.googleapis.com": {
        "cost": "Can be expensive at scale",
        "alternative": "N/A - Use with caution"
    },
}

# Free APIs safe to enable automatically
FREE_APIS = [
    "cloudresourcemanager.googleapis.com",
    "orgpolicy.googleapis.com",
    "iam.googleapis.com",
    "cloudbilling.googleapis.com",
    "billingbudgets.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "compute.googleapis.com",
    "serviceusage.googleapis.com",
    "cloudkms.googleapis.com",
    "secretmanager.googleapis.com",
    "storage.googleapis.com",  # Storage costs but API is free
]


class CostAwareAPIService:
    """Service that checks API costs before enabling"""
    
    def __init__(self):
        self.blocked_apis: List[str] = []
        self.approved_apis: List[str] = []
    
    def check_api_cost(self, api_name: str) -> Dict[str, Any]:
        """
        Check if an API has cost implications
        
        Returns:
            {
                "is_free": bool,
                "cost_info": str or None,
                "alternative": str or None,
                "require_approval": bool
            }
        """
        # Check if it's a known paid API
        if api_name in PAID_APIS:
            cost_data = PAID_APIS[api_name]
            return {
                "is_free": False,
                "cost_info": cost_data["cost"],
                "alternative": cost_data["alternative"],
                "require_approval": True
            }
        
        # Check if it's a known free API
        if api_name in FREE_APIS:
            return {
                "is_free": True,
                "cost_info": None,
                "alternative": None,
                "require_approval": False
            }
        
        # Unknown API - require approval to be safe
        return {
            "is_free": False,
            "cost_info": "Unknown cost - not in free API list",
            "alternative": "Research API pricing before enabling",
            "require_approval": True
        }
    
    def can_enable_api(self, api_name: str, user_approved: bool = False) -> tuple[bool, str]:
        """
        Check if API can be enabled based on cost policy
        
        Args:
            api_name: API to enable
            user_approved: True if user explicitly approved this API
            
        Returns:
            (can_enable, reason)
        """
        cost_check = self.check_api_cost(api_name)
        
        # Free APIs can always be enabled
        if cost_check["is_free"]:
            logger.info(f"[COST-AWARE] ✓ {api_name} is free - enabling")
            return True, "Free API"
        
        # Check if previously approved
        if api_name in self.approved_apis:
            logger.info(f"[COST-AWARE] ✓ {api_name} was previously approved")
            return True, "Previously approved"
        
        # Check if user approved this time
        if user_approved:
            logger.info(f"[COST-AWARE] ✓ {api_name} approved by user")
            self.approved_apis.append(api_name)
            return True, "User approved"
        
        # Block expensive APIs without approval
        logger.warning(f"[COST-AWARE] ✗ {api_name} requires approval - cost: {cost_check['cost_info']}")
        logger.warning(f"[COST-AWARE]   Alternative: {cost_check['alternative']}")
        self.blocked_apis.append(api_name)
        
        return False, f"Requires approval: {cost_check['cost_info']}"
    
    def get_blocked_apis(self) -> List[Dict[str, Any]]:
        """Get list of APIs that were blocked"""
        return [
            {
                "api": api,
                **self.check_api_cost(api)
            }
            for api in self.blocked_apis
        ]
    
    def approve_api(self, api_name: str) -> bool:
        """
        Approve a specific API for enablement
        
        Returns:
            True if approved, False if not found in paid list
        """
        cost_check = self.check_api_cost(api_name)
        
        if cost_check["require_approval"]:
            self.approved_apis.append(api_name)
            if api_name in self.blocked_apis:
                self.blocked_apis.remove(api_name)
            
            logger.info(f"[COST-AWARE] ✓ API approved: {api_name}")
            logger.warning(f"[COST-AWARE]   Cost: {cost_check['cost_info']}")
            return True
        
        return False


# Global instance
cost_aware_api_service = CostAwareAPIService()
