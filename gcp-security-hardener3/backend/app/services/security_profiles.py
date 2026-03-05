"""
Security Profile Templates
Defines the allowed/denied APIs and policies for each security profile
"""
from typing import Dict, List, Set
from app.models.lockdown_models import SecurityProfile


class SecurityProfiles:
    """Security profile configurations"""
    
    # Core APIs that are always needed
    CORE_APIS = {
        "cloudresourcemanager.googleapis.com",  # Project management
        "serviceusage.googleapis.com",  # API management
        "iam.googleapis.com",  # Identity and Access Management
        "cloudbilling.googleapis.com",  # Billing
        "billingbudgets.googleapis.com",  # Billing budgets (scanner needs this)
        "recommender.googleapis.com",  # Cost recommendations (scanner needs this)
        "logging.googleapis.com",  # Cloud Logging
        "monitoring.googleapis.com",  # Cloud Monitoring
        "pubsub.googleapis.com",  # Pub/Sub (for kill switch)
        "cloudfunctions.googleapis.com",  # Cloud Functions (for kill switch)
        "orgpolicy.googleapis.com",  # Organization policies
    }
    
    # Google Workspace Only Profile
    # Allow Compute but monitor usage via alerts
    PROFILE_GWS_ONLY: Dict[str, any] = {
        "name": "Google Workspace Only",
        "description": "For organizations that only use Google Workspace. Monitors compute usage via email alerts instead of blocking.",
        "allowed_apis": list(CORE_APIS | {
            "compute.googleapis.com",  # Allow but monitor
        }),
        "denied_apis": [],  # Monitor instead of deny
        "allow_compute": True,  # Changed from False - allow with monitoring
        "allow_external_ips": False,  # Firewall rules block external access
        "allow_gpus": False,  # Alert on GPU usage
        "network_policy": "deny_all_external",
        "region_lockdown": True,
        "compute_monitoring": True,  # Enable compute monitoring alerts
    }

    
    # Vertex AI Only Profile
    # Allow AI Platform and Storage, deny compute/container
    PROFILE_VERTEX_ONLY: Dict[str, any] = {
        "name": "Vertex AI Only",
        "description": "For organizations using Vertex AI for ML workloads. Allows AI Platform and Storage, denies Compute Engine and GKE.",
        "allowed_apis": list(CORE_APIS | {
            "aiplatform.googleapis.com",  # Vertex AI
            "storage.googleapis.com",  # Cloud Storage
            "bigquery.googleapis.com",  # BigQuery (often used with Vertex AI)
        }),
        "denied_apis": [
            "compute.googleapis.com",
            "container.googleapis.com",
            "run.googleapis.com",  # Cloud Run
        ],
        "allow_compute": False,
        "allow_external_ips": False,
        "allow_gpus": True,  # Vertex AI needs GPUs
        "network_policy": "deny_all_external",
        "region_lockdown": True,
    }
    
    # Web Application Profile
    # Allow compute, VPC, SQL
    PROFILE_WEB_APP: Dict[str, any] = {
        "name": "Web Application",
        "description": "For organizations hosting web applications. Allows Compute Engine, VPC, and Cloud SQL.",
        "allowed_apis": list(CORE_APIS | {
            "compute.googleapis.com",  # Compute Engine
            "vpcaccess.googleapis.com",  # VPC Access
            "sqladmin.googleapis.com",  # Cloud SQL
            "storage.googleapis.com",  # Cloud Storage
            "run.googleapis.com",  # Cloud Run
            "container.googleapis.com",  # GKE (optional)
        }),
        "denied_apis": [
            "ml.googleapis.com",  # Legacy ML API
            "aiplatform.googleapis.com",  # Vertex AI (unless needed)
        ],
        "allow_compute": True,
        "allow_external_ips": True,  # Web apps need external IPs
        "allow_gpus": False,  # Disable by default, can be enabled if needed
        "network_policy": "allow_external_with_monitoring",
        "region_lockdown": True,
    }
    
    @classmethod
    def get_profile(cls, profile: SecurityProfile) -> Dict[str, any]:
        """Get security profile configuration"""
        profiles = {
            SecurityProfile.GWS_ONLY: cls.PROFILE_GWS_ONLY,
            SecurityProfile.VERTEX_ONLY: cls.PROFILE_VERTEX_ONLY,
            SecurityProfile.WEB_APP: cls.PROFILE_WEB_APP,
        }
        return profiles.get(profile, cls.PROFILE_GWS_ONLY)
    
    @classmethod
    def get_allowed_apis(cls, profile: SecurityProfile) -> List[str]:
        """Get list of allowed APIs for a profile"""
        config = cls.get_profile(profile)
        return config["allowed_apis"]
    
    @classmethod
    def get_denied_apis(cls, profile: SecurityProfile) -> List[str]:
        """Get list of explicitly denied APIs for a profile"""
        config = cls.get_profile(profile)
        return config.get("denied_apis", [])
    
    @classmethod
    def should_allow_external_ips(cls, profile: SecurityProfile) -> bool:
        """Check if external IPs should be allowed"""
        config = cls.get_profile(profile)
        return config.get("allow_external_ips", False)
    
    @classmethod
    def should_allow_gpus(cls, profile: SecurityProfile) -> bool:
        """Check if GPUs should be allowed"""
        config = cls.get_profile(profile)
        return config.get("allow_gpus", False)

