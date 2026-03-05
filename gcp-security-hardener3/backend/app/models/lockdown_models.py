"""
Pydantic models for security lockdown operations
"""
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, validator, EmailStr
import re


class SecurityProfile(str, Enum):
    """Security profile templates"""
    GWS_ONLY = "gws_only"  # Google Workspace only - Deny All
    VERTEX_ONLY = "vertex_only"  # Vertex AI only - Allow aiplatform, storage
    WEB_APP = "web_app"  # Web application - Allow compute, vpc, sqladmin


class LockdownRequest(BaseModel):
    """Request to apply security lockdown"""
    project_id: str = Field(..., description="GCP Project ID to secure", min_length=6, max_length=30)
    access_token: str = Field("", description="Firebase ID token for user verification (optional)")
    security_profile: SecurityProfile = Field(..., description="Security profile template to apply")
    
    # Support both old way (full credentials) and new way (token)
    service_account_credentials: Optional[Dict[str, Any]] = Field(None, description="Service account key JSON (deprecated - use credential_token)")
    credential_token: Optional[str] = Field(None, description="Secure credential token from /credentials/upload (recommended)")
    
    region: Optional[str] = Field(None, description="Geographic region for region lockdown")
    budget_limit: Optional[float] = Field(None, description="Monthly budget limit in USD", ge=1, le=1000000)
    alert_emails: Optional[List[EmailStr]] = Field(None, description="Email addresses for alerts")
    organization_id: Optional[str] = Field(None, description="GCP Organization ID (for org policies)")
    selected_risk_ids: Optional[List[str]] = Field(
        default_factory=list,
        description="List of risk IDs to fix. If empty, all risks will be fixed."
    )
    selected_step_ids: Optional[List[str]] = Field(
        default_factory=list,
        description="List of specific step IDs to execute (Change Control)."
    )
    
    # Organization Monitoring - enabled by default
    org_monitoring_enabled: bool = Field(True, description="Enable organization-wide security monitoring (default: True)")
    billing_account_id: Optional[str] = Field(None, description="Billing Account ID for logging cost safety budget")
    
    @validator('credential_token')
    def validate_credentials_provided(cls, v, values):
        """Ensure at least one credential method is provided"""
        service_account_creds = values.get('service_account_credentials')
        
        if v is None and service_account_creds is None:
            raise ValueError('Either credential_token or service_account_credentials must be provided')
        
        return v
    
    @validator('project_id')
    def validate_project_id(cls, v):
        """Validate GCP project ID format"""
        if not re.match(r'^[a-z][a-z0-9-]{4,28}[a-z0-9]$', v):
            raise ValueError('Invalid GCP project ID format')
        if '--' in v:
            raise ValueError('Project ID cannot contain consecutive hyphens')
        return v
    
    @validator('region')
    def validate_region(cls, v):
        """Validate GCP region format"""
        if v is not None and not re.match(r'^[a-z]+-[a-z]+\d+$', v):
            raise ValueError('Invalid GCP region format (e.g., us-central1)')
        return v
    
    @validator('budget_limit')
    def validate_budget(cls, v):
        """Validate budget is positive"""
        if v is not None and v <= 0:
            raise ValueError('Budget limit must be positive')
        return v


class MultiProjectLockdownRequest(BaseModel):
    """Request to apply security lockdown to multiple projects"""
    project_ids: List[str] = Field(..., description="List of GCP Project IDs to secure")
    access_token: str = Field("", description="Firebase ID token for user verification (optional)")
    security_profile: SecurityProfile = Field(..., description="Security profile template to apply")
    
    # Support both old way (full credentials) and new way (token)
    service_account_credentials: Optional[Dict[str, Any]] = Field(None, description="Service account key JSON (deprecated - use credential_token)")
    credential_token: Optional[str] = Field(None, description="Secure credential token from /credentials/upload (recommended)")
    
    region: Optional[str] = Field(None, description="Geographic region for region lockdown")
    budget_limit: Optional[float] = Field(None, description="Monthly budget limit in USD")
    alert_emails: Optional[List[EmailStr]] = Field(None, description="Email addresses for alerts")
    organization_id: Optional[str] = Field(None, description="GCP Organization ID (for org policies)")
    selected_risk_ids: Optional[List[str]] = Field(
        default_factory=list,
        description="List of risk IDs to fix. If empty, all risks will be fixed."
    )
    
    @validator('credential_token')
    def validate_credentials_provided(cls, v, values):
        """Ensure at least one credential method is provided"""
        service_account_creds = values.get('service_account_credentials')
        
        if v is None and service_account_creds is None:
            raise ValueError('Either credential_token or service_account_credentials must be provided')
        
        return v


class LockdownStep(BaseModel):
    """Individual step in the lockdown process"""
    step_id: str
    name: str
    description: str
    status: str = Field(default="pending")  # pending, in_progress, completed, failed
    error: Optional[str] = None
    security_benefit: str = Field(..., description="Explain Like I'm 5 - why this helps")
    details: Optional[Dict[str, Any]] = Field(None, description="Granular metadata about the lockdown action")


class LockdownResponse(BaseModel):
    """Response from lockdown operation"""
    project_id: str
    security_profile: SecurityProfile
    timestamp: str
    steps: List[LockdownStep] = Field(default_factory=list)
    summary: Dict[str, int] = Field(
        default_factory=lambda: {
            "completed": 0,
            "failed": 0,
            "total": 0
        }
    )
    status: str = Field(default="in_progress")  # in_progress, completed, failed
    errors: List[str] = Field(default_factory=list)
    report_url: Optional[str] = Field(None, description="URL to download the outcomes report PDF")
    extended_alerts: List[Dict[str, Any]] = Field(default_factory=list, description="Details of extended alerts created")


class MultiProjectLockdownResponse(BaseModel):
    """Response from multi-project lockdown operation"""
    project_results: List[LockdownResponse] = Field(default_factory=list)
    total_projects: int = 0
    completed_projects: int = 0
    failed_projects: int = 0
    timestamp: str = ""
    overall_status: str = Field(default="in_progress")  # in_progress, completed, completed_with_errors
    errors: List[str] = Field(default_factory=list)

