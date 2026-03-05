"""
Pydantic models for security scan requests and responses
"""
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, validator, root_validator
import re


class RiskLevel(str, Enum):
    """Risk severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskCard(BaseModel):
    """Individual risk finding for UI display"""
    id: str = Field(..., description="Unique identifier for this risk")
    title: str = Field(..., description="Human-readable title (Explain Like I'm 5)")
    description: str = Field(..., description="Simple explanation of the risk")
    risk_level: RiskLevel = Field(..., description="Severity of the risk")
    category: str = Field(..., description="Category: api, iam, billing, network, etc.")
    recommendation: str = Field(..., description="What we recommend doing")
    is_fixable: bool = Field(True, description="Whether this risk can be fixed automatically")
    current_state: Optional[Dict[str, Any]] = Field(None, description="Current configuration state")
    affected_resources: Optional[List[str]] = Field(None, description="List of affected resources")
    remediation_script_filename: Optional[str] = Field(None, description="Filename for the automated fix script")
    remediation_script_content: Optional[str] = Field(None, description="Content of the automated fix script")


class ScanRequest(BaseModel):
    """Request to perform a security scan"""
    project_id: str = Field(..., description="GCP Project ID to scan", min_length=6, max_length=30)
    access_token: str = Field(..., description="Firebase ID token for user verification")
    organization_id: Optional[str] = Field(None, description="GCP Organization ID (optional)")
    
    # Support both old way (full credentials) and new way (token)
    # In future: remove service_account_credentials, make credential_token required
    service_account_credentials: Optional[Dict[str, Any]] = Field(None, description="Service account key JSON (deprecated - use credential_token)")
    credential_token: Optional[str] = Field(None, description="Secure credential token from /credentials/upload (recommended)")
    jit_token: Optional[str] = Field(None, description="JIT Session Token from /session/start (Phase 2 Auth)")
    impersonate_email: Optional[str] = Field(None, description="Scanner SA email to impersonate for this scan")
    scan_modules: Optional[List[str]] = Field(None, description="List of specific modules to scan (e.g. ['billing', 'network'])")
    
    @validator('project_id')
    def validate_project_id(cls, v):
        """Validate GCP project ID format"""
        if not re.match(r'^[a-z][a-z0-9-]{4,28}[a-z0-9]$', v):
            raise ValueError('Invalid GCP project ID format. Must start with lowercase letter, contain only lowercase letters, numbers, and hyphens, and be 6-30 characters long.')
        if '--' in v:
            raise ValueError('Project ID cannot contain consecutive hyphens')
        return v
    
    @validator('organization_id')
    def validate_organization_id(cls, v):
        """Validate organization ID format (digits only)"""
        if v is not None and not re.match(r'^[0-9]+$', v):
            raise ValueError('Organization ID must contain only digits')
        return v
    
    @validator('credential_token')
    def validate_credentials_provided(cls, v, values):
        """Ensure validation passes in identity-based SaaS mode"""
        return v
    
    @validator('service_account_credentials')
    def validate_sa_credentials(cls, v):
        """Validate service account credentials structure"""
        if v is None:
            return v
        required_fields = ['type', 'project_id', 'private_key_id', 'private_key', 'client_email']
        for field in required_fields:
            if field not in v:
                raise ValueError(f'Service account credentials missing required field: {field}')
        if v.get('type') != 'service_account':
            raise ValueError('Credentials must be for a service account')
        return v


class BillingInfo(BaseModel):
    """Billing account and budget information"""
    billing_account_id: Optional[str] = Field(None, description="Billing account ID linked to project")
    billing_account_name: Optional[str] = Field(None, description="Billing account display name")
    has_project_billing: bool = Field(default=False, description="Whether project has direct billing account")
    has_org_billing: bool = Field(default=False, description="Whether project uses org-level billing")
    budgets: List[Dict[str, Any]] = Field(default_factory=list, description="List of budgets for this project")
    current_budget_limit: Optional[float] = Field(None, description="Current budget limit in USD")
    budget_recommendation: Optional[str] = Field(None, description="Recommendation for budget configuration")
    current_month_spend: Optional[float] = Field(None, description="Current month's spending in USD")
    prior_month_spend: Optional[float] = Field(None, description="Prior month's spending in USD")
    spend_trend: Optional[str] = Field(None, description="Spending trend (increasing, decreasing, stable)")
    iam_users: List[Dict[str, Any]] = Field(default_factory=list, description="List of individual users with direct billing access")
    attached_projects: List[Dict[str, Any]] = Field(default_factory=list, description="List of projects linked to this billing account")


class GPUQuotaInfo(BaseModel):
    """GPU quota information for a project"""
    total_quota: int = Field(default=0, description="Total GPU quota across all regions")
    regions_with_quota: int = Field(default=0, description="Number of regions with GPU quota > 0")
    quota_by_region: List[Dict[str, Any]] = Field(default_factory=list, description="GPU quota breakdown by region")
    summary: Optional[str] = Field(None, description="Human-readable summary of GPU quotas")
    risk_level: str = Field(default="info", description="Risk level: safe, warning, high")
    recommendation: Optional[str] = Field(None, description="Recommendation for GPU quota configuration")


class ComputeInstanceInfo(BaseModel):
    """Compute instance type usage information"""
    n2_instances: int = Field(default=0, description="Number of N2 instances currently running")
    c2_instances: int = Field(default=0, description="Number of C2 instances currently running")
    total_restricted_instances: int = Field(default=0, description="Total N2 + C2 instances")
    instances_by_zone: List[Dict[str, Any]] = Field(default_factory=list, description="Instance breakdown by zone")
    policy_enabled: bool = Field(default=False, description="Whether N2/C2 restriction policy is active")
    risk_level: str = Field(default="info", description="Risk level: safe, warning, high")
    recommendation: Optional[str] = Field(None, description="Recommendation for instance type restrictions")


class UnusedAPIsInfo(BaseModel):
    """Information about high-cost APIs that are enabled but may be unused"""
    apis: List[Dict[str, Any]] = Field(default_factory=list, description="List of high-cost APIs enabled")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Summary of API analysis")
    billing_data: Dict[str, Any] = Field(default_factory=dict, description="Billing analysis data")



class ArchitecturalFinding(BaseModel):
    """Finding from AI Security Architect Audit"""
    title: str = Field(..., description="Finding title")
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW")
    standard_violation: str = Field(default="", description="e.g. NIST 800-53 SC-7")
    recommendation: str = Field(..., description="Architectural recommendation")

class ArchitectureInfo(BaseModel):
    """Results from Architectural Foundations Scan"""
    findings: List[ArchitecturalFinding] = Field(default_factory=list)
    scan_status: str = Field(default="completed")
    error: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = Field(None, description="Raw data used for analysis")


class SCCFinding(BaseModel):
    """Security Command Center finding"""
    category: str
    state: str
    severity: str
    event_time: str
    resource_name: str
    external_uri: str


class SCCInfo(BaseModel):
    """Security Command Center Information"""
    status: str = Field(default="DISABLED", description="ACTIVE, DISABLED, or UNKNOWN")
    tier: str = Field(default="STANDARD", description="STANDARD or PREMIUM")
    findings: List[SCCFinding] = Field(default_factory=list, description="List of active findings")



class InventorySummary(BaseModel):
    """Summary of discovered cloud assets from CAI"""
    total_assets: int = Field(0, description="Total count of assets found")
    resource_counts: Dict[str, int] = Field(default_factory=dict, description="Count by asset type (e.g. 'compute.Instance': 5)")
    public_ip_count: int = Field(0, description="Number of resources with public IPs")
    storage_buckets: int = Field(0, description="Number of storage buckets")
    sql_instances: int = Field(0, description="Number of SQL instances")
    firewall_rules: int = Field(0, description="Number of firewall rules")


class ScanResponse(BaseModel):
    """Response from security scan"""
    project_id: str
    organization_id: Optional[str] = None
    organization_name: Optional[str] = None
    scanner_email: Optional[str] = Field(None, description="Identity of the service account that ran the scan")
    scan_timestamp: str
    risks: List[RiskCard] = Field(default_factory=list)
    summary: Dict[str, int] = Field(
        default_factory=lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 0
        }
    )
    enabled_apis: List[str] = Field(default_factory=list)
    inventory_summary: Optional[InventorySummary] = Field(None, description="Master inventory of all assets found via CAI")
    scan_status: str = Field(default="completed")
    errors: List[str] = Field(default_factory=list)
    billing_info: Optional[BillingInfo] = Field(None, description="Billing account and budget information")
    gpu_quota: Optional[GPUQuotaInfo] = Field(None, description="GPU quota information for crypto-mining risk assessment")
    compute_instances: Optional[ComputeInstanceInfo] = Field(None, description="N2/C2 compute instance usage for cost attack prevention")
    unused_apis: Optional[UnusedAPIsInfo] = Field(None, description="High-cost APIs that are enabled but may be unused")
    api_analysis: Optional[Dict[str, Any]] = Field(None, description="Comprehensive API usage and risk analysis")
    iam_analysis: Optional[Dict[str, Any]] = Field(None, description="Identity and Access Management analysis")
    monitoring_analysis: Optional[Dict[str, Any]] = Field(None, description="Monitoring and logging analysis")
    change_control_info: Optional[Dict[str, Any]] = Field(None, description="Change Control Maturity Audit")
    scc_info: Optional[SCCInfo] = Field(None, description="Security Command Center findings and status")
    architecture_info: Optional[ArchitectureInfo] = Field(None, description="AI Security Architect findings")


class MultiProjectScanRequest(BaseModel):
    """Request to scan multiple projects"""
    project_ids: List[str] = Field(..., description="List of GCP Project IDs to scan")
    access_token: str = Field("", description="Firebase ID token for user verification (optional)")
    organization_id: Optional[str] = Field(None, description="GCP Organization ID (optional)")
    scan_modules: Optional[List[str]] = Field(None, description="List of specific modules to scan")
    
    # Support both old way (full credentials) and new way (token)
    service_account_credentials: Optional[Dict[str, Any]] = Field(None, description="Service account key JSON (deprecated - use credential_token)")
    credential_token: Optional[str] = Field(None, description="Secure credential token from /credentials/upload (recommended)")
    jit_token: Optional[str] = Field(None, description="JIT Session Token from /session/start (Phase 2 Auth)")
    impersonate_email: Optional[str] = Field(None, description="Scanner SA email to impersonate for this scan")
    
    @validator('credential_token')
    def validate_credential_field(cls, v, values):
        return v

    @root_validator(skip_on_failure=True)
    def validate_credentials_provided(cls, values):
        """Ensure validation passes in identity-based SaaS mode"""
        return values


class MultiProjectScanResponse(BaseModel):
    """Response from multi-project security scan"""
    scans: List[ScanResponse] = Field(default_factory=list)
    total_projects: int = 0
    completed_projects: int = 0
    failed_projects: int = 0
    scan_timestamp: str = ""
    overall_status: str = Field(default="in_progress")  # in_progress, completed, completed_with_errors
    errors: List[str] = Field(default_factory=list)

