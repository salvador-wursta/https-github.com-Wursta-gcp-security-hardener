"""
Pydantic models for script generation and API analysis
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from enum import Enum


class ScriptFormat(str, Enum):
    """Output format for generated scripts"""
    PYTHON = "python"
    TERRAFORM = "terraform"
    PULUMI = "pulumi"


class ApiRiskLevel(str, Enum):
    """Risk levels for APIs"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApiCategory(str, Enum):
    """API categories for grouping"""
    COMPUTE = "compute"
    STORAGE = "storage"
    AI_ML = "ai_ml"
    DATABASE = "database"
    NETWORKING = "networking"
    CORE = "core"
    OTHER = "other"


class ApiInfo(BaseModel):
    """Information about a single API"""
    name: str = Field(..., description="API service name (e.g., compute.googleapis.com)")
    display_name: str = Field(..., description="Human-readable name")
    category: ApiCategory = Field(..., description="API category")
    risk_level: ApiRiskLevel = Field(..., description="Risk assessment")
    can_disable: bool = Field(..., description="Whether this API can be safely disabled")
    is_enabled: bool = Field(..., description="Whether API is currently enabled")
    monthly_cost_estimate: str = Field(..., description="Estimated monthly cost range")
    reason_enabled: Optional[str] = Field(None, description="Why this API might be enabled")
    recommended_action: str = Field(..., description="Recommended action: disable, keep, or monitor")
    used_by: List[str] = Field(default_factory=list, description="Resources using this API")
    dependencies: List[str] = Field(default_factory=list, description="APIs that depend on this")


class AnalyzeLockdownRequest(BaseModel):
    """Request to analyze project and get API recommendations"""
    project_id: str = Field(..., description="GCP project ID")
    organization_id: Optional[str] = Field(None, description="Organization ID if available")
    scan_results: Optional[Dict[str, Any]] = Field(None, description="Results from security scan")
    credential_token: Optional[str] = Field(None, description="Secure credential token")


class AnalyzeLockdownResponse(BaseModel):
    """Response with API analysis and recommendations"""
    enabled_apis: List[ApiInfo] = Field(..., description="All currently enabled APIs")
    core_apis: List[str] = Field(..., description="Core APIs that cannot be disabled")
    recommendations: Dict[str, List[str]] = Field(..., description="Recommended actions grouped by type")
    total_apis: int = Field(..., description="Total number of enabled APIs")
    high_risk_count: int = Field(..., description="Number of high/critical risk APIs")


class GenerateScriptRequest(BaseModel):
    """Request to generate lockdown script"""
    project_id: str = Field(..., description="GCP project ID")
    organization_id: Optional[str] = Field(None, description="Organization ID")
    apis_to_disable: List[str] = Field(..., description="APIs user selected to disable")
    apply_network_hardening: bool = Field(True, description="Create firewall rules")
    apply_org_policies: bool = Field(True, description="Set organization policies")
    region_lockdown: Optional[str] = Field(None, description="Region to lock down to")
    budget_limit: Optional[float] = Field(None, description="Budget limit in USD")
    alert_emails: Optional[List[str]] = Field(default=None, description="Email addresses for alerts")
    compute_monitoring: bool = Field(False, description="Set up compute monitoring alerts")
    org_monitoring_enabled: bool = Field(True, description="Enable organization-wide monitoring (default: True)")
    format: ScriptFormat = Field(ScriptFormat.PYTHON, description="Output format: python, terraform, or pulumi")



class GenerateScriptResponse(BaseModel):
    """Response with generated script"""
    script: str = Field(..., description="Generated Python script")
    script_hash: str = Field(..., description="Hash of script for verification")
    summary: Dict[str, Any] = Field(..., description="Summary of what script will do")
    estimated_duration: str = Field(..., description="Estimated execution time")
    warnings: List[str] = Field(default_factory=list, description="Warnings about the script")


class ExecuteScriptRequest(BaseModel):
    """Request to execute a lockdown script on the backend"""
    project_id: str = Field(..., description="GCP project ID where script will execute")
    script: str = Field(..., description="Full Python script content to execute")
    credential_token: str = Field(..., description="Credential token for authentication")


class ExecuteScriptResponse(BaseModel):
    """Response from script execution"""
    success: bool = Field(..., description="Whether script executed successfully")
    exit_code: int = Field(..., description="Process exit code (0 = success)")
    output: List[str] = Field(default_factory=list, description="Script output lines")
    report: Optional[Dict[str, Any]] = Field(None, description="Structured execution report")
    error: Optional[str] = Field(None, description="Error message if execution failed")
    duration_seconds: float = Field(..., description="Execution duration in seconds")
    log_file_path: Optional[str] = Field(None, description="Path to persisted log file on server")
