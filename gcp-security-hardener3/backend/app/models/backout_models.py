"""
Pydantic models for backout/rollback operations
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class BackoutRequest(BaseModel):
    """Request to rollback security lockdown changes"""
    project_id: str = Field(..., description="GCP Project ID to rollback", pattern=r"^[a-z0-9-]+$")  # Added regex validation
    access_token: str = Field("", description="Firebase ID token for user verification (optional)")
    credential_token: str = Field(..., description="Secure token for service account credentials")  # Replaced service_account_credentials
    organization_id: Optional[str] = Field(None, description="GCP Organization ID (for org policies)")
    confirm_backout: bool = Field(False, description="Must be True to confirm backout operation")


class BackoutStep(BaseModel):
    """Individual step in the backout process"""
    step_id: str
    name: str
    description: str
    status: str = Field(default="pending")  # pending, in_progress, completed, failed, skipped
    error: Optional[str] = None
    original_value: Optional[Any] = Field(None, description="Original value before lockdown")
    restored_value: Optional[Any] = Field(None, description="Value after restoration")


class BackoutResponse(BaseModel):
    """Response from backout operation"""
    project_id: str
    timestamp: str
    steps: List[BackoutStep] = Field(default_factory=list)
    summary: Dict[str, int] = Field(
        default_factory=lambda: {
            "completed": 0,
            "failed": 0,
            "skipped": 0,
            "total": 0
        }
    )
    status: str = Field(default="in_progress")  # in_progress, completed, failed
    errors: List[str] = Field(default_factory=list)
    warning: Optional[str] = Field(
        None,
        description="Warning message about security implications of backout"
    )

