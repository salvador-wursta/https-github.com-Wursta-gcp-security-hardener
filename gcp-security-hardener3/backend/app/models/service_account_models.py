"""
Pydantic models for service account management
"""
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class CreateServiceAccountRequest(BaseModel):
    """Request to create a temporary service account"""
    project_id: str = Field(..., description="GCP Project ID")
    user_email: str = Field(..., description="Email of user requesting the service account")


class ServiceAccountResponse(BaseModel):
    """Response with service account details"""
    email: str = Field(..., description="Service account email")
    name: str = Field(..., description="Service account resource name")
    unique_id: str = Field(..., description="Service account unique ID")
    key: Dict[str, Any] = Field(..., description="Service account JSON key")
    created_at: str = Field(..., description="Creation timestamp")
    created_by: str = Field(..., description="Email of user who created it")


class DisableServiceAccountRequest(BaseModel):
    """Request to disable a service account"""
    project_id: str = Field(..., description="GCP Project ID")
    service_account_email: str = Field(..., description="Service account email to disable")


class DisableServiceAccountResponse(BaseModel):
    """Response from disabling service account"""
    service_account_email: str
    status: str = Field(..., description="disabled")
    message: str = Field(..., description="Service account disabled and permissions removed")

