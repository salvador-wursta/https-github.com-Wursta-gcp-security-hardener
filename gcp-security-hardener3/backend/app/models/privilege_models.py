"""
Privilege Models
Data models for JIT privilege escalation system
"""
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class ServiceAccountInfo(BaseModel):
    """Service account information"""
    email: str
    unique_id: str
    display_name: str
    exists: bool


class ProjectInfo(BaseModel):
    """Project information from org discovery"""
    project_id: str
    project_name: str
    project_number: str
    status: str
    billing_enabled: Optional[bool] = None
    enabled_api_count: Optional[int] = None
    created_date: Optional[str] = None


class PrivilegeTestResult(BaseModel):
    """Result of privilege testing"""
    can_scan: Optional[bool] = None
    can_lockdown: Optional[bool] = None
    missing_permissions: List[str]
    test_results: dict


class TimerInfo(BaseModel):
    """Privilege escalation timer information"""
    timer_id: str
    started_at: str
    expires_at: str
    duration_minutes: int
    remaining_seconds: Optional[int] = None
    status: str  # "active" | "expired" | "revoked"


class PrivilegeStatus(BaseModel):
    """Current privilege status for a service account"""
    service_account_email: str
    privilege_level: str  # "none" | "viewer" | "elevated"
    active_timer: Optional[str] = None
    projects: List[str]
