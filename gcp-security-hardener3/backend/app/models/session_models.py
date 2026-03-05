from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class JITSession(BaseModel):
    token: str
    created_at: datetime
    last_activity: datetime
    scanner_credentials: Dict[str, Any]
    admin_credentials: Optional[Dict[str, Any]] = None
    
class SessionStatus(BaseModel):
    is_active: bool
    remaining_seconds: int
    expires_at: datetime
    project_id: Optional[str] = None

class SessionInitRequest(BaseModel):
    scanner_key_content: str
    admin_key_content: Optional[str] = None
