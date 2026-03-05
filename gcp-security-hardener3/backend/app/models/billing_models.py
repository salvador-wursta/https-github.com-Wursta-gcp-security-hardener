from pydantic import BaseModel, Field, validator
from typing import Optional, List

class UpdateBudgetRequest(BaseModel):
    project_id: str = Field(..., description="GCP Project ID")
    amount: float = Field(..., gt=0, description="Monthly budget amount in USD")
    alert_emails: Optional[List[str]] = Field(None, description="Emails to alert when budget is exceeded")
    jit_token: Optional[str] = Field(None, description="JIT session token for authentication")
    credential_token: Optional[str] = Field(None, description="Credential token (legacy)")
    
    @validator('amount')
    def amount_must_be_positive(cls, v):
        if v <= 0:
            raise ValueError('Budget amount must be positive')
        return v

class UpdateBudgetResponse(BaseModel):
    success: bool
    budget_id: str
    message: str
    currency: str = "USD"
    amount: float
