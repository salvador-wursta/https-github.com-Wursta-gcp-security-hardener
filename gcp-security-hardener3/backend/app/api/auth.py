"""
Authentication API endpoints
Handles Firebase authentication and token exchange
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from app.services.firebase_auth_service import FirebaseAuthService

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class TokenExchangeRequest(BaseModel):
    """Request to exchange Firebase token for GCP access"""
    firebase_id_token: str
    project_id: Optional[str] = None


class TokenExchangeResponse(BaseModel):
    """Response with GCP access token"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    user_info: dict


@router.post("/exchange", response_model=TokenExchangeResponse)
async def exchange_token(request: TokenExchangeRequest):
    """
    Exchange Firebase ID token for GCP access token
    
    This allows users to authenticate without needing OAuth Client ID.
    They just sign in with Google via Firebase, and we handle the rest.
    """
    try:
        # Verify Firebase token
        user_info = FirebaseAuthService.verify_firebase_token(request.firebase_id_token)
        
        # For now, return the Firebase token
        # In production, you'd exchange this for a GCP access token
        # This requires Firebase project to be linked to GCP project
        
        return TokenExchangeResponse(
            access_token=request.firebase_id_token,  # Will be exchanged in production
            user_info=user_info
        )
        
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token exchange failed: {str(e)}")


@router.get("/verify")
async def verify_token(firebase_id_token: str):
    """Verify a Firebase ID token"""
    try:
        user_info = FirebaseAuthService.verify_firebase_token(firebase_id_token)
        return {"valid": True, "user": user_info}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

