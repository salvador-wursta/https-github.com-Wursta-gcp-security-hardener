"""
CSRF Token API Endpoints
Provides endpoints for generating and managing CSRF tokens
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from app.services.csrf_service import CSRFService
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/csrf", tags=["csrf"])


class CSRFTokenResponse(BaseModel):
    """Response containing a CSRF token"""
    csrf_token: str
    expires_in_seconds: int


class CSRFStatsResponse(BaseModel):
    """Response containing CSRF token statistics"""
    total_tokens: int
    active_tokens: int
    oldest_token_age_seconds: int = None
    newest_token_age_seconds: int = None
    token_expiry_seconds: int
    cleanup_interval_seconds: int


@router.get("/token", response_model=CSRFTokenResponse)
async def get_csrf_token():
    """
    Generate a new CSRF token.
    
    The token should be included in the X-CSRF-Token header for all
    state-changing operations (POST, PUT, DELETE).
    
    Tokens expire after 1 hour and should be refreshed as needed.
    
    Returns:
        CSRFTokenResponse: Contains the token and expiry time
    """
    try:
        token = CSRFService.generate_token()
        return CSRFTokenResponse(
            csrf_token=token,
            expires_in_seconds=CSRFService._token_expiry
        )
    except Exception as e:
        logger.error(f"Failed to generate CSRF token: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to generate CSRF token"
        )


@router.get("/stats", response_model=CSRFStatsResponse)
async def get_csrf_stats():
    """
    Get statistics about the CSRF token cache.
    For debugging and monitoring purposes.
    
    Returns:
        CSRFStatsResponse: Current CSRF token statistics
    """
    try:
        stats = CSRFService.get_stats()
        return CSRFStatsResponse(**stats)
    except Exception as e:
        logger.error(f"Failed to get CSRF stats: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get CSRF stats"
        )


@router.get("/health")
async def csrf_health():
    """Health check for CSRF service"""
    return {"status": "healthy", "service": "csrf"}
