"""
Credential upload endpoints
Secure two-step credential handling

Security Flow:
1. Client uploads credentials -> receives secure token
2. Client uses token in API request
3. Server retrieves credentials (token auto-deleted)
4. Server performs operation

Benefits:
- Credentials never in request bodies (after upload)
- Single-use tokens
- Automatic expiry (5 minutes)
- No credential caching in browser
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from app.services.credential_service import CredentialService
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/credentials", tags=["credentials"])


class CredentialUploadRequest(BaseModel):
    """Request to upload service account credentials"""
    service_account_key: Dict[str, Any] = Field(
        ..., 
        description="Full JSON content of the GCP service account key"
    )


class CredentialUploadResponse(BaseModel):
    """Response containing the secure token"""
    credential_token: str = Field(
        ..., 
        description="Short-lived, single-use token for the uploaded credentials"
    )
    expires_in_seconds: int = Field(
        ..., 
        description="Time until the token expires"
    )


class CacheStatsResponse(BaseModel):
    """Response containing cache statistics"""
    current_size: int
    active_entries: int
    oldest_entry_age_seconds: Optional[int]
    newest_entry_age_seconds: Optional[int]
    token_expiry_seconds: int
    cleanup_interval_seconds: int


@router.post("/upload", response_model=CredentialUploadResponse)
async def upload_credentials(request: CredentialUploadRequest):
    """
    Uploads service account credentials and returns a short-lived token.
    The token can then be used in subsequent API calls instead of the full credentials.
    
    NOW SUPPORTS TWO MODES:
    1. Traditional: service_account_key (JSON)
    2. JIT: superadmin credentials (will trigger service account creation)
    
    The token:
    - Expires after 5 minutes
    - Can only be used once (deleted after retrieval)
    - Is securely generated (32 bytes, URL-safe)
    
    Args:
        request: Contains either service account key JSON or superadmin credentials
        
    Returns:
        CredentialUploadResponse: Contains the token and expiry time
    """
    try:
        # Check if this is a superadmin authentication request
        # Superadmin credentials are identified by the presence of 'auth_type', 'username', 'password'
        if hasattr(request, 'service_account_key') and isinstance(request.service_account_key, dict):
            key_data = request.service_account_key
            
            # Check if it's superadmin format (has auth_type field)
            if key_data.get('auth_type') == 'dual-service-account':
                logger.info("Dual-service-account credentials detected - JIT with scanner/admin")
                
                # Validate fields
                if not key_data.get('scanner_credentials') or not key_data.get('admin_credentials'):
                    raise HTTPException(
                        status_code=400,
                        detail="Dual-service-account requires both scanner_credentials and admin_credentials"
                    )
                
                # Store the dual credentials as-is
                logger.info(f"Storing dual-service-account credentials")
                logger.info(f"Scanner: {key_data['scanner_credentials'].get('client_email')}")
                logger.info(f"Admin: {key_data['admin_credentials'].get('client_email')}")
                
                # Generate token
                credential_token = CredentialService.add_credentials(key_data)
                
                return CredentialUploadResponse(
                    credential_token=credential_token,
                    expires_in_seconds=300
                )
            
            elif key_data.get('auth_type') == 'superadmin':
                logger.info("Superadmin credentials detected - JIT workflow will be triggered")
                
                # Validate superadmin fields
                required_fields = ['username', 'password', 'org_id']
                missing = [f for f in required_fields if not key_data.get(f)]
                if missing:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Superadmin authentication requires: {', '.join(missing)}"
                    )
                
                # Store superadmin credentials with special marker
                # The credentials will include auth_type='superadmin' to trigger JIT flow
                logger.info(f"Storing superadmin credentials for: {key_data.get('username')}")
                token = CredentialService.add_credentials(key_data)
                
                return CredentialUploadResponse(
                    credential_token=token,
                    expires_in_seconds=CredentialService._token_expiry
                )
            
            # Traditional service account JSON
            project_id = key_data.get('project_id', 'N/A')
            client_email = key_data.get('client_email', 'N/A')
            logger.info(f"Service account credential upload for project: {project_id}, client: {client_email}")
            
            # Add credentials to cache and get token
            token = CredentialService.add_credentials(key_data)
            
            return CredentialUploadResponse(
                credential_token=token,
                expires_in_seconds=CredentialService._token_expiry
            )
        else:
            raise HTTPException(
                status_code=400,
                detail="service_account_key is required"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to upload credentials: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to upload credentials: {str(e)}"
        )


@router.get("/cache-stats", response_model=CacheStatsResponse)
async def get_cache_stats():
    """
    Returns statistics about the in-memory credential cache.
    For debugging and monitoring purposes.
    
    Returns:
        CacheStatsResponse: Current cache statistics
    """
    try:
        stats = CredentialService.get_cache_stats()
        return CacheStatsResponse(**stats)
    except Exception as e:
        logger.error(f"Failed to get cache stats: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to get cache stats: {str(e)}"
        )
