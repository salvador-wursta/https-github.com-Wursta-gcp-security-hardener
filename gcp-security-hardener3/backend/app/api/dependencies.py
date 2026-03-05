"""
FastAPI dependencies for authentication and authorization

This module provides reusable dependencies that can be injected into
FastAPI endpoints to enforce authentication requirements.
"""
from fastapi import Header, HTTPException
from typing import Optional
from app.services.firebase_auth_service import FirebaseAuthService
import logging

logger = logging.getLogger(__name__)


async def verify_token(authorization: str = Header(None)) -> dict:
    """
    Dependency to verify Firebase authentication token on protected endpoints
    
    This function:
    - Extracts Bearer token from Authorization header
    - Validates token with Firebase Auth
    - Returns user information if valid
    - Raises 401 error if invalid or missing
    
    Usage in endpoints:
        @router.post("/endpoint")
        async def my_endpoint(user: dict = Depends(verify_token)):
            # user dict contains: uid, email, name
            pass
    
    Args:
        authorization: Authorization header (automatically injected by FastAPI)
    
    Returns:
        dict: User information with keys:
            - uid: User ID
            - email: User email address
            - name: User display name
    
    Raises:
        HTTPException: 401 if token is missing, invalid, or expired
    """
    if not authorization:
        logger.warning("Authentication attempt without Authorization header")
        raise HTTPException(
            status_code=401,
            detail="Authorization header missing. Please provide a valid Bearer token."
        )
    
    try:
        # Parse Bearer token
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            logger.warning(f"Invalid authentication scheme provided")
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication scheme. Use: Bearer <token>"
            )
        
        token = parts[1]
        
        # Verify with Firebase
        user_info = FirebaseAuthService.verify_firebase_token(token)
        
        # Log successful authentication (email is already redacted by logging filter)
        logger.info(f"Authenticated user: {user_info.get('email', 'unknown')}")
        
        return user_info
    
    except ValueError as e:
        # Firebase verification failed
        logger.warning(f"Token verification failed: {str(e)}")
        raise HTTPException(
            status_code=401, 
            detail=f"Authentication failed: {str(e)}"
        )
    except Exception as e:
        # Unexpected error
        logger.error(f"Unexpected authentication error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token"
        )


async def verify_token_optional(authorization: str = Header(None)) -> Optional[dict]:
    """
    Optional authentication dependency
    
    Similar to verify_token, but returns None instead of raising an error
    if no token is provided. Useful for endpoints that have enhanced features
    for authenticated users but are also accessible anonymously.
    
    Args:
        authorization: Authorization header (automatically injected by FastAPI)
    
    Returns:
        Optional[dict]: User information if authenticated, None if not
    """
    if not authorization:
        return None
    
    try:
        return await verify_token(authorization)
    except HTTPException:
        return None

async def verify_jit_session(x_jit_token: str = Header(None), authorization: str = Header(None)) -> dict:
    """
    Verify JIT session token and return credentials.
    Standardized to handle X-JIT-Token or Authorization headers.
    """
    from app.services.jit_session_service import JITSessionService
    
    token = x_jit_token
    
    # Fallback to Authorization header if X-JIT-Header is missing
    if not token and authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == 'bearer':
            token = parts[1]
            logger.debug("verify_jit_session: Falling back to Bearer token from Authorization header")
    
    logger.debug(f"DEBUG verify_jit_session: Final Token: {token[:8] if token else 'NONE'}")
    
    if not token:
        logger.warning("verify_jit_session: No token found in X-Jit-Token or Authorization header")
        raise HTTPException(
            status_code=401,
            detail="Missing JIT session token"
        )
        
    service = JITSessionService()
    logger.debug(f"DEBUG verify_jit_session: Active sessions in memory: {len(service._sessions)}")
    
    session = service.access_session(token)
    
    if not session:
        logger.warning(f"verify_jit_session: Token {token[:8]}... not found in active sessions")
        raise HTTPException(
            status_code=401,
            detail="Session expired or invalid. Please re-upload credentials."
        )
        
    return {
        "scanner_credentials": session.scanner_credentials,
        "admin_credentials": session.admin_credentials,
        "token": session.token
    }

