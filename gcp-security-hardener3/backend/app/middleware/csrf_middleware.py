"""
CSRF Protection Middleware
Validates CSRF tokens for state-changing operations

Security Features:
- Validates X-CSRF-Token header on POST, PUT, DELETE requests
- Exempts safe methods (GET, HEAD, OPTIONS)
- Exempts specific paths (health checks, token generation)
- Returns 403 Forbidden for invalid/missing tokens
"""
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from app.services.csrf_service import CSRFService
import logging

logger = logging.getLogger(__name__)


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce CSRF token validation on state-changing operations.
    """
    
    # HTTP methods that require CSRF protection
    PROTECTED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
    
    # Paths that are exempt from CSRF protection
    EXEMPT_PATHS = {
        "/api/v1/csrf/token",                      # Token generation endpoint
        "/api/v1/csrf/stats",                       # Stats endpoint
        "/api/v1/auth/",                            # Auth endpoints
        "/api/v1/credentials/upload",               # Credential upload (happens before CSRF token available)
        "/api/v1/projects/list",                    # Project listing (read-only operation)
        "/api/v1/lockdown/generate-script",         # Script generation (read-only, no state change)
        "/api/v1/lockdown/generate-multi-script",   # Multi-project script generation
        "/api/v1/backout/generate-script",          # Backout script generation
        "/api/v1/org-monitoring/get-org-id",        # Auto-detect Organization ID
        "/api/v1/lockdown/generate-script-v2",      # New granular script generation
        "/api/v1/session/start",                    # JIT session start (initial auth)
        "/docs",                                    # API documentation
        "/openapi.json",                            # OpenAPI spec
        "/redoc",                                   # ReDoc documentation
    }
    
    MAX_TOKEN_AGE = 3600  # 1 hour
    
    # Path prefixes that are exempt
    EXEMPT_PREFIXES = [
        "/health",                   # Health check endpoints
        "/api/v1/scan",              # Scan endpoints (uses JIT Bearer token)
        "/api/v1/report",            # Reporting endpoints (uses JIT Token)
        "/api/v1/clients",           # Client management (Local data)
    ]

    async def dispatch(self, request: Request, call_next):
        """
        Process each request and validate CSRF token if required.
        """
        # Skip CSRF check for safe methods
        if request.method not in self.PROTECTED_METHODS:
            return await call_next(request)
        
        # Skip CSRF check for exempt paths
        path = request.url.path
        if path in self.EXEMPT_PATHS:
            logger.debug(f"CSRF check skipped for exempt path: {path}")
            return await call_next(request)
        
        # Skip CSRF check for exempt path prefixes
        for prefix in self.EXEMPT_PREFIXES:
            if path.startswith(prefix) or path.endswith(prefix):
                logger.debug(f"CSRF check skipped for exempt prefix: {path}")
                return await call_next(request)
        
        # Get CSRF token from header
        csrf_token = request.headers.get("X-CSRF-Token")
        
        if not csrf_token:
            logger.warning(f"CSRF token missing for {request.method} {path}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "detail": "CSRF token missing. Include X-CSRF-Token header in your request.",
                    "error": "csrf_token_missing"
                }
            )
        
        # Validate CSRF token
        if not CSRFService.validate_token(csrf_token):
            logger.warning(f"Invalid CSRF token for {request.method} {path}: {csrf_token[:8]}...")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "detail": "Invalid or expired CSRF token. Please refresh your token.",
                    "error": "csrf_token_invalid"
                }
            )
        
        # Token is valid, proceed with request
        logger.debug(f"CSRF token validated for {request.method} {path}")
        return await call_next(request)
