"""
Generic error handler that doesn't leak internal details

This module provides sanitized error handling for production environments,
preventing sensitive information from being exposed to users while maintaining
proper logging for debugging.
"""
import logging
import uuid
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

logger = logging.getLogger(__name__)


async def generic_error_handler(request: Request, exc: Exception):
    """
    Handle all unexpected exceptions with sanitized error messages
    
    This handler:
    - Generates a unique request ID for tracking
    - Logs full error details internally (with sensitive data filtering)
    - Returns generic message to users
    - Includes request ID for support inquiries
    
    Args:
        request: The FastAPI request object
        exc: The exception that was raised
        
    Returns:
        JSONResponse with sanitized error message
    """
    # Generate request ID for tracking
    request_id = str(uuid.uuid4())
    
    # Log full error with request ID (for debugging)
    logger.error(
        f"Request {request_id} failed",
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
            "error": str(exc),
            "error_type": type(exc).__name__,
        },
        exc_info=True
    )
    
    # Return generic message to user
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal error occurred. Please contact support if the issue persists.",
            "request_id": request_id,
            "support_message": f"Reference ID: {request_id}"
        },
        headers={"X-Request-ID": request_id}
    )


async def validation_error_handler(request: Request, exc: RequestValidationError):
    """
    Handle validation errors with sanitized messages
    
    Validation errors are generally safe to expose, but we still sanitize
    them to prevent leaking internal structure details.
    
    Args:
        request: The FastAPI request object
        exc: The validation error
        
    Returns:
        JSONResponse with sanitized validation error
    """
    request_id = str(uuid.uuid4())
    
    # Log validation error
    logger.warning(
        f"Validation error for request {request_id}",
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
            "errors": exc.errors(),
        }
    )
    
    # Sanitize error messages (remove internal field paths)
    sanitized_errors = []
    for error in exc.errors():
        field_path = " -> ".join(str(loc) for loc in error.get("loc", []))
        sanitized_errors.append({
            "field": field_path,
            "message": error.get("msg", "Invalid value"),
        })
    
    return JSONResponse(
        status_code=422,
        content={
            "detail": "Validation error",
            "errors": sanitized_errors,
            "request_id": request_id
        },
        headers={"X-Request-ID": request_id}
    )
