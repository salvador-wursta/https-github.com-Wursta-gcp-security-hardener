"""
API endpoints for email verification
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr
from app.services.email_verification_service import EmailVerificationService
import logging

router = APIRouter(prefix="/api/v1/email", tags=["email"])
logger = logging.getLogger(__name__)


class SendVerificationRequest(BaseModel):
    """Request to send verification email"""
    email: EmailStr


class SendVerificationResponse(BaseModel):
    """Response from sending verification email"""
    success: bool
    message: str
    token: str  # Return token for development/testing


class VerifyEmailRequest(BaseModel):
    """Request to verify email"""
    token: str


class VerifyEmailResponse(BaseModel):
    """Response from verifying email"""
    success: bool
    email: str = None
    message: str


class CheckVerificationRequest(BaseModel):
    """Request to check if email is verified"""
    email: EmailStr


class CheckVerificationResponse(BaseModel):
    """Response from checking verification status"""
    verified: bool
    email: str


@router.post("/send-verification", response_model=SendVerificationResponse)
async def send_verification_email(request: SendVerificationRequest, http_request: Request):
    """
    Send verification email to the provided email address
    
    Args:
        request: Email address to verify
        
    Returns:
        Success status and verification token
    """
    try:
        logger.info(f"[EMAIL_API] Sending verification email to: {request.email}")
        
        # Generate verification token
        token = EmailVerificationService.generate_verification_token(request.email)
        
        # Get base URL from request
        # In production, use a configured frontend URL
        base_url = http_request.headers.get('origin', 'http://localhost:3000')
        
        # Send verification email
        email_sent = EmailVerificationService.send_verification_email(
            email=request.email,
            token=token,
            base_url=base_url
        )
        
        if email_sent:
            logger.info(f"[EMAIL_API] ✓ Verification email sent to {request.email}")
            return SendVerificationResponse(
                success=True,
                message="Verification email sent successfully. Please check your inbox.",
                token=token  # Return token for development (remove in production)
            )
        else:
            logger.error(f"[EMAIL_API] Failed to send verification email to {request.email}")
            raise HTTPException(
                status_code=500,
                detail="Failed to send verification email. Please try again later."
            )
            
    except Exception as e:
        logger.error(f"[EMAIL_API] Error sending verification email: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error sending verification email: {str(e)}"
        )


@router.post("/verify", response_model=VerifyEmailResponse)
async def verify_email(request: VerifyEmailRequest):
    """
    Verify an email using a token
    
    Args:
        request: Verification token
        
    Returns:
        Success status and verified email
    """
    try:
        logger.info(f"[EMAIL_API] Verifying token: {request.token[:8]}...")
        
        # Verify token
        email = EmailVerificationService.verify_token(request.token)
        
        if email:
            logger.info(f"[EMAIL_API] ✓ Email verified: {email}")
            return VerifyEmailResponse(
                success=True,
                email=email,
                message=f"Email {email} has been verified successfully!"
            )
        else:
            logger.warning(f"[EMAIL_API] Invalid or expired token: {request.token[:8]}...")
            return VerifyEmailResponse(
                success=False,
                email=None,
                message="Invalid or expired verification token. Please request a new verification email."
            )
            
    except Exception as e:
        logger.error(f"[EMAIL_API] Error verifying email: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error verifying email: {str(e)}"
        )


@router.post("/check-verification", response_model=CheckVerificationResponse)
async def check_verification(request: CheckVerificationRequest):
    """
    Check if an email has been verified
    
    Args:
        request: Email address to check
        
    Returns:
        Verification status
    """
    try:
        logger.info(f"[EMAIL_API] Checking verification status for: {request.email}")
        
        is_verified = EmailVerificationService.is_email_verified(request.email)
        
        logger.info(f"[EMAIL_API] Email {request.email} verified: {is_verified}")
        
        return CheckVerificationResponse(
            verified=is_verified,
            email=request.email
        )
            
    except Exception as e:
        logger.error(f"[EMAIL_API] Error checking verification: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error checking verification: {str(e)}"
        )


@router.post("/cleanup")
async def cleanup_expired_tokens():
    """
    Cleanup expired verification tokens (admin endpoint)
    
    Returns:
        Success status
    """
    try:
        logger.info("[EMAIL_API] Cleaning up expired tokens...")
        EmailVerificationService.cleanup_expired_tokens()
        logger.info("[EMAIL_API] ✓ Cleanup complete")
        
        return {"success": True, "message": "Expired tokens cleaned up"}
            
    except Exception as e:
        logger.error(f"[EMAIL_API] Error during cleanup: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error during cleanup: {str(e)}"
        )
