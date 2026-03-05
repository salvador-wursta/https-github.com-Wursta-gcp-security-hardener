"""
Email Verification Service
Handles email verification tokens and sending verification emails
"""
import logging
import secrets
import time
from typing import Dict, Optional
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


class EmailVerificationService:
    """Service for email verification"""
    
    # In-memory storage for verification tokens (production should use Redis/database)
    _verification_tokens: Dict[str, Dict] = {}
    
    # Token expiry time (24 hours)
    TOKEN_EXPIRY_SECONDS = 86400
    
    @classmethod
    def generate_verification_token(cls, email: str) -> str:
        """
        Generate a unique verification token for an email
        
        Args:
            email: Email address to verify
            
        Returns:
            Verification token
        """
        # Generate a secure random token
        token = secrets.token_urlsafe(32)
        
        # Store token with email and expiry
        cls._verification_tokens[token] = {
            'email': email,
            'created_at': time.time(),
            'verified': False,
            'expires_at': time.time() + cls.TOKEN_EXPIRY_SECONDS
        }
        
        logger.info(f"[EMAIL_VERIFICATION] Generated token for {email}")
        return token
    
    @classmethod
    def verify_token(cls, token: str) -> Optional[str]:
        """
        Verify a token and return the associated email if valid
        
        Args:
            token: Verification token
            
        Returns:
            Email address if token is valid, None otherwise
        """
        if token not in cls._verification_tokens:
            logger.warning(f"[EMAIL_VERIFICATION] Invalid token: {token[:8]}...")
            return None
        
        token_data = cls._verification_tokens[token]
        
        # Check if token has expired
        if time.time() > token_data['expires_at']:
            logger.warning(f"[EMAIL_VERIFICATION] Expired token for {token_data['email']}")
            del cls._verification_tokens[token]
            return None
        
        # Mark as verified
        token_data['verified'] = True
        email = token_data['email']
        
        logger.info(f"[EMAIL_VERIFICATION] ✓ Token verified for {email}")
        return email
    
    @classmethod
    def is_email_verified(cls, email: str) -> bool:
        """
        Check if an email has been verified
        
        Args:
            email: Email address to check
            
        Returns:
            True if email is verified, False otherwise
        """
        # Check all tokens for this email
        for token_data in cls._verification_tokens.values():
            if token_data['email'] == email and token_data['verified']:
                # Check if still valid (not expired)
                if time.time() <= token_data['expires_at']:
                    return True
        
        return False
    
    @classmethod
    def cleanup_expired_tokens(cls):
        """Remove expired tokens from memory"""
        current_time = time.time()
        expired_tokens = [
            token for token, data in cls._verification_tokens.items()
            if current_time > data['expires_at']
        ]
        
        for token in expired_tokens:
            email = cls._verification_tokens[token]['email']
            del cls._verification_tokens[token]
            logger.info(f"[EMAIL_VERIFICATION] Cleaned up expired token for {email}")
    
    @classmethod
    def send_verification_email(cls, email: str, token: str, base_url: str = "http://localhost:3000") -> bool:
        """
        Send verification email with clickable link
        
        Args:
            email: Email address to send to
            token: Verification token
            base_url: Base URL of the frontend application
            
        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            verification_url = f"{base_url}/verify-email?token={token}"
            
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'Verify Your Email - GCP Security Hardener'
            msg['From'] = 'noreply@gcp-security-hardener.com'
            msg['To'] = email
            
            # Plain text version
            text = f"""
GCP Security Hardener - Email Verification

Hi there!

We need to verify your email address to ensure we can send you important security alerts.

Please click the link below to verify your email:
{verification_url}

This link will expire in 24 hours.

If you didn't request this, you can safely ignore this email.

---
GCP Security Hardener
Protecting your cloud from crypto-mining attacks
"""
            
            # HTML version
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px 10px 0 0;
            text-align: center;
        }}
        .content {{
            background: #f9fafb;
            padding: 30px;
            border: 1px solid #e5e7eb;
            border-top: none;
        }}
        .button {{
            display: inline-block;
            padding: 15px 30px;
            background: #667eea;
            color: white !important;
            text-decoration: none;
            border-radius: 8px;
            font-weight: bold;
            margin: 20px 0;
        }}
        .button:hover {{
            background: #5568d3;
        }}
        .footer {{
            background: #e5e7eb;
            padding: 20px;
            text-align: center;
            font-size: 12px;
            color: #6b7280;
            border-radius: 0 0 10px 10px;
        }}
        .warning {{
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1 style="margin: 0;">🛡️ GCP Security Hardener</h1>
        <p style="margin: 10px 0 0 0;">Email Verification Required</p>
    </div>
    
    <div class="content">
        <h2>Hi there!</h2>
        
        <p>We need to verify your email address to ensure we can send you important security alerts about your Google Cloud Platform project.</p>
        
        <p>Click the button below to verify your email:</p>
        
        <center>
            <a href="{verification_url}" class="button">
                ✓ Verify My Email
            </a>
        </center>
        
        <div class="warning">
            <strong>⏰ Important:</strong> This verification link will expire in 24 hours.
        </div>
        
        <p>If the button doesn't work, you can also copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #667eea;">{verification_url}</p>
        
        <p style="margin-top: 30px; color: #6b7280; font-size: 14px;">
            If you didn't request this email verification, you can safely ignore this message.
        </p>
    </div>
    
    <div class="footer">
        <p><strong>GCP Security Hardener</strong></p>
        <p>Protecting your cloud from crypto-mining attacks and unexpected costs</p>
        <p style="margin-top: 10px;">This is an automated email. Please do not reply to this message.</p>
    </div>
</body>
</html>
"""
            
            # Attach both plain text and HTML versions
            part1 = MIMEText(text, 'plain')
            part2 = MIMEText(html, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # For development: just log the email content
            # In production: use a real SMTP server or service like SendGrid, AWS SES, etc.
            logger.info("=" * 80)
            logger.info("[EMAIL_VERIFICATION] Email would be sent to: " + email)
            logger.info(f"[EMAIL_VERIFICATION] Verification URL: {verification_url}")
            logger.info("=" * 80)
            logger.info("[EMAIL_VERIFICATION] Development mode - email not actually sent")
            logger.info("[EMAIL_VERIFICATION] In production, configure SMTP or use a service like:")
            logger.info("[EMAIL_VERIFICATION]   - SendGrid")
            logger.info("[EMAIL_VERIFICATION]   - AWS SES (Simple Email Service)")
            logger.info("[EMAIL_VERIFICATION]   - Mailgun")
            logger.info("[EMAIL_VERIFICATION]   - Postmark")
            logger.info("=" * 80)
            
            # TODO: In production, uncomment and configure:
            # smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
            # smtp_port = int(os.getenv('SMTP_PORT', '587'))
            # smtp_username = os.getenv('SMTP_USERNAME')
            # smtp_password = os.getenv('SMTP_PASSWORD')
            #
            # with smtplib.SMTP(smtp_server, smtp_port) as server:
            #     server.starttls()
            #     server.login(smtp_username, smtp_password)
            #     server.send_message(msg)
            
            return True
            
        except Exception as e:
            logger.error(f"[EMAIL_VERIFICATION] Error sending verification email: {e}")
            return False
