"""
CSRF Token Service
Generates and validates CSRF tokens to prevent cross-site request forgery attacks

Security Features:
- Secure random token generation
- Time-based expiration (1 hour)
- Token validation with automatic cleanup
- Thread-safe implementation
"""
import secrets
import time
import threading
from typing import Optional, Dict
import logging

logger = logging.getLogger(__name__)


class CSRFService:
    """
    Manages CSRF tokens for preventing cross-site request forgery
    """
    _tokens: Dict[str, float] = {}  # token -> timestamp
    _lock = threading.Lock()
    _token_expiry = 3600  # 1 hour
    _cleanup_interval = 600  # Clean up every 10 minutes
    _cleanup_thread: Optional[threading.Thread] = None
    _stop_cleanup_event = threading.Event()

    @classmethod
    def _start_cleanup_thread(cls):
        """Start the background cleanup thread if not already running."""
        if cls._cleanup_thread is None or not cls._cleanup_thread.is_alive():
            logger.info("Starting CSRF token cleanup thread.")
            cls._stop_cleanup_event.clear()
            cls._cleanup_thread = threading.Thread(target=cls._cleanup_loop, daemon=True)
            cls._cleanup_thread.start()

    @classmethod
    def _cleanup_loop(cls):
        """Background thread that periodically cleans up expired tokens."""
        while not cls._stop_cleanup_event.is_set():
            cls.cleanup_expired_tokens()
            cls._stop_cleanup_event.wait(cls._cleanup_interval)
        logger.info("CSRF token cleanup thread stopped.")

    @classmethod
    def generate_token(cls) -> str:
        """
        Generate a new CSRF token.
        
        Returns:
            str: A secure, random CSRF token (32 bytes URL-safe)
        """
        cls._start_cleanup_thread()
        token = secrets.token_urlsafe(32)
        with cls._lock:
            cls._tokens[token] = time.time()
        logger.info(f"Generated CSRF token: {token[:8]}... (expires in {cls._token_expiry}s)")
        return token

    @classmethod
    def validate_token(cls, token: str) -> bool:
        """
        Validate a CSRF token.
        
        Args:
            token: The CSRF token to validate
            
        Returns:
            bool: True if token is valid and not expired, False otherwise
        """
        if not token:
            logger.warning("CSRF validation failed: Empty token")
            return False
        
        with cls._lock:
            if token not in cls._tokens:
                logger.warning(f"CSRF validation failed: Token not found: {token[:8]}...")
                return False
            
            timestamp = cls._tokens[token]
            if time.time() - timestamp > cls._token_expiry:
                logger.warning(f"CSRF validation failed: Token expired: {token[:8]}...")
                del cls._tokens[token]
                return False
        
        logger.info(f"CSRF token validated successfully: {token[:8]}...")
        return True

    @classmethod
    def revoke_token(cls, token: str):
        """
        Revoke a CSRF token (delete it from storage).
        
        Args:
            token: The CSRF token to revoke
        """
        with cls._lock:
            if token in cls._tokens:
                del cls._tokens[token]
                logger.info(f"Revoked CSRF token: {token[:8]}...")

    @classmethod
    def cleanup_expired_tokens(cls):
        """Remove expired CSRF tokens from storage."""
        current_time = time.time()
        with cls._lock:
            expired_tokens = [
                token for token, timestamp in cls._tokens.items()
                if current_time - timestamp >= cls._token_expiry
            ]
            for token in expired_tokens:
                del cls._tokens[token]
        
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired CSRF tokens.")

    @classmethod
    def get_stats(cls) -> Dict[str, any]:
        """
        Get statistics about the CSRF token cache.
        
        Returns:
            dict: Statistics including token count, oldest/newest token age
        """
        with cls._lock:
            current_time = time.time()
            active_tokens = [
                timestamp for timestamp in cls._tokens.values()
                if current_time - timestamp < cls._token_expiry
            ]
            
            oldest_token_time = min(active_tokens) if active_tokens else None
            newest_token_time = max(active_tokens) if active_tokens else None

            return {
                "total_tokens": len(cls._tokens),
                "active_tokens": len(active_tokens),
                "oldest_token_age_seconds": round(current_time - oldest_token_time) if oldest_token_time else None,
                "newest_token_age_seconds": round(current_time - newest_token_time) if newest_token_time else None,
                "token_expiry_seconds": cls._token_expiry,
                "cleanup_interval_seconds": cls._cleanup_interval
            }

    @classmethod
    def stop_cleanup_thread(cls):
        """Stop the background cleanup thread. Mainly for testing/shutdown."""
        if cls._cleanup_thread and cls._cleanup_thread.is_alive():
            logger.info("Stopping CSRF token cleanup thread...")
            cls._stop_cleanup_event.set()
            cls._cleanup_thread.join(timeout=1)


# Start cleanup thread when module is loaded
CSRFService._start_cleanup_thread()
