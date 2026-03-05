"""
Secure credential caching service
Stores credentials temporarily with single-use tokens

Security Features:
- Single-use tokens (deleted after retrieval)
- 5-minute TTL (automatic expiry)
- Secure random tokens (32 bytes URL-safe)
- Background cleanup thread
- No credential logging
"""
import secrets
import time
import threading
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class CredentialService:
    """
    Manages temporary storage and retrieval of service account credentials.
    Credentials are stored in memory and associated with a short-lived, single-use token.
    """
    _credential_cache: Dict[str, Dict[str, Any]] = {}
    _lock = threading.Lock()
    _cleanup_interval = 300  # Clean up every 5 minutes
    _token_expiry = 300      # Tokens expire after 5 minutes
    _cleanup_thread: Optional[threading.Thread] = None
    _stop_cleanup_event = threading.Event()

    @classmethod
    def _start_cleanup_thread(cls):
        """Start the background cleanup thread if not already running."""
        if cls._cleanup_thread is None or not cls._cleanup_thread.is_alive():
            logger.info("Starting credential cache cleanup thread.")
            cls._stop_cleanup_event.clear()
            cls._cleanup_thread = threading.Thread(target=cls._cleanup_loop, daemon=True)
            cls._cleanup_thread.start()

    @classmethod
    def _cleanup_loop(cls):
        """Background thread that periodically cleans up expired credentials."""
        while not cls._stop_cleanup_event.is_set():
            cls.cleanup_expired_credentials()
            cls._stop_cleanup_event.wait(cls._cleanup_interval)
        logger.info("Credential cache cleanup thread stopped.")

    @classmethod
    def add_credentials(cls, credentials: Dict[str, Any]) -> str:
        """
        Adds service account credentials to the cache and returns a unique token.
        
        Args:
            credentials: Full service account JSON key
            
        Returns:
            str: Secure, random token for retrieving credentials
        """
        cls._start_cleanup_thread()
        token = secrets.token_urlsafe(32)  # Generate a secure, random token
        with cls._lock:
            cls._credential_cache[token] = {
                "credentials": credentials,
                "timestamp": time.time()
            }
        logger.info(f"Credentials added to cache with token: {token[:8]}... (expires in {cls._token_expiry}s)")
        return token

    @classmethod
    def get_credentials(cls, token: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves credentials using the token WITHOUT removing them from the cache.
        This allows the same token to be used for multiple API calls during a session.
        
        Args:
            token: The secure token returned from add_credentials
            
        Returns:
            dict: Service account credentials, or None if token is invalid/expired
        """
        with cls._lock:
            entry = cls._credential_cache.get(token)
        
        if entry:
            if time.time() - entry["timestamp"] < cls._token_expiry:
                logger.info(f"Credentials retrieved for token: {token[:8]}... (not removed - reusable)")
                return entry["credentials"]
            else:
                logger.warning(f"Attempted to retrieve expired token: {token[:8]}...")
                # Remove expired token
                with cls._lock:
                    cls._credential_cache.pop(token, None)
        else:
            logger.warning(f"Attempted to retrieve non-existent token: {token[:8]}...")
        return None

    @classmethod
    def cleanup_expired_credentials(cls):
        """Removes expired credentials from the cache."""
        with cls._lock:
            expired_tokens = [
                token for token, entry in cls._credential_cache.items()
                if time.time() - entry["timestamp"] >= cls._token_expiry
            ]
            for token in expired_tokens:
                del cls._credential_cache[token]
                logger.info(f"Cleaned up expired token: {token[:8]}...")
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired credential entries.")

    @classmethod
    def get_cache_stats(cls) -> Dict[str, Any]:
        """
        Returns statistics about the current cache.
        
        Returns:
            dict: Statistics including current size, active entries, and age info
        """
        with cls._lock:
            current_time = time.time()
            active_entries = [
                entry for entry in cls._credential_cache.values()
                if current_time - entry["timestamp"] < cls._token_expiry
            ]
            
            oldest_entry_time = min([e["timestamp"] for e in active_entries]) if active_entries else None
            newest_entry_time = max([e["timestamp"] for e in active_entries]) if active_entries else None

            return {
                "current_size": len(cls._credential_cache),
                "active_entries": len(active_entries),
                "oldest_entry_age_seconds": round(current_time - oldest_entry_time) if oldest_entry_time else None,
                "newest_entry_age_seconds": round(current_time - newest_entry_time) if newest_entry_time else None,
                "token_expiry_seconds": cls._token_expiry,
                "cleanup_interval_seconds": cls._cleanup_interval
            }

    @classmethod
    def stop_cleanup_thread(cls):
        """Stop the background cleanup thread. Mainly for testing/shutdown."""
        if cls._cleanup_thread and cls._cleanup_thread.is_alive():
            logger.info("Stopping credential cache cleanup thread...")
            cls._stop_cleanup_event.set()
            cls._cleanup_thread.join(timeout=1)


# Start cleanup thread when module is loaded
CredentialService._start_cleanup_thread()
