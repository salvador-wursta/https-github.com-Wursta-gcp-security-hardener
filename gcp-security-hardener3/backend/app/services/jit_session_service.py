import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import json
from app.models.session_models import JITSession, SessionStatus

logger = logging.getLogger(__name__)

class JITSessionService:
    """
    Manages JIT sessions with strict timeouts and in-memory credential storage.
    Singleton pattern to ensure persistent state across API calls.
    """
    _instance = None
    _sessions: Dict[str, JITSession] = {}
    
    SESSION_TIMEOUT_MINUTES = 60
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(JITSessionService, cls).__new__(cls)
        return cls._instance
    
    def start_session(self, scanner_key: str, admin_key: Optional[str]) -> str:
        """
        Start a new JIT session with uploaded credentials.
        Returns a session token.
        """
        try:
            # Parse JSONs to ensure valid format and store as dicts
            scanner_creds = json.loads(scanner_key)
            admin_creds = json.loads(admin_key) if admin_key else None
            
            token = secrets.token_urlsafe(32)
            now = datetime.now()
            
            session = JITSession(
                token=token,
                created_at=now,
                last_activity=now,
                scanner_credentials=scanner_creds,
                admin_credentials=admin_creds
            )
            
            self._sessions[token] = session
            logger.info(f"Started new JIT session: {token[:8]}...")
            
            # Clean up old sessions
            self._purge_expired()
            
            return token
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse credential keys: {e}")
            raise ValueError("Invalid JSON credential format")
        except Exception as e:
            logger.error(f"Error starting JIT session: {e}")
            raise

    def access_session(self, token: str) -> Optional[JITSession]:
        """
        Retrieve session and update activity timestamp.
        Returns None if expired or invalid.
        """
        if token not in self._sessions:
            return None
            
        session = self._sessions[token]
        
        # Check expiry
        if self._is_expired(session):
            self.end_session(token)
            return None
            
        # Update activity
        session.last_activity = datetime.now()
        return session

    def get_credentials(self, token: str) -> Optional[Tuple[Dict, Dict]]:
        """
        Get credentials for a valid session.
        Returns (scanner_creds, admin_creds) or None.
        """
        session = self.access_session(token)
        if session:
            return session.scanner_credentials, session.admin_credentials
        return None

    def get_status(self, token: str) -> SessionStatus:
        """
        Get session status without updating activity (optional).
        """
        if token not in self._sessions:
            return SessionStatus(is_active=False, remaining_seconds=0, expires_at=datetime.min)
            
        session = self._sessions[token]
        if self._is_expired(session):
            self.end_session(token)
            return SessionStatus(is_active=False, remaining_seconds=0, expires_at=datetime.min)
            
        timeout_delta = timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)
        expires_at = session.last_activity + timeout_delta
        remaining = (expires_at - datetime.now()).total_seconds()
        
        # Extract project_id from scanner credentials (which is mandatory)
        project_id = session.scanner_credentials.get("project_id")

        return SessionStatus(
            is_active=True,
            remaining_seconds=int(max(0, remaining)),
            expires_at=expires_at,
            project_id=project_id
        )

    def end_session(self, token: str):
        """Terminate a session immediately."""
        if token in self._sessions:
            del self._sessions[token]
            logger.info(f"Terminated JIT session: {token[:8]}...")

    def _is_expired(self, session: JITSession) -> bool:
        timeout = timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)
        return datetime.now() - session.last_activity > timeout

    def _purge_expired(self):
        """Remove all expired sessions."""
        tokens_to_remove = []
        for token, session in self._sessions.items():
            if self._is_expired(session):
                tokens_to_remove.append(token)
        
        for token in tokens_to_remove:
            self.end_session(token)
