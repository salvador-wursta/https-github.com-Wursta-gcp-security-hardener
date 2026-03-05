"""
Privilege Timer Service
Manages time-limited privilege escalation with automatic de-escalation
"""
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import uuid

logger = logging.getLogger(__name__)


class PrivilegeTimerService:
    """Service for managing privilege escalation timers"""
    
    def __init__(self):
        # In production, this would use a database or Redis
        # For now, using in-memory storage
        self.active_timers: Dict[str, Dict[str, Any]] = {}
    
    def start_timer(
        self,
        service_account_email: str,
        project_ids: List[str],
        duration_minutes: int = 5
    ) -> Dict[str, Any]:
        """
        Start a privilege escalation timer
        
        Args:
            service_account_email: Service account that's elevated
            project_ids: Projects with elevated access
            duration_minutes: How long the elevation lasts
            
        Returns:
            {
                "timer_id": str,
                "started_at": datetime,
                "expires_at": datetime,
                "duration_minutes": int
            }
        """
        timer_id = str(uuid.uuid4())
        started_at = datetime.utcnow()
        expires_at = started_at + timedelta(minutes=duration_minutes)
        
        timer_data = {
            "timer_id": timer_id,
            "service_account_email": service_account_email,
            "project_ids": project_ids,
            "started_at": started_at,
            "expires_at": expires_at,
            "duration_minutes": duration_minutes,
            "status": "active"
        }
        
        self.active_timers[timer_id] = timer_data
        
        logger.info(f"[TIMER] Started timer {timer_id} for {service_account_email}")
        logger.info(f"[TIMER] Duration: {duration_minutes} minutes, expires at {expires_at}")
        
        return {
            "timer_id": timer_id,
            "started_at": started_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "duration_minutes": duration_minutes
        }
    
    def check_timer_status(self, timer_id: str) -> Dict[str, Any]:
        """
        Check the status of a timer
        
        Args:
            timer_id: Timer ID to check
            
        Returns:
            {
                "timer_id": str,
                "status": str,  # "active" | "expired" | "revoked"
                "remaining_seconds": int,
                "expired": bool
            }
        """
        if timer_id not in self.active_timers:
            return {
                "error": "Timer not found",
                "timer_id": timer_id
            }
        
        timer = self.active_timers[timer_id]
        now = datetime.utcnow()
        
        # Check if expired
        if now >= timer["expires_at"]:
            timer["status"] = "expired"
            expired = True
            remaining_seconds = 0
        else:
            remaining_seconds = int((timer["expires_at"] - now).total_seconds())
            expired = False
        
        return {
            "timer_id": timer_id,
            "status": timer["status"],
            "remaining_seconds": remaining_seconds,
            "expired": expired,
            "service_account_email": timer["service_account_email"],
            "project_ids": timer["project_ids"]
        }
    
    def force_expire(self, timer_id: str) -> Dict[str, Any]:
        """
        Manually expire a timer (user clicked "Finished")
        
        Args:
            timer_id: Timer to expire
            
        Returns:
            {
                "success": bool,
                "timer_id": str,
                "status": str
            }
        """
        if timer_id not in self.active_timers:
            return {
                "success": False,
                "error": "Timer not found"
            }
        
        self.active_timers[timer_id]["status"] = "revoked"
        self.active_timers[timer_id]["revoked_at"] = datetime.utcnow()
        
        logger.info(f"[TIMER] Manually expired timer {timer_id}")
        
        return {
            "success": True,
            "timer_id": timer_id,
            "status": "revoked"
        }
    
    def get_expired_timers(self) -> List[Dict[str, Any]]:
        """
        Get all timers that have expired but haven't been cleaned up
        
        Returns:
            List of expired timer data
        """
        now = datetime.utcnow()
        expired = []
        
        for timer_id, timer in self.active_timers.items():
            if timer["status"] == "active" and now >= timer["expires_at"]:
                timer["status"] = "expired"
                expired.append(timer)
        
        return expired
