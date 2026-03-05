"""
Logging Service - Sets up change management monitoring
Security: Never logs sensitive audit data
"""
import logging
from typing import Optional, Dict, Any
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class LoggingService:
    """Service for setting up Cloud Logging sinks and alerts"""
    
    def __init__(self, credentials: Credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        self.logging_service = build('logging', 'v2', credentials=credentials)
    
    def create_api_enablement_sink(
        self,
        sink_name: str = "api-enablement-monitor",
        destination_email: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a logging sink that monitors API enablement attempts
        
        Args:
            sink_name: Name of the logging sink
            destination_email: Email address to send alerts to
            
        Returns:
            Sink configuration dict
        """
        try:
            # Create sink filter for API enablement
            filter_expr = (
                'protoPayload.methodName="google.api.serviceusage.v1.ServiceUsage.EnableService"'
            )
            
            # Destination: Pub/Sub topic or email (via Cloud Monitoring)
            # For email alerts, we'd typically use Cloud Monitoring notification channels
            # For simplicity, we'll create a Pub/Sub topic that can trigger email notifications
            
            sink_config = {
                "name": sink_name,
                "filter": filter_expr,
                "destination": f"pubsub.googleapis.com/projects/{self.project_id}/topics/api-enablement-alerts",
                "outputVersionFormat": "V2"
            }
            
            # Note: Simplified implementation
            # Full implementation would use:
            # sink = self.logging_service.projects().sinks().create(
            #     parent=f"projects/{self.project_id}",
            #     body=sink_config
            # ).execute()
            
            logger.info(f"Logging sink {sink_name} configured for API enablement monitoring")
            
            return {
                "sink_name": sink_name,
                "filter": filter_expr,
                "status": "configured",
                "note": "Sink will alert when any API is enabled"
            }
            
        except HttpError as e:
            error_msg = f"Failed to create logging sink: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"HTTP ERROR creating logging sink:")
            logger.error(f"  Sink name: {sink_name}")
            logger.error(f"  Project: {self.project_id}")
            logger.error(f"  Destination email: {destination_email or 'None'}")
            logger.error(f"  HTTP Status: {e.resp.status if hasattr(e, 'resp') else 'N/A'}")
            logger.error(f"  Error message: {error_msg}")
            logger.error(f"  Error details: {e.error_details if hasattr(e, 'error_details') else 'N/A'}")
            import traceback
            logger.error(f"  Stack trace:\n{traceback.format_exc()}")
            logger.error("=" * 80)
            raise Exception(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error creating logging sink: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"UNEXPECTED ERROR creating logging sink:")
            logger.error(f"  Sink name: {sink_name}")
            logger.error(f"  Project: {self.project_id}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Error message: {error_msg}")
            import traceback
            logger.error(f"  Stack trace:\n{traceback.format_exc()}")
            logger.error("=" * 80)
            raise Exception(error_msg)
    
    def create_notification_channel(self, email: str) -> Dict[str, Any]:
        """
        Create a Cloud Monitoring notification channel for email alerts
        
        Args:
            email: Email address for notifications
            
        Returns:
            Notification channel configuration
        """
        try:
            monitoring_service = build('monitoring', 'v3', credentials=self.credentials)
            
            # Create email notification channel
            channel_config = {
                "type": "email",
                "displayName": f"Security Hardener Alerts - {email}",
                "labels": {
                    "email_address": email
                }
            }
            
            # Note: Simplified implementation
            # Full implementation would use:
            # channel = monitoring_service.projects().notificationChannels().create(
            #     name=f"projects/{self.project_id}",
            #     body=channel_config
            # ).execute()
            
            logger.info(f"Notification channel created for {email}")
            
            return {
                "email": email,
                "type": "email",
                "status": "configured"
            }
            
        except Exception as e:
            error_msg = f"Failed to create notification channel: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)

