"""
Compute Monitoring Service
Sets up log-based alerts for compute resource creation and usage
"""
import logging
from typing import Dict, Any, Optional
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from app.config.monitoring_config import EXTENDED_ALERTS

logger = logging.getLogger(__name__)


class ComputeMonitoringService:
    """Service for setting up compute resource monitoring and alerts"""
    
    def __init__(self, credentials: Credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        
    def create_email_notification_channel(self, email: str) -> str:
        """
        Create an email notification channel for alerts
        
        Args:
            email: Email address to send notifications to
            
        Returns:
            Notification channel ID
        """
        try:
            logger.info(f"[MONITORING] Creating email notification channel for {email}")
            
            monitoring = build('monitoring', 'v3', credentials=self.credentials)
            
            # Check if channel already exists
            project_name = f"projects/{self.project_id}"
            existing_channels = monitoring.projects().notificationChannels().list(
                name=project_name
            ).execute()
            
            for channel in existing_channels.get('notificationChannels', []):
                if channel.get('type') == 'email' and channel.get('labels', {}).get('email_address') == email:
                    logger.info(f"[MONITORING] ✓ Email notification channel already exists: {channel['name']}")
                    return channel['name']
            
            # Create new email notification channel
            channel_config = {
                'type': 'email',
                'displayName': f'GCP Security Hardener Alerts - {email}',
                'description': 'Email alerts for compute resource creation',
                'labels': {
                    'email_address': email
                },
                'enabled': True
            }
            
            channel = monitoring.projects().notificationChannels().create(
                name=project_name,
                body=channel_config
            ).execute()
            
            channel_id = channel['name']
            logger.info(f"[MONITORING] ✓ Created email notification channel: {channel_id}")
            return channel_id
            
        except HttpError as e:
            logger.error(f"[MONITORING] Failed to create notification channel: {str(e)}")
            raise Exception(f"Failed to create email notification channel: {str(e)}")
    
    def create_vm_creation_alert(self, notification_channel_id: str) -> Dict[str, Any]:
        """
        Create log-based alert for VM instance creation
        
        Args:
            notification_channel_id: Notification channel to send alerts to
            
        Returns:
            Alert policy details
        """
        try:
            logger.info("[MONITORING] Creating VM creation alert...")
            
            monitoring = build('monitoring', 'v3', credentials=self.credentials)
            project_name = f"projects/{self.project_id}"
            
            # Log filter for VM creation
            log_filter = '''
            resource.type="gce_instance"
            protoPayload.methodName="v1.compute.instances.insert"
            severity="NOTICE"
            '''
            
            alert_policy = {
                'displayName': 'VM Instance Created Alert',
                'documentation': {
                    'content': '⚠️ A new VM instance was created in your GCP project. If this was not authorized, investigate immediately.',
                    'mimeType': 'text/markdown'
                },
                'conditions': [{
                    'displayName': 'VM Instance Created',
                    'conditionThreshold': {
                        'filter': f'resource.type="logging.googleapis.com/log" AND metric.type="logging.googleapis.com/user/{self.project_id}/vm_creation" AND {log_filter}',
                        'comparison': 'COMPARISON_GT',
                        'thresholdValue': 0,
                        'duration': {'seconds': 0},
                        'aggregations': [{
                            'alignmentPeriod': {'seconds': 60},
                            'perSeriesAligner': 'ALIGN_RATE'
                        }]
                    }
                }],
                'combiner': 'OR',
                'enabled': True,
                'notificationChannels': [notification_channel_id],
                'alertStrategy': {
                    'autoClose': {'seconds': 604800}  # 7 days
                }
            }
            
            policy = monitoring.projects().alertPolicies().create(
                name=project_name,
                body=alert_policy
            ).execute()
            
            logger.info(f"[MONITORING] ✓ Created VM creation alert: {policy['name']}")
            return {'success': True, 'policy_name': policy['name']}
            
        except HttpError as e:
            logger.warning(f"[MONITORING] Could not create VM creation alert: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def create_gpu_attachment_alert(self, notification_channel_id: str) -> Dict[str, Any]:
        """
        Create log-based alert for GPU attachment to VMs
        
        Args:
            notification_channel_id: Notification channel to send alerts to
            
        Returns:
            Alert policy details
        """
        try:
            logger.info("[MONITORING] Creating GPU attachment alert...")
            
            monitoring = build('monitoring', 'v3', credentials=self.credentials)
            project_name = f"projects/{self.project_id}"
            
            # Log filter for GPU attachment
            log_filter = '''
            resource.type="gce_instance"
            (protoPayload.methodName="v1.compute.instances.attachDisk" OR 
             protoPayload.methodName="v1.compute.instances.insert")
            (protoPayload.request.guestAccelerators:* OR
             protoPayload.request.machineType=~".*gpu.*")
            '''
            
            alert_policy = {
                'displayName': 'GPU Attached to VM Alert',
                'documentation': {
                    'content': '🚨 CRITICAL: A GPU was attached to a VM instance. GPUs are extremely expensive and often used for crypto-mining. Investigate immediately!',
                    'mimeType': 'text/markdown'
                },
                'conditions': [{
                    'displayName': 'GPU Attached',
                    'conditionThreshold': {
                        'filter': f'resource.type="logging.googleapis.com/log" AND metric.type="logging.googleapis.com/user/{self.project_id}/gpu_attachment" AND {log_filter}',
                        'comparison': 'COMPARISON_GT',
                        'thresholdValue': 0,
                        'duration': {'seconds': 0},
                        'aggregations': [{
                            'alignmentPeriod': {'seconds': 60},
                            'perSeriesAligner': 'ALIGN_RATE'
                        }]
                    }
                }],
                'combiner': 'OR',
                'enabled': True,
                'notificationChannels': [notification_channel_id],
                'alertStrategy': {
                    'autoClose': {'seconds': 604800}
                }
            }
            
            policy = monitoring.projects().alertPolicies().create(
                name=project_name,
                body=alert_policy
            ).execute()
            
            logger.info(f"[MONITORING] ✓ Created GPU attachment alert: {policy['name']}")
            return {'success': True, 'policy_name': policy['name']}
            
        except HttpError as e:
            logger.warning(f"[MONITORING] Could not create GPU attachment alert: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def create_expensive_machine_type_alert(self, notification_channel_id: str) -> Dict[str, Any]:
        """
        Create log-based alert for expensive machine types (N2, C2)
        
        Args:
            notification_channel_id: Notification channel to send alerts to
            
        Returns:
            Alert policy details
        """
        try:
            logger.info("[MONITORING] Creating expensive machine type alert...")
            
            monitoring = build('monitoring', 'v3', credentials=self.credentials)
            project_name = f"projects/{self.project_id}"
            
            # Log filter for N2/C2 machine types
            log_filter = '''
            resource.type="gce_instance"
            protoPayload.methodName="v1.compute.instances.insert"
            (protoPayload.request.machineType=~".*n2-.*" OR 
             protoPayload.request.machineType=~".*c2-.*")
            '''
            
            alert_policy = {
                'displayName': 'Expensive Machine Type Created Alert',
                'documentation': {
                    'content': '💰 WARNING: An expensive machine type (N2 or C2) was created. These are high-performance instances that cost significantly more. Verify this is authorized.',
                    'mimeType': 'text/markdown'
                },
                'conditions': [{
                    'displayName': 'N2/C2 Instance Created',
                    'conditionThreshold': {
                        'filter': f'resource.type="logging.googleapis.com/log" AND metric.type="logging.googleapis.com/user/{self.project_id}/expensive_machine" AND {log_filter}',
                        'comparison': 'COMPARISON_GT',
                        'thresholdValue': 0,
                        'duration': {'seconds': 0},
                        'aggregations': [{
                            'alignmentPeriod': {'seconds': 60},
                            'perSeriesAligner': 'ALIGN_RATE'
                        }]
                    }
                }],
                'combiner': 'OR',
                'enabled': True,
                'notificationChannels': [notification_channel_id],
                'alertStrategy': {
                    'autoClose': {'seconds': 604800}
                }
            }
            
            policy = monitoring.projects().alertPolicies().create(
                name=project_name,
                body=alert_policy
            ).execute()
            
            logger.info(f"[MONITORING] ✓ Created expensive machine type alert: {policy['name']}")
            return {'success': True, 'policy_name': policy['name']}
            
        except HttpError as e:
            logger.warning(f"[MONITORING] Could not create expensive machine type alert: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def create_log_based_alert(self, notification_channel_id: str, alert_config: Dict[str, str]) -> Dict[str, Any]:
        """
        Create a generic log-based alert from configuration
        
        Args:
            notification_channel_id: Notification channel ID
            alert_config: Dictionary containing display_name, doc_content, filter, etc.
            
        Returns:
            Result dictionary with success status
        """
        try:
            monitoring = build('monitoring', 'v3', credentials=self.credentials)
            project_name = f"projects/{self.project_id}"
            
            display_name = alert_config['display_name']
            logger.info(f"[MONITORING] Creating alert: {display_name}...")
            
            # Create a unique metric name for validatability (optional but good practice)
            # For simple log alerts, we can use condition_matched_log which is simpler 
            # and doesn't require creating a metric first, but costs money in recent GCP pricing?
            # Actually, standard pattern is "Log Match" condition.
            
            alert_policy = {
                'displayName': display_name,
                'documentation': {
                    'content': f"{alert_config['doc_content']}\n\nManaged by GCP Security Hardener.",
                    'mimeType': 'text/markdown'
                },
                'conditions': [{
                    'displayName': alert_config['condition_name'],
                    'conditionMatchedLog': {
                        'filter': alert_config['filter'],
                    }
                }],
                'combiner': 'OR',
                'enabled': True,
                'notificationChannels': [notification_channel_id],
                'alertStrategy': {
                    'autoClose': {'seconds': 604800}  # 7 days
                }
            }
            
            policy = monitoring.projects().alertPolicies().create(
                name=project_name,
                body=alert_policy
            ).execute()
            
            logger.info(f"[MONITORING] ✓ Created alert: {policy['name']}")
            return {
                'success': True, 
                'policy_name': policy['name'],
                'display_name': display_name
            }
            
        except HttpError as e:
            logger.warning(f"[MONITORING] Could not create alert {alert_config['display_name']}: {str(e)}")
            return {
                'success': False, 
                'error': str(e),
                'display_name': alert_config['display_name']
            }

    def setup_all_alerts(self, email: str) -> Dict[str, Any]:
        """
        Set up all compute monitoring alerts
        
        Args:
            email: Email address for notifications
            
        Returns:
            Summary of created alerts
        """
        logger.info("=" * 80)
        logger.info("SETTING UP COMPUTE MONITORING ALERTS")
        logger.info(f"Email: {email}")
        logger.info("=" * 80)
        
        try:
            # Create notification channel
            channel_id = self.create_email_notification_channel(email)
            
            created_alerts_details = []
            
            # 1. Create original Compute Alerts 
            vm_alert = self.create_vm_creation_alert(channel_id)
            gpu_alert = self.create_gpu_attachment_alert(channel_id)
            expensive_alert = self.create_expensive_machine_type_alert(channel_id)
            
            if vm_alert['success']:
                created_alerts_details.append({
                    "display_name": "VM Instance Created",
                    "channels": [email],
                    "status": "created"
                })
            
            if gpu_alert['success']:
                created_alerts_details.append({
                    "display_name": "GPU Attachment",
                    "channels": [email],
                    "status": "created"
                })
                
            if expensive_alert['success']:
                 created_alerts_details.append({
                    "display_name": "Expensive Machine Type",
                    "channels": [email],
                    "status": "created"
                })

            # 2. Create Extended Alerts
            for alert_config in EXTENDED_ALERTS:
                result = self.create_log_based_alert(channel_id, alert_config)
                
                status = "created" if result['success'] else "failed"
                error = result.get('error')
                
                created_alerts_details.append({
                    "display_name": alert_config['display_name'],
                    "channels": [email],
                    "status": status,
                    "error": error
                })

            success_count = len([a for a in created_alerts_details if a['status'] == 'created'])
            
            logger.info("=" * 80)
            logger.info(f"COMPUTE MONITORING SETUP COMPLETE")
            logger.info(f"  Alerts created: {success_count}/{len(created_alerts_details)}")
            logger.info("=" * 80)
            
            return {
                'success': True,
                'channel_id': channel_id,
                'alerts_created': success_count,
                'details': created_alerts_details
            }
            
        except Exception as e:
            logger.error(f"Failed to set up compute monitoring: {str(e)}")
            return {
                'success': False,
                'alert_count': 0,
                'error': str(e),
                'details': []
            }
