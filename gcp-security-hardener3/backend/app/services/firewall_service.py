"""
VPC Firewall Service - Creates firewall rules to block external access
Security: Properly hardens network without requiring org policies
"""
import logging
from typing import Dict, Any, List
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class FirewallService:
    """Service for managing VPC firewall rules"""
    
    def __init__(self, credentials: Credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        self.compute = build('compute', 'v1', credentials=credentials)
    
    def create_deny_external_ingress_rule(
        self,
        network: str = "default",
        rule_name: str = "deny-external-ingress"
    ) -> Dict[str, Any]:
        """
        Create a firewall rule that denies all external ingress traffic
        
        Args:
            network: VPC network name (default: "default")
            rule_name: Name for the firewall rule
            
        Returns:
            Firewall rule configuration
        """
        try:
            logger.info(f"[FIREWALL] Creating deny-all external ingress rule")
            logger.info(f"  Network: {network}")
            logger.info(f"  Rule name: {rule_name}")
            
            firewall_body = {
                "name": rule_name,
                "network": f"projects/{self.project_id}/global/networks/{network}",
                "description": "GCP Security Hardener: Block all external ingress traffic",
                "direction": "INGRESS",
                "priority": 100,
                "denied": [
                    {
                        "IPProtocol": "all"
                    }
                ],
                "sourceRanges": ["0.0.0.0/0"],
                "targetTags": []  # Applies to all VMs
            }
            
            logger.debug(f"[FIREWALL] Rule configuration: {firewall_body}")
            
            # Check if rule already exists
            try:
                existing = self.compute.firewalls().get(
                    project=self.project_id,
                    firewall=rule_name
                ).execute()
                
                logger.info(f"[FIREWALL] Rule already exists, will update")
                
                # Update existing rule
                operation = self.compute.firewalls().update(
                    project=self.project_id,
                    firewall=rule_name,
                    body=firewall_body
                ).execute()
                
                logger.info(f"[FIREWALL] ✓ Rule UPDATED successfully")
                
            except HttpError as e:
                if e.resp.status == 404:
                    logger.info(f"[FIREWALL] Rule doesn't exist, creating new")
                    
                    # Create new rule
                    operation = self.compute.firewalls().insert(
                        project=self.project_id,
                        body=firewall_body
                    ).execute()
                    
                    logger.info(f"[FIREWALL] ✓ Rule CREATED successfully")
                else:
                    raise
            
            logger.debug(f"[FIREWALL] Operation: {operation}")
            
            return {
                "rule_name": rule_name,
                "network": network,
                "direction": "INGRESS",
                "action": "DENY",
                "status": "applied",
                "operation": operation.get('name', 'unknown')
            }
            
        except HttpError as e:
            error_msg = f"Failed to create firewall rule: {str(e)}"
            logger.error(f"[FIREWALL] HTTP Error: {error_msg}")
            raise Exception(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error creating firewall rule: {str(e)}"
            logger.error(f"[FIREWALL] Error: {error_msg}")
            raise Exception(error_msg)
    
    def create_allow_internal_rule(
        self,
        network: str = "default",
        rule_name: str = "allow-internal"
    ) -> Dict[str, Any]:
        """
        Create a firewall rule that allows internal RFC1918 traffic
        
        Args:
            network: VPC network name (default: "default")
            rule_name: Name for the firewall rule
            
        Returns:
            Firewall rule configuration
        """
        try:
            logger.info(f"[FIREWALL] Creating allow-internal rule")
            
            firewall_body = {
                "name": rule_name,
                "network": f"projects/{self.project_id}/global/networks/{network}",
                "description": "GCP Security Hardener: Allow internal network traffic",
                "direction": "INGRESS",
                "priority": 200,
                "allowed": [
                    {
                        "IPProtocol": "all"
                    }
                ],
                "sourceRanges": [
                    "10.0.0.0/8",      # Private Class A
                    "172.16.0.0/12",   # Private Class B  
                    "192.168.0.0/16"   # Private Class C
                ],
                "targetTags": []
            }
            
            # Check if rule already exists
            try:
                existing = self.compute.firewalls().get(
                    project=self.project_id,
                    firewall=rule_name
                ).execute()
                
                logger.info(f"[FIREWALL] Rule already exists, will update")
                
                operation = self.compute.firewalls().update(
                    project=self.project_id,
                    firewall=rule_name,
                    body=firewall_body
                ).execute()
                
                logger.info(f"[FIREWALL] ✓ Rule UPDATED successfully")
                
            except HttpError as e:
                if e.resp.status == 404:
                    logger.info(f"[FIREWALL] Rule doesn't exist, creating new")
                    
                    operation = self.compute.firewalls().insert(
                        project=self.project_id,
                        body=firewall_body
                    ).execute()
                    
                    logger.info(f"[FIREWALL] ✓ Rule CREATED successfully")
                else:
                    raise
            
            return {
                "rule_name": rule_name,
                "network": network,
                "direction": "INGRESS",
                "action": "ALLOW",
                "status": "applied",
                "operation": operation.get('name', 'unknown')
            }
            
        except Exception as e:
            error_msg = f"Failed to create allow-internal rule: {str(e)}"
            logger.error(f"[FIREWALL] Error: {error_msg}")
            raise Exception(error_msg)
    
    
    def setup_change_monitoring(self) -> Dict[str, Any]:
        """
        Set up FREE monitoring for firewall changes
        Creates log sink to track all firewall modifications
        Cost: $0 (uses free Cloud Logging tier)
        """
        try:
            logger.info(f"[MONITORING] Setting up firewall change monitoring (FREE)")
            
            from googleapiclient.discovery import build
            logging_service = build('logging', 'v2', credentials=self.credentials)
            
            # Filter for firewall changes
            filter_expr = (
                'protoPayload.serviceName="compute.googleapis.com" AND '
                '(protoPayload.methodName="v1.compute.firewalls.insert" OR '
                'protoPayload.methodName="v1.compute.firewalls.update" OR '
                'protoPayload.methodName="v1.compute.firewalls.delete" OR '
                'protoPayload.methodName="v1.compute.firewalls.patch")'
            )
            
            sink_name = "firewall-change-monitor"
            destination = f"logging.googleapis.com/projects/{self.project_id}/locations/global/buckets/_Default"
            
            sink_config = {
                "name": sink_name,
                "filter": filter_expr,
                "destination": destination,
                "description": "FREE monitoring: Track all firewall rule modifications",
                "outputVersionFormat": "V2"
            }
            
            parent = f"projects/{self.project_id}"
            
            try:
                # Try to create
                logging_service.projects().sinks().create(
                    parent=parent,
                    body=sink_config
                ).execute()
                logger.info(f"[MONITORING] ✓ Log sink created (FREE, no cost)")
            except Exception as e:
                if 'already exists' in str(e).lower():
                    # Update existing
                    logging_service.projects().sinks().update(
                        sinkName=f"{parent}/sinks/{sink_name}",
                        body=sink_config
                    ).execute()
                    logger.info(f"[MONITORING] ✓ Log sink updated (FREE, no cost)")
                else:
                    raise
            
            logger.info(f"[MONITORING] ✓ All firewall changes will be logged")
            logger.info(f"[MONITORING] View logs: https://console.cloud.google.com/logs/query?project={self.project_id}")
            
            return {
                "sink_name": sink_name,
                "status": "active",
                "cost": "$0/month",
                "monitoring": "enabled"
            }
            
        except Exception as e:
            logger.warning(f"[MONITORING] Could not set up monitoring (non-critical): {e}")
            logger.warning(f"[MONITORING] Firewall rules will still work, just without automatic monitoring")
            return {
                "sink_name": None,
                "status": "failed",
                "error": str(e),
                "monitoring": "disabled"
            }
    
    def list_firewall_rules(self) -> List[Dict[str, Any]]:
        """
        List all firewall rules in the project
        
        Returns:
            List of firewall rule summaries
        """
        try:
            result = self.compute.firewalls().list(project=self.project_id).execute()
            
            rules = []
            for item in result.get('items', []):
                rules.append({
                    'name': item.get('name'),
                    'direction': item.get('direction'),
                    'priority': item.get('priority'),
                    'network': item.get('network', '').split('/')[-1]
                })
            
            return rules
        except Exception as e:
            logger.error(f"Failed to list firewall rules: {e}")
            return []
            
    def inspect_firewall_configuration(self) -> Dict[str, Any]:
        """
        Inspect firewall configuration to check for a global deny-all rule.
        
        Returns:
            Dict with status (SECURED, RISK, VULNERABILITY) and details
        """
        try:
            logger.info(f"[FIREWALL] Inspecting firewall configuration for project {self.project_id}")
            result = self.compute.firewalls().list(project=self.project_id).execute()
            items = result.get('items', [])
            
            if not items:
                logger.warning("[FIREWALL] No firewall rules found!")
                return {
                    "status": "VULNERABILITY",
                    "reason": "No firewall rules exist in the project. The network is completely open or relying on implicit rules.",
                    "recommendation": "Create a base 'deny-all' ingress rule for all external traffic (0.0.0.0/0)."
                }
            
            # Check for a "Deny All" ingress rule
            # Criteria: 
            # 1. Action is DENY (or has 'denied' property)
            # 2. Source range is 0.0.0.0/0
            # 3. Direction is INGRESS
            # 4. Protocol is 'all'
            # 5. Priority is relatively high
            
            deny_all_rules = []
            
            for rule in items:
                if rule.get('direction') == 'INGRESS' and '0.0.0.0/0' in rule.get('sourceRanges', []):
                    # Check for DENY action
                    if 'denied' in rule:
                        # Check if it denies 'all'
                        for denied in rule['denied']:
                            if denied.get('IPProtocol') == 'all':
                                deny_all_rules.append(rule)
                                break
            
            if not deny_all_rules:
                logger.info("[FIREWALL] No deny-all ingress rule found")
                return {
                    "status": "RISK",
                    "reason": "A global 'deny-all' ingress rule was not found. While you may have specific deny rules, a default-deny posture is safer.",
                    "recommendation": "Implement a high-priority 'deny-all' rule for 0.0.0.0/0 to ensure a default-deny security posture."
                }
            
            # Found at least one deny-all rule
            # Check priority
            deny_all_rules.sort(key=lambda x: x.get('priority', 1000))
            best_rule = deny_all_rules[0]
            priority = best_rule.get('priority', 1000)
            
            if priority > 1000:
                return {
                    "status": "RISK",
                    "reason": f"A 'deny-all' rule exists ('{best_rule['name']}') but has low priority ({priority}). Higher priority rules might be bypassing it.",
                    "recommendation": "Increase the priority (decrease the number) of your 'deny-all' rule to ensure it acts as a reliable catch-all."
                }
                
            return {
                "status": "SECURED",
                "reason": f"Verified 'deny-all' ingress rule ('{best_rule['name']}') found with high priority ({priority}).",
                "recommendation": "Maintain your existing default-deny security posture."
            }
            
        except Exception as e:
            logger.error(f"Failed to inspect firewall configuration: {str(e)}")
            return {
                "status": "ERROR",
                "reason": f"Could not analyze firewall configuration: {str(e)}",
                "recommendation": "Ensure the service account has compute.firewalls.list permissions."
            }
