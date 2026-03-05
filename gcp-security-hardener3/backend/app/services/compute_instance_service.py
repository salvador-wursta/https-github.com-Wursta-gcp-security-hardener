"""
Compute Instance Service
Scans for high-cost instance types (N2, C2) and checks restrictions
Security: Prevents expensive compute abuse by attackers
"""
import logging
from typing import Dict, List, Optional, Any
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class ComputeInstanceService:
    """Service for scanning and managing compute instance types"""
    
    # High-cost instance families that are rarely needed by SMBs
    RESTRICTED_FAMILIES = ['n2', 'c2']
    
    def __init__(self, credentials: Credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        
        try:
            self.compute_service = build('compute', 'v1', credentials=credentials)
        except Exception as e:
            logger.warning(f"Could not initialize Compute API: {str(e)}")
            self.compute_service = None
    
    def scan_instances(self) -> Dict[str, Any]:
        """
        Scan for N2 and C2 instances across all zones
        
        Returns:
            Dict with instance counts and details
        """
        if not self.compute_service:
            logger.error("[COMPUTE] Compute service not available")
            return {
                'n2_instances': 0,
                'c2_instances': 0,
                'total_restricted_instances': 0,
                'instances_by_zone': [],
                'error': 'Compute API not available'
            }
        
        try:
            logger.info("[COMPUTE] Scanning for N2 and C2 instances (using aggregated list for speed)...")
            start_time = __import__('time').time()
            
            n2_count = 0
            c2_count = 0
            instances_by_zone = []
            
            # Use aggregatedList to get ALL instances in ALL zones with ONE API call
            # This is MUCH faster than iterating through 100+ zones individually
            aggregated_response = self.compute_service.instances().aggregatedList(
                project=self.project_id
            ).execute()
            
            # Process instances grouped by zone
            if 'items' in aggregated_response:
                for zone_key, zone_data in aggregated_response['items'].items():
                    # zone_key format: "zones/us-central1-a"
                    zone_name = zone_key.split('/')[-1] if '/' in zone_key else zone_key
                    
                    # Check if this zone has instances
                    if 'instances' in zone_data:
                        for instance in zone_data['instances']:
                            machine_type = instance.get('machineType', '')
                            # Extract machine family from machine type URL
                            # Format: zones/us-central1-a/machineTypes/n2-standard-4
                            machine_family = self._extract_machine_family(machine_type)
                            
                            if machine_family in ['n2', 'c2']:
                                instance_name = instance.get('name', 'unknown')
                                status = instance.get('status', 'UNKNOWN')
                                
                                if machine_family == 'n2':
                                    n2_count += 1
                                elif machine_family == 'c2':
                                    c2_count += 1
                                
                                instances_by_zone.append({
                                    'zone': zone_name,
                                    'name': instance_name,
                                    'machine_type': machine_type.split('/')[-1],
                                    'machine_family': machine_family.upper(),
                                    'status': status
                                })
                                
                                logger.debug(f"[COMPUTE] Found {machine_family.upper()} instance: {instance_name} in {zone_name}")
            
            elapsed_time = __import__('time').time() - start_time
            logger.info(f"[COMPUTE] Scan completed in {elapsed_time:.2f} seconds")
            
            total = n2_count + c2_count
            logger.info(f"[COMPUTE] Scan complete: {total} restricted instances (N2: {n2_count}, C2: {c2_count})")
            
            return {
                'n2_instances': n2_count,
                'c2_instances': c2_count,
                'total_restricted_instances': total,
                'instances_by_zone': instances_by_zone
            }
            
        except HttpError as e:
            logger.error(f"[COMPUTE] HTTP Error scanning instances: {str(e)}")
            return {
                'n2_instances': -1,
                'c2_instances': -1,
                'total_restricted_instances': -1,
                'instances_by_zone': [],
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"[COMPUTE] Error scanning instances: {str(e)}")
            return {
                'n2_instances': -1,
                'c2_instances': -1,
                'total_restricted_instances': -1,
                'instances_by_zone': [],
                'error': str(e)
            }
    
    def _extract_machine_family(self, machine_type_url: str) -> str:
        """
        Extract machine family from machine type URL
        
        Args:
            machine_type_url: e.g. "zones/us-central1-a/machineTypes/n2-standard-4"
        
        Returns:
            Machine family: e.g. "n2"
        """
        try:
            # Get the last part (machine type name)
            machine_type_name = machine_type_url.split('/')[-1]
            # Extract family (before first hyphen)
            family = machine_type_name.split('-')[0].lower()
            return family
        except Exception:
            return 'unknown'
    
    def check_restriction_policy(self) -> bool:
        """
        Check if organization policy restricts N2/C2 instances
        
        Returns:
            True if restriction policy is active, False otherwise
        """
        try:
            # This would check for org policy constraint:
            # compute.restrictedMachineTypeRestrictions
            # For now, return False (not implemented yet)
            logger.info("[COMPUTE] Organization policy check not yet implemented")
            return False
            
        except Exception as e:
            logger.error(f"[COMPUTE] Error checking restriction policy: {str(e)}")
            return False
    
    def generate_restriction_recommendation(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate recommendation based on scan results
        
        Args:
            scan_results: Results from scan_instances()
        
        Returns:
            Dict with risk level and recommendation
        """
        n2_count = scan_results.get('n2_instances', 0)
        c2_count = scan_results.get('c2_instances', 0)
        total = scan_results.get('total_restricted_instances', 0)
        
        # Check for errors
        if total == -1:
            return {
                'risk_level': 'info',
                'recommendation': '⚠️ Could not scan compute instances. Compute API may not be enabled.',
                'policy_enabled': False
            }
        
        # No instances found - good for restriction
        if total == 0:
            return {
                'risk_level': 'safe',
                'recommendation': (
                    '✓ No N2 or C2 instances detected. '
                    'Consider restricting these instance types via organization policy to prevent expensive attacks. '
                    'Most small businesses can use E2 (cost-optimized) or N1 (general purpose) instances instead.'
                ),
                'policy_enabled': False
            }
        
        # Instances found - need justification
        if total <= 2:
            return {
                'risk_level': 'warning',
                'recommendation': (
                    f'⚠️ Found {total} high-cost instances (N2: {n2_count}, C2: {c2_count}). '
                    f'These are expensive instance types. If not actively needed, consider: '
                    f'1) Migrating to E2/N1 instances for cost savings, '
                    f'2) Stopping unused instances, '
                    f'3) Restricting N2/C2 via organization policy to prevent abuse.'
                ),
                'policy_enabled': False
            }

        else:
            return {
                'risk_level': 'high',
                'recommendation': (
                    f'🔴 Found {total} high-cost instances (N2: {n2_count}, C2: {c2_count}). '
                    f'These are very expensive instance types. High risk of cost attack if account is compromised. '
                    f'Recommendations: '
                    f'1) Review if all instances are necessary, '
                    f'2) Consider migrating to E2/N1 for typical workloads, '
                    f'3) Stop unused instances immediately, '
                    f'4) Restrict N2/C2 via organization policy.'
                ),
                'policy_enabled': False
            }

    def _get_reserved_addresses(self) -> set:
        """Fetch all reserved static IP addresses in the project."""
        reserved_ips = set()
        if not self.compute_service:
            return reserved_ips
            
        try:
            logger.info("[COMPUTE] Fetching reserved static IPs...")
            # aggregatedList addresses
            response = self.compute_service.addresses().aggregatedList(project=self.project_id).execute()
            
            if 'items' in response:
                for zone_data in response['items'].values():
                    if 'addresses' in zone_data:
                        for addr in zone_data['addresses']:
                            if 'address' in addr:
                                reserved_ips.add(addr['address'])
        except Exception as e:
            logger.warning(f"[COMPUTE] Failed to fetch reserved IPs: {e}")
            
        return reserved_ips

    def detect_external_ips(self) -> List[Dict[str, Any]]:
        """
        Detect instances with external IPs and identify if they are Static or Dynamic.
        
        Returns:
            List of instances with external IP details
        """
        if not self.compute_service:
            return []
            
        try:
            logger.info("[COMPUTE] Detecting instances with external IPs...")
            static_ips = self._get_reserved_addresses()
            instances_with_external_ips = []
            
            aggregated_response = self.compute_service.instances().aggregatedList(
                project=self.project_id
            ).execute()
            
            if 'items' in aggregated_response:
                for zone_data in aggregated_response['items'].values():
                    if 'instances' in zone_data:
                        for instance in zone_data['instances']:
                            for network_interface in instance.get('networkInterfaces', []):
                                for access_config in network_interface.get('accessConfigs', []):
                                    if 'natIP' in access_config:
                                        ip = access_config.get('natIP')
                                        ip_type = "Static" if ip in static_ips else "Dynamic (Ephemeral)"
                                        
                                        instances_with_external_ips.append({
                                            'name': instance.get('name'),
                                            'external_ip': ip,
                                            'type': ip_type,
                                            'zone': instance.get('zone', '').split('/')[-1]
                                        })
            
            return instances_with_external_ips
            
        except Exception as e:
            logger.error(f"[COMPUTE] Error detecting external IPs: {str(e)}")
            return []

    def check_security_services(self) -> Dict[str, Any]:
        """
        Check for the presence of Cloud IDS and Cloud Armor
        
        Returns:
            Dict with status for each service
        """
        results = {
            "cloud_ids": {"enabled": False, "endpoints": []},
            "cloud_armor": {"enabled": False, "policies": []}
        }
        
        try:
            # 1. Check Cloud Armor (part of Compute API - security_policies)
            if self.compute_service:
                try:
                    policies = self.compute_service.securityPolicies().list(project=self.project_id).execute()
                    if policies.get('items'):
                        results["cloud_armor"]["enabled"] = True
                        results["cloud_armor"]["policies"] = [p.get('name') for p in policies.get('items', [])]
                except Exception as ca_err:
                    logger.debug(f"Cloud Armor check failed (likely API disabled): {ca_err}")

            # 2. Check Cloud IDS (ids.googleapis.com)
            try:
                from googleapiclient.discovery import build as ids_build
                ids_api = ids_build('ids', 'v1', credentials=self.credentials)
                # Just try to list endpoints to see if it works/enabled
                # Using a dummy location to check enablement
                ids_api.projects().locations().endpoints().list(parent=f"projects/{self.project_id}/locations/us-central1").execute()
                results["cloud_ids"]["enabled"] = True
            except Exception as ids_err:
                logger.debug(f"Cloud IDS check failed (likely API disabled): {ids_err}")
            
            return results
            
        except Exception as e:
            logger.error(f"[COMPUTE] Error checking security services: {str(e)}")
            return results
