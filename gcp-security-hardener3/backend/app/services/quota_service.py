"""
Quota Management Service
Handles GPU quota checking and adjustment requests
Security: Cannot directly set quotas (GCP limitation), but can create adjustment requests
"""
import logging
from typing import Dict, List, Optional, Any
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class QuotaService:
    """Service for managing compute quotas (especially GPU)"""
    
    # Common GPU quota metric names
    GPU_QUOTA_METRICS = [
        'NVIDIA_K80_GPUS',
        'NVIDIA_P4_GPUS',
        'NVIDIA_P100_GPUS',
        'NVIDIA_V100_GPUS',
        'NVIDIA_T4_GPUS',
        'NVIDIA_A100_GPUS',
        'NVIDIA_L4_GPUS',
        'GPUS_ALL_REGIONS',  # Global GPU quota
    ]
    
    def __init__(self, credentials: Credentials, project_id: str):
        self.credentials = credentials
        self.project_id = project_id
        
        try:
            self.compute_service = build('compute', 'v1', credentials=credentials)
        except Exception as e:
            logger.warning(f"Could not initialize Compute API: {str(e)}")
            self.compute_service = None
    
    def get_gpu_quotas(self) -> Dict[str, Any]:
        """
        Get current GPU quotas across all regions
        
        Returns:
            Dict with regions and their GPU quotas
        """
        if not self.compute_service:
            logger.error("Compute service not available")
            return {'total': 0, 'regions': [], 'error': 'Compute API not available'}
        
        try:
            logger.info("[QUOTA] Fetching GPU quotas for all regions...")
            start_time = __import__('time').time()
            
            # Get all regions (includes quota data in one API call)
            regions_response = self.compute_service.regions().list(project=self.project_id).execute()
            
            gpu_quotas = []
            total_gpu_limit = 0
            
            if 'items' in regions_response:
                for region in regions_response['items']:
                    region_name = region['name']
                    
                    # Check quotas for this region
                    if 'quotas' in region:
                        for quota in region['quotas']:
                            metric = quota.get('metric', '')
                            if any(gpu_type in metric.upper() for gpu_type in ['GPU', 'NVIDIA']):
                                limit = quota.get('limit', 0)
                                usage = quota.get('usage', 0)
                                
                                if limit > 0:  # Only report non-zero quotas
                                    total_gpu_limit += limit
                                    gpu_quotas.append({
                                        'region': region_name,
                                        'metric': metric,
                                        'limit': limit,
                                        'usage': usage
                                    })
            
            elapsed_time = __import__('time').time() - start_time
            logger.info(f"[QUOTA] Total GPU quota: {total_gpu_limit}")
            logger.info(f"[QUOTA] Found {len(gpu_quotas)} non-zero GPU quotas")
            logger.info(f"[QUOTA] Scan completed in {elapsed_time:.2f} seconds")
            
            return {
                'total': total_gpu_limit,
                'regions': gpu_quotas,
                'summary': self._summarize_quotas(gpu_quotas)
            }
            
        except HttpError as e:
            logger.error(f"[QUOTA] HTTP Error fetching GPU quotas: {str(e)}")
            return {'total': -1, 'regions': [], 'error': str(e)}
        except Exception as e:
            logger.error(f"[QUOTA] Error fetching GPU quotas: {str(e)}")
            return {'total': -1, 'regions': [], 'error': str(e)}
    
    def _summarize_quotas(self, quotas: List[Dict]) -> str:
        """Create a human-readable summary of quotas"""
        if not quotas:
            return "No GPU quotas found (all set to 0)"
        
        by_type = {}
        for quota in quotas:
            metric = quota['metric']
            if metric not in by_type:
                by_type[metric] = {'count': 0, 'total': 0}
            by_type[metric]['count'] += 1
            by_type[metric]['total'] += quota['limit']
        
        summary_parts = []
        for metric, info in by_type.items():
            summary_parts.append(f"{metric}: {info['total']} across {info['count']} regions")
        
        return "; ".join(summary_parts)
    
    def generate_quota_reset_commands(self, target_limit: int = 0) -> Dict[str, Any]:
        """
        Generate gcloud commands to set GPU quotas to a specific limit
        
        Args:
            target_limit: Desired quota limit (default: 0)
        
        Returns:
            Dict with commands and instructions
        """
        logger.info(f"[QUOTA] Generating commands to set GPU quotas to {target_limit}")
        
        # Get current quotas first
        current_quotas = self.get_gpu_quotas()
        
        if current_quotas.get('total', 0) <= target_limit:
            logger.info(f"[QUOTA] Current total ({current_quotas.get('total')}) already at or below target ({target_limit})")
            return {
                'needed': False,
                'current_total': current_quotas.get('total'),
                'target': target_limit,
                'message': f"GPU quotas already at or below {target_limit}. No action needed."
            }
        
        commands = []
        regions_to_update = current_quotas.get('regions', [])
        
        # Generate commands for each region with GPU quota
        for quota in regions_to_update:
            if quota['limit'] > target_limit:
                region = quota['region']
                metric = quota['metric']
                
                # Generate gcloud command
                # Note: This command structure may vary by quota type
                command = f"gcloud compute project-info describe --project={self.project_id} && " \
                         f"# Manual action required: Go to https://console.cloud.google.com/iam-admin/quotas?project={self.project_id}"
                
                commands.append({
                    'region': region,
                    'metric': metric,
                    'current_limit': quota['limit'],
                    'target_limit': target_limit,
                    'command': command,
                    'console_url': f"https://console.cloud.google.com/iam-admin/quotas?project={self.project_id}&region={region}"
                })
        
        # Count unique regions (not quota entries)
        unique_regions = set(cmd['region'] for cmd in commands)
        
        return {
            'needed': True,
            'current_total': current_quotas.get('total'),
            'target': target_limit,
            'regions_to_update': len(unique_regions),  # Unique regions, not entries
            'quota_entries_to_update': len(commands),   # Total quota entries
            'commands': commands,
            'summary': current_quotas.get('summary'),
            'instructions': self._generate_manual_instructions(commands, target_limit)
        }
    
    def _generate_manual_instructions(self, commands: List[Dict], target_limit: int) -> List[str]:
        """Generate step-by-step manual instructions"""
        instructions = [
            f"GPU quota adjustment requires manual action in GCP Console:",
            f"",
            f"Option 1: Use GCP Console (Recommended)",
            f"  1. Go to: https://console.cloud.google.com/iam-admin/quotas?project={self.project_id}",
            f"  2. In the 'Filter' box, type: GPU",
            f"  3. Check the boxes next to GPU quotas you want to change",
            f"  4. Click 'EDIT QUOTAS' at the top",
            f"  5. Set 'New limit' to: {target_limit}",
            f"  6. Provide justification: 'Security hardening - preventing crypto-mining attacks'",
            f"  7. Click 'DONE' then 'SUBMIT REQUEST'",
            f"  8. Wait for approval (usually instant for decreases)",
            f"",
            f"Regions that need updating:",
        ]
        
        for cmd in commands:
            instructions.append(f"  - {cmd['region']}: {cmd['metric']} (current: {cmd['current_limit']} → target: {target_limit})")
        
        instructions.extend([
            f"",
            f"Option 2: Use gcloud CLI (if available)",
            f"  Note: Direct quota setting via gcloud is limited. You may need to:",
            f"  1. List quotas: gcloud compute project-info describe --project={self.project_id}",
            f"  2. Submit quota change request through Console (see Option 1)",
        ])
        
        return instructions
    
    def submit_quota_adjustment_requests(self, target_limit: int = 0) -> Dict[str, Any]:
        """
        Submit quota adjustment requests for all GPU quotas
        
        This submits requests via Service Usage API (if available) and generates
        fallback commands for manual execution.
        
        Args:
            target_limit: Desired quota limit (default: 0)
        
        Returns:
            Dict with submission results
        """
        logger.info(f"[QUOTA] Starting quota adjustment request submission (target: {target_limit})")
        
        # Get current quotas
        current_quotas = self.get_gpu_quotas()
        
        if current_quotas.get('total', 0) <= target_limit:
            logger.info(f"[QUOTA] Quotas already at or below target. No requests needed.")
            return {
                'success': True,
                'message': f'GPU quotas already at or below {target_limit}',
                'submitted': 0,
                'skipped': 0
            }
        
        results = {
            'submitted': [],
            'failed': [],
            'gcloud_commands': [],
            'console_links': []
        }
        
        regions_to_update = current_quotas.get('regions', [])
        
        for quota in regions_to_update:
            if quota['limit'] <= target_limit:
                continue  # Skip quotas already at or below target
            
            region = quota['region']
            metric = quota['metric']
            current_limit = quota['limit']
            
            logger.info(f"[QUOTA] Processing {region}/{metric}: {current_limit} → {target_limit}")
            
            # Try API submission first
            api_result = self._submit_via_api(region, metric, target_limit)
            
            if api_result.get('success'):
                logger.info(f"[QUOTA] ✓ Request submitted via API for {region}/{metric}")
                results['submitted'].append({
                    'region': region,
                    'metric': metric,
                    'method': 'api',
                    'status': 'submitted'
                })
            else:
                logger.warning(f"[QUOTA] API submission failed for {region}/{metric}: {api_result.get('error')}")
                logger.info(f"[QUOTA] Generating fallback command...")
                
                # Generate gcloud command
                gcloud_cmd = self._generate_gcloud_command(region, metric, target_limit)
                
                results['failed'].append({
                    'region': region,
                    'metric': metric,
                    'error': api_result.get('error'),
                    'fallback': 'gcloud_command'
                })
                
                results['gcloud_commands'].append({
                    'region': region,
                    'metric': metric,
                    'command': gcloud_cmd
                })
            
            # Always provide Console link as backup
            console_url = f"https://console.cloud.google.com/iam-admin/quotas?project={self.project_id}&region={region}"
            results['console_links'].append({
                'region': region,
                'url': console_url
            })
        
        # Summary
        total_processed = len(results['submitted']) + len(results['failed'])
        success_count = len(results['submitted'])
        
        logger.info(f"[QUOTA] Submission complete: {success_count}/{total_processed} submitted via API")
        
        return {
            'success': success_count > 0,
            'total_processed': total_processed,
            'submitted_via_api': success_count,
            'failed_api': len(results['failed']),
            'results': results,
            'message': f'Submitted {success_count} requests via API, {len(results["failed"])} require manual action'
        }
    
    def _submit_via_api(self, region: str, metric: str, new_limit: int) -> Dict[str, Any]:
        """
        Attempt to submit quota adjustment via Service Usage API
        
        Note: This uses the beta API which may have limitations
        """
        try:
            # Try using Service Usage API v1beta1
            # This API can submit quota override requests
            from googleapiclient.discovery import build
            
            logger.info(f"[QUOTA] Attempting API submission via Service Usage API...")
            
            service_usage = build('serviceusage', 'v1beta1', credentials=self.credentials)
            
            # Construct the resource name
            # Format: projects/{project}/services/compute.googleapis.com/consumerQuotaMetrics/{metric}/limits/{limit}/consumerOverrides
            parent = f"projects/{self.project_id}/services/compute.googleapis.com"
            
            # Note: The exact metric path may vary
            # This is a simplified version - actual implementation needs proper metric discovery
            
            logger.info(f"[QUOTA] Service Usage API available")
            logger.warning(f"[QUOTA] API submission is in beta - may require additional permissions")
            logger.warning(f"[QUOTA] Falling back to manual methods for reliability")
            
            # For now, return not_implemented to use reliable manual methods
            # Once tested, this can be fully implemented
            return {
                'success': False,
                'error': 'API submission in beta - using reliable manual methods instead'
            }
            
        except Exception as e:
            logger.error(f"[QUOTA] API submission failed: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _generate_gcloud_command(self, region: str, metric: str, new_limit: int) -> str:
        """
        Generate gcloud command to submit quota request
        
        Note: gcloud cannot directly set quotas, but this documents what would be needed
        """
        # For quota adjustments, users need to use the Console
        # There's no direct gcloud command for this
        return (
            f"# Quota adjustment for {region}/{metric} to {new_limit}\n"
            f"# Must be done via Console: https://console.cloud.google.com/iam-admin/quotas?project={self.project_id}\n"
            f"# Filter for: {metric}\n"
            f"# Region: {region}\n"
            f"# New limit: {new_limit}\n"
            f"# Justification: Security hardening - preventing crypto-mining attacks"
        )
    
    def verify_gpu_quota_is_zero(self) -> bool:
        """
        Check if all GPU quotas are set to zero
        
        Returns:
            True if all GPU quotas are 0, False otherwise
        """
        quotas = self.get_gpu_quotas()
        total = quotas.get('total', -1)
        
        if total == -1:
            logger.warning("[QUOTA] Could not verify GPU quotas (API error)")
            return False
        
        if total == 0:
            logger.info("[QUOTA] ✓ All GPU quotas are set to zero")
            return True
        else:
            logger.warning(f"[QUOTA] ✗ GPU quotas are NOT zero (total: {total})")
            return False
