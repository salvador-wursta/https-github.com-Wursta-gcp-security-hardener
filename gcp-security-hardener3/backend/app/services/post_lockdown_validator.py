"""
Post-Lockdown Validation and Retry Service
Automatically rescans after lockdown to verify changes were applied
"""
import logging
from typing import Dict, Any, List
from app.services.gcp_client import GCPClient
from app.services.scanner_service import ScannerService

logger = logging.getLogger(__name__)

class PostLockdownValidator:
    """Validates lockdown changes and provides retry mechanism"""
    
    def __init__(self, gcp_client: GCPClient):
        self.gcp_client = gcp_client
        self.scanner = ScannerService(gcp_client)
    
    async def validate_and_compare(self, before_scan: Dict[str, Any], after_rescan: bool = True) -> Dict[str, Any]:
        """
        Compare before and after scan results
        
        Returns:
            - risks_resolved: List of risks that were fixed
            - risks_remaining: List of risks still present
            - success_rate: Percentage of risks resolved
            - should_retry: Boolean indicating if retry is recommended
        """
        if not after_rescan:
            return {
                "risks_resolved": [],
                "risks_remaining": before_scan.get("risks", []),
                "success_rate": 0,
                "should_retry": True,
                "message": "Lockdown completed but validation was skipped"
            }
        
        logger.info(f"[VALIDATION] Running post-lockdown scan...")
        
        # Run new scan
        after_scan = await self.scanner.scan_project(self.gcp_client.project_id)
        
        # Compare results
        before_risks = {r["risk_id"]: r for r in before_scan.get("risks", [])}
        after_risks = {r["risk_id"]: r for r in after_scan.get("risks", [])}
        
        resolved = []
        remaining = []
        
        for risk_id, risk in before_risks.items():
            if risk_id not in after_risks:
                resolved.append(risk)
            else:
                remaining.append(after_risks[risk_id])
        
        total = len(before_risks)
        resolved_count = len(resolved)
        success_rate = (resolved_count / total * 100) if total > 0 else 0
        
        should_retry = success_rate < 80  # Retry if less than 80% success
        
        logger.info(f"[VALIDATION] Results: {resolved_count}/{total} risks resolved ({success_rate:.1f}%)")
        
        return {
            "risks_resolved": resolved,
            "risks_remaining": remaining,
            "success_rate": success_rate,
            "should_retry": should_retry,
            "total_before": total,
            "total_after": len(after_risks),
            "message": f"{resolved_count} of {total} risks resolved"
        }
