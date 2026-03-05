"""
Resource Graph Service
Parses flat CAI asset lists into a queryable graph/network structure.
"""
import logging
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)

class ResourceGraphService:
    def __init__(self, assets: List[Dict[str, Any]]):
        self.assets = assets
        self.asset_map = {a['name']: a for a in assets}
        self.edges = [] # List of (source, target, type)

    def count_public_ips(self) -> int:
        """
        Count resources that appear to have public IPs based on CAI data.
        CAI 'additional_attributes' often contains network info for Compute Engines.
        """
        count = 0
        for asset in self.assets:
            # Method 1: Check Compute Instance 'networkInterfaces' in additional_attributes
            if asset['asset_type'] == "compute.googleapis.com/Instance":
                attrs = asset.get('additional_attributes', {})
                # This depends on how CAI serializes the struct. 
                # Often checks for 'externalIP' or access configs.
                
                # Heuristic: Check for 'natIP' or 'externalIp' strings in the stringified attributes 
                # if we can't easily parse the Struct generic structure.
                # However, since we converted to dict, we can try to look deeper.
                
                # Simpler approach for now: Network Tags often imply exposure, 
                # but let's count on 'externalIP' being present in the enriched data.
                pass
            
            # Method 2: External IP Address resource itself
            if asset['asset_type'] == "compute.googleapis.com/Address":
                # Check if it is EXTERNAL
                attrs = asset.get('additional_attributes', {})
                if attrs.get('addressType') == 'EXTERNAL':
                    count += 1
                    
        return count

    def find_orphaned_disks(self) -> List[Dict[str, Any]]:
        """Find disks that are not attached to any instance"""
        orphans = []
        for asset in self.assets:
            if asset['asset_type'] == "compute.googleapis.com/Disk":
                attrs = asset.get('additional_attributes', {})
                # 'users' field lists the URLs of instances using this disk
                users = attrs.get('users', [])
                if not users:
                    orphans.append(asset)
        return orphans
