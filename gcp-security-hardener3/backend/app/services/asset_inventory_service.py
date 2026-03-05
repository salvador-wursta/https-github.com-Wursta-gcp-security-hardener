"""
Cloud Asset Inventory Service
Provides access to Google Cloud Asset Inventory API for architecture snapshots.
"""
import logging
from typing import List, Dict, Any, Optional
from app.services.gcp_client import GCPClient

logger = logging.getLogger(__name__)

class AssetInventoryService:
    """Service for interacting with Google Cloud Asset Inventory"""
    
    def __init__(self, gcp_client: GCPClient):
        self.gcp_client = gcp_client
        self.client = None
        self._iam_client = None

    def _get_client(self):
        """Lazy load AssetServiceClient"""
        if not self.client:
            try:
                from google.cloud import asset_v1
                self.client = asset_v1.AssetServiceClient(credentials=self.gcp_client.credentials)
            except ImportError:
                logger.error("google-cloud-asset library not installed")
                return None
            except Exception as e:
                logger.error(f"Failed to initialize AssetServiceClient: {e}")
                return None
        return self.client

    def search_all_resources(self, scope: str, asset_types: List[str] = None, query: str = "") -> List[Dict[str, Any]]:
        """
        Search for resources using Cloud Asset Inventory
        
        Args:
            scope: The scope of the search (e.g. 'projects/123')
            asset_types: List of asset types to include (e.g. ['compute.googleapis.com/Instance'])
            query: Optional custom query string
            
        Returns:
            List of simplified resource dictionaries
        """
        client = self._get_client()
        if not client:
            return []

        try:
            # Prepare request
            # Note: scope should be 'projects/{project_id}' or 'organizations/{org_id}'
            logger.info(f"Searching assets in {scope} (types={asset_types})")
            
            # The client library handles pagination automatically when iterating
            # We don't construct the request object manually to avoid explicit type imports if possible,
            # but usually client.search_all_resources(request={...}) is safer.
            # Using keyword arguments directly:
            
            results = client.search_all_resources(
                scope=scope,
                query=query,
                asset_types=asset_types,
            )
            
            from google.protobuf.json_format import MessageToDict
            
            assets = []
            for result in results:
                # Convert protobuf to dict safely
                # Handle additional_attributes Protobuf Struct
                add_attrs = {}
                if result.additional_attributes:
                     # Accessing ._pb is safer for Gapic wrappers
                     add_attrs = MessageToDict(result.additional_attributes._pb)

                assets.append({
                    "name": result.name,
                    "asset_type": result.asset_type,
                    "display_name": result.display_name,
                    "project": result.project,
                    "folders": list(result.folders),
                    "organization": result.organization,
                    "location": result.location,
                    "labels": dict(result.labels),
                    "network_tags": list(result.network_tags),
                    "state": result.state, # Added missing field
                    "additional_attributes": add_attrs
                })
            
            logger.info(f"CAI: Found {len(assets)} resources")
            return assets
            
        except Exception as e:
            error_str = str(e)
            if "403" in error_str or "Permission denied" in error_str or "SERVICE_DISABLED" in error_str:
                logger.error(f"CAI Permission Error: {e}")
                raise PermissionError(
                    "Access Denied to Cloud Asset Inventory. "
                    "Please ensure the Scanner Service Account has 'roles/cloudasset.viewer'. "
                    "Also ensure the 'cloudasset.googleapis.com' API is enabled in the target project."
                )
            logger.error(f"Error searching resources: {e}")
            # Do not raise for other errors, just return empty list to keep scan resilient
            return []

    def search_all_iam_policies(self, scope: str, query: str = "") -> List[Dict[str, Any]]:
        """
        Search for IAM policies using Cloud Asset Inventory
        
        Args:
            scope: The scope of the search
            query: Optional query
            
        Returns:
            List of IAM policy summaries
        """
        client = self._get_client()
        if not client:
            return []

        try:
            logger.info(f"Searching IAM policies in {scope}")
            
            results = client.search_all_iam_policies(
                scope=scope,
                query=query,
            )
            
            policies = []
            for result in results:
                policy_dict = {
                    "resource": result.resource,
                    "project": result.project,
                    "policy": {
                        "bindings": []
                    }
                }
                
                # Manual proto-to-dict for policy bindings
                if result.policy:
                    for binding in result.policy.bindings:
                        policy_dict["policy"]["bindings"].append({
                            "role": binding.role,
                            "members": list(binding.members)
                        })
                
                policies.append(policy_dict)
            
            logger.info(f"CAI: Found {len(policies)} IAM policies")
            return policies
            
        except Exception as e:
            error_str = str(e)
            if "403" in error_str or "Permission denied" in error_str or "SERVICE_DISABLED" in error_str:
                logger.error(f"CAI IAM Permission Error: {e}")
                raise PermissionError(
                    "Access Denied to Cloud Asset Inventory (IAM). "
                    "Please ensure the Scanner Service Account has 'roles/cloudasset.viewer'."
                )
            logger.error(f"Error searching IAM policies: {e}")
            return []
