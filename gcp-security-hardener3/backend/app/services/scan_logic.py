"""
Scan Logic Utilities
Provides core functions for finding processing and deduplication.
"""
from typing import List, Dict, Any

def deduplicate_findings(raw_findings: List[Any], title_attr="title", resource_attr="resource_id") -> List[Any]:
    """
    Implements a unique_findings dictionary to filter out duplicates.
    Hashing logic uses Title + Resource ID.
    """
    unique_findings = {}
    
    for finding in raw_findings:
        # Support both object attributes and dictionary keys
        try:
            title = getattr(finding, title_attr) if hasattr(finding, title_attr) else finding.get(title_attr)
            resource_id = getattr(finding, resource_attr) if hasattr(finding, resource_attr) else finding.get(resource_attr)
        except (AttributeError, KeyError):
            # Fallback if attributes are missing
            title = "Unknown"
            resource_id = "Default"
            
        key = f"{title}|{resource_id}"
        
        if key not in unique_findings:
            unique_findings[key] = finding
            
    return list(unique_findings.values())
