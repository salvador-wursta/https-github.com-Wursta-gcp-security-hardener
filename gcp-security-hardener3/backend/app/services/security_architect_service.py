"""
Security Architect Service
Uses GenAI to analyze Cloud Asset Inventory snapshots against architectural standards.
"""
import logging
import json
from typing import Dict, Any, List
from app.services.asset_inventory_service import AssetInventoryService
from app.services.ai_service import AIService
from app.services.resource_graph_service import ResourceGraphService
from app.services.scan_logic import deduplicate_findings
from app.models.scan_models import ArchitectureInfo, ArchitecturalFinding

logger = logging.getLogger(__name__)

class SecurityArchitectService:
    def __init__(self, asset_service: AssetInventoryService, ai_service: AIService):
        self.asset_service = asset_service
        self.ai_service = ai_service

    def perform_architectural_review(self, project_id: str, assets: List[Dict[str, Any]] = None) -> ArchitectureInfo:
        """
        Perform a full architectural review using CAI and GenAI in an iterative manner.
        
        Args:
            project_id: GCP Project ID
            assets: Optional list of pre-fetched assets (from Phase 2 Master Inventory). 
                    If None, they will be fetched.
        """
        # Vertex AI is initialized via ADC, so we check availability differently if needed
        # For now, we assume ADC is present in Cloud Run environment
        if not self.ai_service:
            return ArchitectureInfo(
                scan_status="error",
                error="AI Service not initialized"
            )

        try:
            logger.info(f"Starting Iterative Architectural Foundations scan for {project_id}")
            
            # 0. Ensure API is Enabled
            try:
                # Only check if we need to fetch, or just always ensure? 
                # Good to ensure for IAM fetch anyway.
                self.asset_service.gcp_client.enable_api("cloudasset.googleapis.com", project_id=project_id)
            except Exception as e:
                logger.warning(f"Could not enable Cloud Asset API: {e}")
            
            scope = f"projects/{project_id}"
            
            # 1. Prepare Assets (Use Header or Fetch)
            if assets:
                resources = assets
                logger.info(f"Using {len(resources)} pre-fetched assets for Architectural Review")
            else:
                # Fallback Fetch
                target_asset_types = [
                    "compute.googleapis.com/Network",
                    "compute.googleapis.com/Subnetwork",
                    "compute.googleapis.com/Firewall",
                    "compute.googleapis.com/Route",
                    "compute.googleapis.com/Instance", 
                    "container.googleapis.com/Cluster",
                    "sqladmin.googleapis.com/Instance",
                    "storage.googleapis.com/Bucket",
                    "iam.googleapis.com/ServiceAccount"
                ]
                resources = self.asset_service.search_all_resources(scope=scope, asset_types=target_asset_types)
                if not resources:
                    logger.info("No specific architectural assets found. Attempting broad search...")
                    resources = self.asset_service.search_all_resources(scope=scope, query="", asset_types=[])[:100]

            iam_policies = self.asset_service.search_all_iam_policies(scope=scope)
            
            # 2. Graph Theory & Statistics (Phase 2 Enhancement)
            graph = ResourceGraphService(resources)
            public_ips = graph.count_public_ips()
            orphans = graph.find_orphaned_disks()

            # Prepare Context Data
            snapshot_summary = {
                "project_id": project_id,
                "high_level_stats": {
                    "total_resources": len(resources),
                    "public_ips_detected": public_ips,
                    "orphaned_disks_count": len(orphans),
                    "iam_policies_count": len(iam_policies)
                },
                "counts": {
                    "resources": len(resources),
                    "iam_policies": len(iam_policies)
                },
                "resources_sample": [
                    {
                        "name": r.get("display_name"),
                        "type": r.get("asset_type"),
                        "network_tags": r.get("network_tags"),
                        "location": r.get("location"),
                        "parent": r.get("parent"),
                        "state": r.get("state"),
                        # Add extra context if relevant
                        "public_exposed": "externalIP" in str(r.get("additional_attributes", "")) 
                    } for r in resources[:80] 
                ],
                "iam_policies_sample": [
                    {
                        "resource": p.get("resource"),
                        "bindings_summary": [
                            f"{b.get('role')}: {len(b.get('members'))} members" 
                            for b in p.get("policy", {}).get("bindings", [])
                        ]
                    } for p in iam_policies[:30]
                ]
            }

            # VALIDATION: Ensure we have data before asking AI
            if snapshot_summary["counts"]["resources"] == 0 and snapshot_summary["counts"]["iam_policies"] == 0:
                logger.warning(f"Aborting architectural review for {project_id}: No resources or policies found.")
                return ArchitectureInfo(
                    scan_status="completed", # Return completed but with info-level error
                    error="Data Collection Incomplete: Cloud Asset Inventory returned 0 resources and 0 policies. Please ensure the API is enabled and permissions are correct.",
                    raw_data=snapshot_summary,
                    findings=[]
                )

            # 2. Iterative Analysis Phase
            import time
            import re
            import json # Ensure json is imported
            
            categories = [
                {
                    "name": "Identity & Access Management (IAM)",
                    "focus": "Least privilege, separation of duties, detailed service account analysis, and key management.",
                    "standards": "NIST 800-53 AC-6, Google Cloud IAM Best Practices"
                },
                {
                    "name": "Network Security & Perimeter",
                    "focus": "VPC Service Controls, firewall rules, private connectivity, load balancing, and perimeter defense.",
                    "standards": "NIST 800-53 SC-7, Google Cloud Network Security Architecture"
                },
                {
                    "name": "Data Protection & Compute",
                    "focus": "Data residency, public access prevention, encryption-at-rest (CMEK), and compute isolation.",
                    "standards": "NIST 800-53 SC-13, SC-28"
                }
            ]
            
            all_findings = []
            primary_model = 'gemini-2.0-flash' # Upgraded from lite
            
            for category in categories:
                logger.info(f"Analyzing category: {category['name']}...")
                
                # Construct focused prompt
                prompt = f"""
                Act as a Principal Cloud Security Architect. Perform a DEEP DIVE Architectural Review of this GCP Project.
                
                DOMAIN: {category['name']}
                FOCUS AREAS: {category['focus']}
                STANDARDS: {category['standards']}
                
                INPUT DATA:
                {json.dumps(snapshot_summary, indent=2)}
                
                INSTRUCTIONS:
                Analyze the input data specifically for the {category['name']} domain.
                Identify 2-3 distinct, critical architectural risks or needed foundations.
                
                **REQUIREMENTS FOR DETAIL**:
                - **Contextualize**: Reference specific resource names/types from the input data if available.
                - **Risk Scenario**: explain *why* this is a risk (e.g., "Attackers could pivot from...").
                - **Technical Depth**: Provide specific `gcloud` commands or terraform patterns to remediate.
                
                **STRICT FORMATTING RULES**:
                1. **ONE FINDING = ONE ISSUE**: Do NOT combine multiple different recommendations.
                2. **NO NUMBERED LISTS IN BODY**: Write distinct findings for distinct issues.
                3. **GREENFIELD HANDLING**: If resources are missing, suggest specific foundational setups for this domain (e.g., "Establish Org Policy" vs "Setup VPC-SC").
                
                OUTPUT FORMAT (JSON ONLY):
                {{
                    "findings": [
                        {{
                            "title": "Specific architectural finding (e.g., 'Missing VPC Service Controls on Prod Data')",
                            "severity": "HIGH", 
                            "standard_violation": "Standard ID",
                            "recommendation": "Detailed markdown recommendation including Risk Scenario and specific Remediation Steps."
                        }}
                    ]
                }}
                """
                
                response = None
                # Retry logic for each category call
                for attempt in range(3):
                    try:
                        # Use the new AIService generate_analysis method
                        response_text = self.ai_service.generate_analysis(prompt + "\n\nResponse must be valid JSON.")
                        if response_text:
                            break
                    except Exception as e:
                        logger.warning(f"Category {category['name']} attempt {attempt+1} failed: {e}")
                        time.sleep(2)
                
                if not response_text:
                    logger.error(f"Skipping category {category['name']} due to AI failures")
                    continue
                    
                # Parse Findings for this Category
                try:
                    text = response_text.replace("```json", "").replace("```", "").strip()
                    cat_data = json.loads(text)
                    cat_findings_data = cat_data.get("findings", [])
                    
                    for f in cat_findings_data:
                        raw_rec = f.get("recommendation", "")
                        raw_title = f.get("title", "Unknown")
                        
                        # Apply Robust Regex Splitting (Drafting Correction)
                        list_items = list(re.finditer(
                            r"(?:^|\s)(\d+)\.\s+\*\*([^*]+)\*\*:?\s*(.*?)(?=\s\d+\.\s+\*\*|$)", 
                            raw_rec, 
                            re.DOTALL
                        ))
                        
                        if list_items:
                             for m in list_items:
                                new_title = m.group(2).strip()
                                new_body = m.group(3).strip()
                                new_body = re.sub(r"^[-:]\s*", "", new_body) # detailed cleanup
                                
                                all_findings.append(ArchitecturalFinding(
                                    title=new_title,
                                    severity=f.get("severity", "HIGH"), # Inherit or default
                                    standard_violation=f.get("standard_violation", ""),
                                    recommendation=new_body
                                ))
                        # Check logic 2: Ordinal
                        elif "First," in raw_rec and "Second," in raw_rec and not list_items:
                             sentences = re.split(r"(?<=[.!?])\s+(?=(?:First|Second|Third|Fourth|Finally),)", raw_rec)
                             for sent in sentences:
                                 title_match = re.search(r"(?:First|Second|Third|Fourth|Finally),\s+([^.,]+)", sent)
                                 derived_title = title_match.group(1).capitalize() if title_match else raw_title
                                 all_findings.append(ArchitecturalFinding(
                                     title=derived_title,
                                     severity=f.get("severity", "HIGH"),
                                     standard_violation=f.get("standard_violation", ""),
                                     recommendation=sent.strip()
                                 ))
                        else:
                            all_findings.append(ArchitecturalFinding(
                                title=raw_title,
                                severity=f.get("severity", "MEDIUM"),
                                standard_violation=f.get("standard_violation", ""),
                                recommendation=raw_rec
                            ))
                            
                except Exception as e:
                    logger.error(f"Failed to parse category {category['name']} response: {e}")

            # 3. Apply Deduplication Logic (Phase 2 Requirement)
            # We treat the list of architectural findings as raw data to be filtered
            deduplicated = deduplicate_findings(all_findings)

            # 4. Create Separate Data Views
            # View A: Full Dataset for User Download (Raw JSON)
            full_dataset = {
                "project_id": project_id,
                "scan_type": "architectural_review",
                "generated_at": time.time(),
                "summary_stats": snapshot_summary["high_level_stats"],
                "resources": resources, # Full List
                "iam_policies": iam_policies # Full List
            }

            return ArchitectureInfo(
                findings=deduplicated,
                raw_data=full_dataset
            )
            
        except Exception as global_e:
            logger.error(f"Architectural review failed: {global_e}")
            return ArchitectureInfo(
                scan_status="error", 
                error=f"AI Analysis Failed: {str(global_e)}"
            )
