"""
IAM Narrative Service
Generates expert security narratives for IAM principals based on analysis data.
"""
from typing import Dict, Any, List

class IamNarrativeService:
    def generate_narratives(self, iam_analysis: Dict[str, Any]) -> Dict[str, str]:
        """
        Generates a human-readable security narrative for each risky principal.
        
        Args:
            iam_analysis: The raw results from IamAnalysisService
            
        Returns:
            Dictionary mapping principal emails to their security narrative string
        """
        narratives = {}
        
        # 1. Process Basic Role Risks (Owners/Editors)
        for risk in iam_analysis.get('basic_roles', []):
            member = risk['member']
            role = risk['role']
            
            # Initialize or append
            current_narrative = narratives.get(member, [])
            
            if role == 'roles/owner':
                current_narrative.append(
                    "This account has optimal control over the project (Owner). "
                    "This violates Least Privilege. Owners can delete the project, modify all IAM policies, and access all data. "
                    "Action: Downgrade to 'Editor' or specific functional roles immediately."
                )
            elif role == 'roles/editor':
                current_narrative.append(
                    "This account has broad edit access to most services (Editor). "
                    "While less risky than Owner, it is still too broad for most users or service accounts. "
                    "Action: Replace with granular roles (e.g., 'Compute Admin', 'Storage Object Admin')."
                )
            elif role == 'roles/viewer':
                current_narrative.append(
                    "This account has read-only access to almost everything (Viewer). "
                    "While safer, ensure this user truly needs to see ALL data, including potential secrets in metadata."
                )
                
            narratives[member] = current_narrative

        # 2. Process Service Account Key Risks
        for risk in iam_analysis.get('service_account_keys', []):
            account = risk['account']
            age = risk['age_days']
            key_id = risk['key_id'][:8]
            
            current_narrative = narratives.get(account, [])
            current_narrative.append(
                f"We found a user-managed key (ID: {key_id}...) that is {age} days old. "
                "Long-lived keys are a primary target for attackers. "
                "Action: Rotate this key immediately. Ideally, switch to Workload Identity Federation to eliminate keys entirely."
            )
            narratives[account] = current_narrative

        # 3. Process Default Service Accounts
        for risk in iam_analysis.get('default_service_accounts', []):
            account = risk['account']
            
            current_narrative = narratives.get(account, [])
            current_narrative.append(
                "This is a Google-managed default service account with the primitive 'Editor' role. "
                "If a VM using this account is compromised, the attacker gains Editor access to your whole project. "
                "Action: Disable automatic role grants for default SAs and restrict this account's permissions."
            )
            narratives[account] = current_narrative

        # 4. Process External Members
        for risk in iam_analysis.get('external_members', []):
            member = risk['member']
            
            current_narrative = narratives.get(member, [])
            current_narrative.append(
                "This identity belongs to a public domain (e.g., gmail.com). "
                "It is not managed by your organization's corporate policies (MFA, password complexity). "
                "Action: Revoke access and invite a corporate account instead."
            )
            narratives[member] = current_narrative
            
        # 5. Format final strings
        final_narratives = {}
        for member, lines in narratives.items():
            # Deduplicate lines
            unique_lines = list(set(lines))
            # Join nicely
            explanation = " ".join(unique_lines)
            
            # Add MFA note for users vs SAs (Removed as per user request to declutter)
            # if "serviceAccount" not in member: ...
            
            final_narratives[member] = explanation
            
        return final_narratives
