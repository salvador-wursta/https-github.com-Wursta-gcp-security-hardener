"""
Mapping between risk IDs and lockdown steps
Used to determine which lockdown steps to apply based on selected risks
"""
from typing import Dict, List, Set

# Mapping from risk ID to lockdown step IDs
RISK_TO_STEPS: Dict[str, List[str]] = {
    # Risky API risks -> API restrictions
    "risky_api_compute.googleapis.com": ["api_restrictions"],
    "risky_api_container.googleapis.com": ["api_restrictions"],
    "risky_api_ml.googleapis.com": ["api_restrictions"],
    "risky_api_aiplatform.googleapis.com": ["api_restrictions"],
    "risky_api_dataflow.googleapis.com": ["api_restrictions"],
    "compute_api_enabled": ["api_restrictions"],
    
    # Service account key risks -> Service account key protection
    "service_account_keys_allowed": ["service_account_keys"],
    
    # Billing risks -> Billing kill switch
    "no_billing_budgets": ["billing_kill_switch"],
    "budgets_without_alerts": ["billing_kill_switch"],
    "billing_check_failed": ["billing_kill_switch"],
    
    # GPU quota risks -> Quota caps
    "gpu_quota_unlimited": ["quota_caps"],
    
    # Network risks -> Network hardening (if applicable)
    # Note: Network hardening is usually applied based on security profile, not specific risks
    
    # General monitoring -> Change management logging
    # This is usually applied for all risks, but can be selected
}

# Mapping from step ID to risk categories it addresses
STEP_TO_CATEGORIES: Dict[str, List[str]] = {
    "api_restrictions": ["api"],
    "network_hardening": ["network"],
    "service_account_keys": ["iam"],
    "region_lockdown": ["region"],
    "quota_caps": ["quota"],
    "billing_kill_switch": ["billing"],
    "change_management": ["monitoring", "api"]  # Applies to API enablement monitoring
}

# Default steps that should always be applied (if no risks selected, apply all)
DEFAULT_STEPS = [
    "api_restrictions",
    "network_hardening",
    "service_account_keys",
    "quota_caps",
    "billing_kill_switch",
    "change_management"
]

def get_steps_for_risks(risk_ids: List[str]) -> Set[str]:
    """
    Get the set of lockdown step IDs that should be applied for the given risk IDs
    
    Args:
        risk_ids: List of risk IDs selected by the user
    
    Returns:
        Set of step IDs to apply
    
    Note:
        For security hardening, we ALWAYS apply all DEFAULT_STEPS as a baseline.
        Risk selection is ADDITIVE - selecting risks adds additional steps,
        but never reduces the baseline security controls.
    """
    # ALWAYS start with all default steps as baseline security controls
    # This ensures core security is always applied, regardless of risk selection
    steps = set(DEFAULT_STEPS)
    
    if not risk_ids:
        # No risks selected - return all default steps
        return steps
    
    # Add any additional steps based on selected risks
    for risk_id in risk_ids:
        if risk_id in RISK_TO_STEPS:
            steps.update(RISK_TO_STEPS[risk_id])
        else:
            # If risk ID not in mapping, it's already covered by defaults
            # or is a display-only risk (like billing info)
            pass
    
    return steps

def get_risks_for_step(step_id: str) -> List[str]:
    """
    Get risk IDs that would trigger a given step
    
    Args:
        step_id: Lockdown step ID
    
    Returns:
        List of risk IDs that map to this step
    """
    risks = []
    for risk_id, step_ids in RISK_TO_STEPS.items():
        if step_id in step_ids:
            risks.append(risk_id)
    return risks
