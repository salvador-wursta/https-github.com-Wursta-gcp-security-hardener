"""
Script Generator Service
Generates shell scripts with gcloud commands for lockdown and backout operations
"""
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from app.models.lockdown_models import LockdownRequest, SecurityProfile, MultiProjectLockdownRequest
from app.models.backout_models import BackoutRequest
from app.services.security_profiles import SecurityProfiles
from app.services.risk_to_step_mapping import get_steps_for_risks

logger = logging.getLogger(__name__)


class ScriptGenerator:
    """Service for generating executable shell scripts"""
    
    @staticmethod
    def generate_lockdown_script(request: LockdownRequest) -> str:
        """
        Generate a shell script with gcloud commands for lockdown
        
        Args:
            request: Lockdown request with all configuration
            
        Returns:
            Shell script as string
        """
        # Extract project_id from request or service account credentials
        project_id = request.project_id
        if not project_id and request.service_account_credentials:
            project_id = request.service_account_credentials.get('project_id')
        
        if not project_id:
            raise ValueError("Project ID is required. Please provide project_id in the request or ensure your service account key includes a project_id field.")
        
        logger.info(f"Generating lockdown script for project: {project_id}")
        
        profile = request.security_profile
        profile_config = SecurityProfiles.get_profile(profile)
        selected_steps = get_steps_for_risks(request.selected_risk_ids or [])
        
        # Add region_lockdown if region is specified
        if request.region:
            selected_steps.add("region_lockdown")
        
        # Log what steps are being applied
        logger.info(f"  Profile: {profile_config['name']}")
        logger.info(f"  Selected risk IDs: {request.selected_risk_ids or []}")
        logger.info(f"  Selected steps: {sorted(selected_steps)}")
        logger.info(f"  Region: {request.region or 'None'}")
        
        script_lines = [
            "#!/bin/bash",
            "#",
            "# GCP Security Hardener - Lockdown Script",
            f"# Project: {project_id}",
            f"# Security Profile: {profile_config['name']}",
            f"# Generated: {datetime.now().isoformat()}",
            "#",
            "# WARNING: This script will apply security policies to your GCP project.",
            "# Review all commands before executing.",
            "#",
            "",
            "# ============================================================================",
            "# CONFIGURATION",
            "# ============================================================================",
            f"PROJECT_ID=\"{project_id}\"",
            "",
            "# Validate that PROJECT_ID is set",
            "if [ -z \"$PROJECT_ID\" ]; then",
            "  echo \"ERROR: PROJECT_ID is not set. Please set it in this script.\"",
            "  exit 1",
            "fi",
            "",
            "echo \"================================================================================\"",
            f"echo \"Applying security lockdown to project: $PROJECT_ID\"",
            "echo \"================================================================================\"",
            "",
            "# Set the project",
            "echo \"Setting GCP project to: $PROJECT_ID\"",
            f"gcloud config set project $PROJECT_ID || {{",
            "  echo \"ERROR: Failed to set project. Please check that PROJECT_ID is correct.\"",
            "  exit 1",
            "}",
            "",
            "# Verify project exists and is accessible",
            "echo \"Verifying project access...\"",
            "gcloud projects describe $PROJECT_ID > /dev/null 2>&1 || {",
            "  echo \"ERROR: Cannot access project $PROJECT_ID. Please check:\"",
            "  echo \"  1. Project ID is correct\"",
            "  echo \"  2. You have permissions to access this project\"",
            "  echo \"  3. You are authenticated with gcloud\"",
            "  exit 1",
            "}",
            "echo \"✓ Project verified: $PROJECT_ID\"",
            "",
            "# Enable required APIs",
            "echo 'Enabling required APIs...'",
            "gcloud services enable orgpolicy.googleapis.com --project=$PROJECT_ID",
            "gcloud services enable billingbudgets.googleapis.com --project=$PROJECT_ID",
            "gcloud services enable logging.googleapis.com --project=$PROJECT_ID",
            "gcloud services enable pubsub.googleapis.com --project=$PROJECT_ID",
            "",
        ]
        
        # API Restrictions
        if "api_restrictions" in selected_steps:
            allowed_apis = SecurityProfiles.get_allowed_apis(profile)
            script_lines.extend([
                "#",
                "# Step 1: Restrict API Access",
                "# Only allow specific APIs to be enabled",
                "#",
                "echo 'Applying API restrictions...'",
                f"# Allowed APIs: {', '.join(allowed_apis[:5])}{'...' if len(allowed_apis) > 5 else ''}",
                "",
                "# Set organization policy to restrict services",
                "# Note: This requires orgpolicy.googleapis.com API",
                "echo \"Setting API restrictions policy...\"",
                "if ! gcloud resource-manager org-policies set-policy \\",
                f"  --project=$PROJECT_ID \\",
                f"  --policy-name=constraints/serviceuser.services \\",
                f"  --policy-file=- <<EOF; then",
                "  echo \"ERROR: Failed to set API restrictions policy\"",
                "  exit 1",
                "fi",
                "{",
                "  \"spec\": {",
                "    \"rules\": [",
                "      {",
                "        \"enforce\": true,",
                "        \"values\": {",
                "          \"allowedValues\": [",
            ])
            for api in allowed_apis:
                script_lines.append(f'            "{api}",')
            script_lines.extend([
                "          ]",
                "        }",
                "      }",
                "    ]",
                "  }",
                "}",
                "EOF",
                "",
            ])
        
        # Network Hardening
        if "network_hardening" in selected_steps:
            allow_external = SecurityProfiles.should_allow_external_ips(profile)
            script_lines.extend([
                "#",
                "# Step 2: Network Hardening - Restrict External IPs",
                "#",
                "echo 'Applying network hardening...'",
            ])
            if not allow_external:
                script_lines.extend([
                    "echo \"Setting external IP restriction policy...\"",
                    "if ! gcloud resource-manager org-policies set-policy \\",
                    "  --project=$PROJECT_ID \\",
                    "  --policy-name=constraints/compute.vmExternalIpAccess \\",
                    "  --policy-file=- <<EOF; then",
                    "  echo \"ERROR: Failed to set external IP restriction policy\"",
                    "  exit 1",
                    "fi",
                    "{",
                    "  \"spec\": {",
                    "    \"rules\": [",
                    "      {",
                    "        \"enforce\": true",
                    "      }",
                    "    ]",
                    "  }",
                    "}",
                    "EOF",
                    "",
                ])
            else:
                script_lines.append("# External IPs allowed for this profile (Web App)")
                script_lines.append("")
        
        # Service Account Key Protection
        if "service_account_keys" in selected_steps:
            script_lines.extend([
                "#",
                "# Step 3: Disable Service Account Key Creation",
                "#",
                "echo 'Disabling service account key creation...'",
                "if ! gcloud resource-manager org-policies set-policy \\",
                "  --project=$PROJECT_ID \\",
                "  --policy-name=constraints/iam.disableServiceAccountKeyCreation \\",
                "  --policy-file=- <<EOF; then",
                "  echo \"ERROR: Failed to set service account key restriction policy\"",
                "  exit 1",
                "fi",
                "{",
                "  \"spec\": {",
                "    \"rules\": [",
                "      {",
                "        \"enforce\": true",
                "      }",
                "    ]",
                "  }",
                "}",
                "EOF",
                "",
            ])
        
        # Region Lockdown
        if "region_lockdown" in selected_steps and request.region:
            script_lines.extend([
                "#",
                f"# Step 4: Region Lockdown - Restrict to {request.region}",
                "#",
                f"echo 'Applying region lockdown to {request.region}...'",
                "if ! gcloud resource-manager org-policies set-policy \\",
                "  --project=$PROJECT_ID \\",
                "  --policy-name=constraints/compute.restrictAllowedResources \\",
                "  --policy-file=- <<EOF; then",
                "  echo \"ERROR: Failed to set region restriction policy\"",
                "  exit 1",
                "fi",
                "{",
                "  \"spec\": {",
                "    \"rules\": [",
                "      {",
                "        \"enforce\": true,",
                "        \"values\": {",
                "          \"allowedValues\": [",
                f'            "regions/{request.region}"',
                "          ]",
                "        }",
                "      }",
                "    ]",
                "  }",
                "}",
                "EOF",
                "",
            ])
        
        # Quota Caps (GPU)
        if "quota_caps" in selected_steps:
            allow_gpus = SecurityProfiles.should_allow_gpus(profile)
            script_lines.extend([
                "",
                "# ============================================================================",
                "# Step 5: GPU Quota Management",
                "# ============================================================================",
                "echo ''",
                "echo '================================================================================'",
                "echo 'GPU QUOTA ADJUSTMENT'",
                "echo '================================================================================'",
            ])
            if not allow_gpus:
                script_lines.extend([
                    "echo ''",
                    "echo '⚠️  GPU quota must be set to 0 to prevent crypto-mining attacks'",
                    "echo ''",
                    "echo 'IMPORTANT: GCP does not allow programmatic quota setting.'",
                    "echo 'This is a security feature to prevent malicious quota manipulation.'",
                    "echo ''",
                    "echo 'Please follow these steps to adjust your GPU quota:'",
                    "echo ''",
                    "echo 'Option 1: Use GCP Console (Recommended)'",
                    f"echo '  1. Open: https://console.cloud.google.com/iam-admin/quotas?project={project_id}'",
                    "echo '  2. In the Filter box, type: GPU'",
                    "echo '  3. Check the boxes next to GPU quotas you want to change'",
                    "echo '  4. Click \"EDIT QUOTAS\" at the top'",
                    "echo '  5. Set \"New limit\" to: 0'",
                    "echo '  6. Provide justification: Security hardening - preventing crypto-mining attacks'",
                    "echo '  7. Click \"DONE\" then \"SUBMIT REQUEST\"'",
                    "echo '  8. Wait for approval (usually instant for decreases)'",
                    "echo ''",
                    "echo 'Option 2: Check Current Quotas with gcloud'",
                    "echo '  Run this command to see current quotas:'",
                    "echo ''",
                    "echo '  for region in \\$(gcloud compute regions list --format=\"value(name)\"); do'",
                    "echo '    echo \"Region: \\$region\"'",
                    "echo '    gcloud compute regions describe \\$region --format=\"table(quotas.metric,quotas.limit,quotas.usage)\" | grep -i gpu'",
                    "echo '  done'",
                    "echo ''",
                    f"echo '📋 Quick Link: https://console.cloud.google.com/iam-admin/quotas?project={project_id}'",
                    "echo ''",
                    "read -p 'Press Enter after you have adjusted the GPU quotas to continue...'",
                    "",
                ])
            else:
                script_lines.extend([
                    "echo '✓ GPU quota left unchanged (required for Vertex AI or ML workloads)'",
                    "echo ''",
                ])
        
        # Billing Kill Switch
        if "billing_kill_switch" in selected_steps and request.budget_limit:
            script_lines.extend([
                "#",
                f"# Step 6: Create Billing Budget (${request.budget_limit}/month)",
                "#",
                "echo 'Creating billing budget...'",
                "",
                "# Get billing account ID",
                "BILLING_ACCOUNT=$(gcloud billing projects describe $PROJECT_ID --format='value(billingAccountName)' | cut -d'/' -f2)",
                "",
                "if [ -z \"$BILLING_ACCOUNT\" ]; then",
                "  echo 'ERROR: No billing account found. Please link a billing account first.'",
                "  exit 1",
                "fi",
                "",
            ])
            
            # Create notification channel if email is provided
            if request.alert_email:
                script_lines.extend([
                    "#",
                    f"# Step 6.1: Create Notification Channel for {request.alert_email}",
                    "#",
                    "echo 'Creating notification channel for budget alerts...'",
                    "",
                    f"# Create email notification channel",
                    "NOTIFICATION_CHANNEL=$(gcloud alpha monitoring channels create \\",
                    "  --display-name=\"Security Hardener Budget Alerts\" \\",
                    "  --type=email \\",
                    f"  --channel-labels=email_address={request.alert_email} \\",
                    "  --format='value(name)' 2>/dev/null || echo '')",
                    "",
                    "# If channel creation fails, try alternative method",
                    "if [ -z \"$NOTIFICATION_CHANNEL\" ]; then",
                    "  echo 'Warning: Could not create notification channel via gcloud CLI.'",
                    f"  echo 'Please create a notification channel manually in GCP Console for: {request.alert_email}'",
                    "  echo 'Visit: https://console.cloud.google.com/monitoring/alerting/notificationChannels'",
                    "  NOTIFICATION_CHANNEL=\"\"",
                    "else",
                    "  echo \"✓ Notification channel created: $NOTIFICATION_CHANNEL\"",
                    "fi",
                    "",
                ])
            
            script_lines.extend([
                f"# Create budget with ${request.budget_limit} limit",
                "gcloud billing budgets create \\",
                f"  --billing-account=$BILLING_ACCOUNT \\",
                f"  --display-name=\"Security Hardener Budget - ${request.budget_limit}/month\" \\",
                f"  --budget-amount={int(request.budget_limit)}USD \\",
                f"  --threshold-rule=percent={100.0} \\",
                f"  --projects=$PROJECT_ID",
            ])
            
            if request.alert_email:
                script_lines.extend([
                    "  --notification-rule=monitoring-notification-channels=$NOTIFICATION_CHANNEL \\",
                    "  --notification-rule=disable-default-iam-recipients=false \\",
                ])
            
            script_lines.extend([
                "  || {",
                "    echo \"ERROR: Failed to create billing budget\"",
                "    exit 1",
                "  }",
                "",
            ])
            
            if request.alert_email:
                script_lines.extend([
                    f"echo \"✓ Budget created with alerts to: {request.alert_email}\"",
                    "",
                ])
        
        # Change Management Logging
        if "change_management" in selected_steps:
            script_lines.extend([
                "#",
                "# Step 7: Set Up Change Monitoring",
                "#",
                "echo 'Setting up change monitoring...'",
                "",
            ])
            
            if request.alert_email:
                script_lines.extend([
                    "#",
                    f"# Step 7.1: Create Notification Channel for {request.alert_email}",
                    "#",
                    "echo 'Creating notification channel for change monitoring alerts...'",
                    "",
                    f"# Create email notification channel for logging alerts",
                    "LOGGING_NOTIFICATION_CHANNEL=$(gcloud alpha monitoring channels create \\",
                    "  --display-name=\"Security Hardener Change Monitoring\" \\",
                    "  --type=email \\",
                    f"  --channel-labels=email_address={request.alert_email} \\",
                    "  --format='value(name)' 2>/dev/null || echo '')",
                    "",
                    "# If channel creation fails, try alternative method",
                    "if [ -z \"$LOGGING_NOTIFICATION_CHANNEL\" ]; then",
                    "  echo 'Warning: Could not create notification channel via gcloud CLI.'",
                    f"  echo 'Please create a notification channel manually in GCP Console for: {request.alert_email}'",
                    "  echo 'Visit: https://console.cloud.google.com/monitoring/alerting/notificationChannels'",
                    "  LOGGING_NOTIFICATION_CHANNEL=\"\"",
                    "else",
                    "  echo \"✓ Notification channel created: $LOGGING_NOTIFICATION_CHANNEL\"",
                    "fi",
                    "",
                    "#",
                    "# Step 7.2: Create Logging Sink for API Enablement Monitoring",
                    "#",
                    "echo 'Creating logging sink for API enablement monitoring...'",
                    "",
                    "# Create Pub/Sub topic for logging sink destination",
                    "gcloud pubsub topics create api-enablement-alerts --project=$PROJECT_ID 2>/dev/null || echo 'Topic may already exist'",
                    "",
                    "# Create logging sink",
                    "gcloud logging sinks create api-enablement-monitor \\",
                    "  pubsub.googleapis.com/projects/$PROJECT_ID/topics/api-enablement-alerts \\",
                    "  --log-filter='protoPayload.methodName=\\\"google.api.serviceusage.v1.ServiceUsage.EnableService\\\"' \\",
                    "  --project=$PROJECT_ID || {",
                    "  echo 'Warning: Failed to create logging sink. You may need to create it manually.'",
                    "}",
                    "",
                    f"echo \"✓ Change monitoring configured. Alerts will be sent to: {request.alert_email}\"",
                    "",
                ])
            else:
                script_lines.extend([
                    "# Create logging sink for API enablement monitoring",
                    "# Note: Email notifications require a notification channel to be set up",
                    "echo 'Creating logging sink for API enablement monitoring...'",
                    "",
                    "# Create Pub/Sub topic for logging sink destination",
                    "gcloud pubsub topics create api-enablement-alerts --project=$PROJECT_ID 2>/dev/null || echo 'Topic may already exist'",
                    "",
                    "# Create logging sink",
                    "gcloud logging sinks create api-enablement-monitor \\",
                    "  pubsub.googleapis.com/projects/$PROJECT_ID/topics/api-enablement-alerts \\",
                    "  --log-filter='protoPayload.methodName=\\\"google.api.serviceusage.v1.ServiceUsage.EnableService\\\"' \\",
                    "  --project=$PROJECT_ID || {",
                    "  echo 'Warning: Failed to create logging sink. You may need to create it manually.'",
                    "}",
                    "",
                    "echo '✓ Logging sink created. Set up notification channels in GCP Console to receive email alerts.'",
                    "",
                ])
        
        script_lines.extend([
            "#",
            "# Lockdown Complete",
            "#",
            "echo 'Lockdown script completed!'",
            "echo 'Review the applied policies in GCP Console: https://console.cloud.google.com/iam-admin/orgpolicies?project='$PROJECT_ID",
            "",
        ])
        
        return "\n".join(script_lines)
    
    @staticmethod
    def generate_multi_project_lockdown_script(request: MultiProjectLockdownRequest) -> str:
        """
        Generate a shell script with gcloud commands for multi-project lockdown
        
        Args:
            request: Multi-project lockdown request
            
        Returns:
            Shell script as string
        """
        if not request.project_ids:
            raise ValueError("At least one project ID is required")
        
        profile = request.security_profile
        profile_config = SecurityProfiles.get_profile(profile)
        selected_steps = get_steps_for_risks(request.selected_risk_ids or [])
        
        # Add region_lockdown if region is specified
        if request.region:
            selected_steps.add("region_lockdown")
        
        # Log what steps are being applied
        logger.info(f"Generating multi-project lockdown script for {len(request.project_ids)} projects")
        logger.info(f"  Profile: {profile_config['name']}")
        logger.info(f"  Selected risk IDs: {request.selected_risk_ids or []}")
        logger.info(f"  Selected steps: {sorted(selected_steps)}")
        logger.info(f"  Region: {request.region or 'None'}")
        
        script_lines = [
            "#!/bin/bash",
            "#",
            "# GCP Security Hardener - Multi-Project Lockdown Script",
            f"# Projects: {', '.join(request.project_ids)}",
            f"# Security Profile: {profile_config['name']}",
            f"# Generated: {datetime.now().isoformat()}",
            "#",
            "# WARNING: This script will apply security policies to multiple GCP projects.",
            "# Review all commands before executing.",
            "#",
            "",
            "# ============================================================================",
            "# CONFIGURATION",
            "# ============================================================================",
            "# List of projects to apply lockdown to",
            "PROJECT_IDS=(",
        ]
        
        # Add all project IDs
        for project_id in request.project_ids:
            script_lines.append(f'  "{project_id}"')
        
        script_lines.extend([
            ")",
            "",
            "# Validate that PROJECT_IDS is set",
            "if [ ${#PROJECT_IDS[@]} -eq 0 ]; then",
            "  echo \"ERROR: No projects specified. Please set PROJECT_IDS in this script.\"",
            "  exit 1",
            "fi",
            "",
            "echo \"================================================================================\"",
            "echo \"Applying security lockdown to ${#PROJECT_IDS[@]} project(s)\"",
            "echo \"================================================================================\"",
            "",
            "# Function to apply lockdown to a single project",
            "apply_lockdown_to_project() {",
            "  local PROJECT_ID=$1",
            "  echo \"\"",
            "  echo \"--------------------------------------------------------------------------------\"",
            "  echo \"Processing project: $PROJECT_ID\"",
            "  echo \"--------------------------------------------------------------------------------\"",
            "",
            "  # Set the project",
            "  echo \"Setting GCP project to: $PROJECT_ID\"",
            "  gcloud config set project $PROJECT_ID || {",
            "    echo \"ERROR: Failed to set project $PROJECT_ID. Skipping...\"",
            "    return 1",
            "  }",
            "",
            "  # Verify project exists and is accessible",
            "  echo \"Verifying project access...\"",
            "  gcloud projects describe $PROJECT_ID > /dev/null 2>&1 || {",
            "    echo \"ERROR: Cannot access project $PROJECT_ID. Skipping...\"",
            "    return 1",
            "  }",
            "  echo \"✓ Project verified: $PROJECT_ID\"",
            "",
            "  # Enable required APIs",
            "  echo \"Enabling required APIs...\"",
            "  gcloud services enable orgpolicy.googleapis.com --project=$PROJECT_ID || echo \"Warning: Failed to enable orgpolicy API\"",
            "  gcloud services enable billingbudgets.googleapis.com --project=$PROJECT_ID || echo \"Warning: Failed to enable billingbudgets API\"",
            "  gcloud services enable logging.googleapis.com --project=$PROJECT_ID || echo \"Warning: Failed to enable logging API\"",
            "  gcloud services enable pubsub.googleapis.com --project=$PROJECT_ID || echo \"Warning: Failed to enable pubsub API\"",
            "",
        ])
        
        # Add the lockdown steps (same as single project, but inside the function)
        # API Restrictions
        if "api_restrictions" in selected_steps:
            allowed_apis = SecurityProfiles.get_allowed_apis(profile)
            script_lines.extend([
                "  #",
                "  # Step 1: Restrict API Access",
                "  #",
                "  echo \"Applying API restrictions...\"",
                "  if ! gcloud resource-manager org-policies set-policy \\",
                "    --project=$PROJECT_ID \\",
                "    --policy-name=constraints/serviceuser.services \\",
                "    --policy-file=- <<EOF; then",
                "    echo \"ERROR: Failed to set API restrictions policy for $PROJECT_ID\"",
                "    return 1",
                "  fi",
                "  {",
                "    \"spec\": {",
                "      \"rules\": [",
                "        {",
                "          \"enforce\": true,",
                "          \"values\": {",
                "            \"allowedValues\": [",
            ])
            for api in allowed_apis:
                script_lines.append(f'              "{api}",')
            script_lines.extend([
                "            ]",
                "          }",
                "        }",
                "      ]",
                "    }",
                "  }",
                "  EOF",
                "",
            ])
        
        # Network Hardening
        if "network_hardening" in selected_steps:
            allow_external = SecurityProfiles.should_allow_external_ips(profile)
            if not allow_external:
                script_lines.extend([
                    "  #",
                    "  # Step 2: Network Hardening",
                    "  #",
                    "  echo \"Applying network hardening...\"",
                    "  if ! gcloud resource-manager org-policies set-policy \\",
                    "    --project=$PROJECT_ID \\",
                    "    --policy-name=constraints/compute.vmExternalIpAccess \\",
                    "    --policy-file=- <<EOF; then",
                    "    echo \"ERROR: Failed to set external IP restriction policy for $PROJECT_ID\"",
                    "    return 1",
                    "  fi",
                    "  {",
                    "    \"spec\": {",
                    "      \"rules\": [",
                    "        {",
                    "          \"enforce\": true",
                    "        }",
                    "      ]",
                    "    }",
                    "  }",
                    "  EOF",
                    "",
                ])
        
        # Service Account Key Protection
        if "service_account_keys" in selected_steps:
            script_lines.extend([
                "  #",
                "  # Step 3: Disable Service Account Key Creation",
                "  #",
                "  echo \"Disabling service account key creation...\"",
                "  if ! gcloud resource-manager org-policies set-policy \\",
                "    --project=$PROJECT_ID \\",
                "    --policy-name=constraints/iam.disableServiceAccountKeyCreation \\",
                "    --policy-file=- <<EOF; then",
                "    echo \"ERROR: Failed to set service account key restriction policy for $PROJECT_ID\"",
                "    return 1",
                "  fi",
                "  {",
                "    \"spec\": {",
                "      \"rules\": [",
                "        {",
                "          \"enforce\": true",
                "        }",
                "      ]",
                "    }",
                "  }",
                "  EOF",
                "",
            ])
        
        # Region Lockdown
        if "region_lockdown" in selected_steps and request.region:
            script_lines.extend([
                "  #",
                f"  # Step 4: Region Lockdown - Restrict to {request.region}",
                "  #",
                f"  echo \"Applying region lockdown to {request.region}...\"",
                "  if ! gcloud resource-manager org-policies set-policy \\",
                "    --project=$PROJECT_ID \\",
                "    --policy-name=constraints/compute.restrictAllowedResources \\",
                "    --policy-file=- <<EOF; then",
                "    echo \"ERROR: Failed to set region restriction policy for $PROJECT_ID\"",
                "    return 1",
                "  fi",
                "  {",
                "    \"spec\": {",
                "      \"rules\": [",
                "        {",
                "          \"enforce\": true,",
                "          \"values\": {",
                "            \"allowedValues\": [",
                f'              "regions/{request.region}"',
                "            ]",
                "          }",
                "        }",
                "      ]",
                "    }",
                "  }",
                "  EOF",
                "",
            ])
        
        # Billing Kill Switch
        if "billing_kill_switch" in selected_steps and request.budget_limit:
            script_lines.extend([
                "  #",
                f"  # Step 6: Create Billing Budget (${request.budget_limit}/month)",
                "  #",
                "  echo \"Creating billing budget...\"",
                "  BILLING_ACCOUNT=$(gcloud billing projects describe $PROJECT_ID --format='value(billingAccountName)' | cut -d'/' -f2)",
                "",
                "  if [ -z \"$BILLING_ACCOUNT\" ]; then",
                "    echo \"WARNING: No billing account found for $PROJECT_ID. Skipping budget creation.\"",
                "    return 0",
                "  fi",
                "",
            ])
            
            # Create notification channel if email is provided
            if request.alert_email:
                script_lines.extend([
                    "  #",
                    f"  # Step 6.1: Create Notification Channel for {request.alert_email}",
                    "  #",
                    "  echo \"Creating notification channel for budget alerts...\"",
                    "",
                    f"  # Create email notification channel",
                    "  NOTIFICATION_CHANNEL=$(gcloud alpha monitoring channels create \\",
                    "    --display-name=\"Security Hardener Budget Alerts\" \\",
                    "    --type=email \\",
                    f"    --channel-labels=email_address={request.alert_email} \\",
                    "    --format='value(name)' 2>/dev/null || echo '')",
                    "",
                    "  # If channel creation fails, try alternative method",
                    "  if [ -z \"$NOTIFICATION_CHANNEL\" ]; then",
                    "    echo \"Warning: Could not create notification channel via gcloud CLI.\"",
                    f"    echo \"Please create a notification channel manually in GCP Console for: {request.alert_email}\"",
                    "    echo \"Visit: https://console.cloud.google.com/monitoring/alerting/notificationChannels\"",
                    "    NOTIFICATION_CHANNEL=\"\"",
                    "  else",
                    "    echo \"✓ Notification channel created: $NOTIFICATION_CHANNEL\"",
                    "  fi",
                    "",
                ])
            
            script_lines.extend([
                f"  # Create budget with ${request.budget_limit} limit",
                "  gcloud billing budgets create \\",
                "    --billing-account=$BILLING_ACCOUNT \\",
                f"    --display-name=\"Security Hardener Budget - ${request.budget_limit}/month\" \\",
                f"    --budget-amount={int(request.budget_limit)}USD \\",
                f"    --threshold-rule=percent={100.0} \\",
                "    --projects=$PROJECT_ID",
            ])
            
            if request.alert_email:
                script_lines.extend([
                    "    --notification-rule=monitoring-notification-channels=$NOTIFICATION_CHANNEL \\",
                    "    --notification-rule=disable-default-iam-recipients=false \\",
                ])
            
            script_lines.extend([
                "    || {",
                "      echo \"ERROR: Failed to create billing budget for $PROJECT_ID\"",
                "      return 1",
                "    }",
                "",
            ])
            
            if request.alert_email:
                script_lines.extend([
                    f"  echo \"✓ Budget created with alerts to: {request.alert_email}\"",
                    "",
                ])
        
        # GPU Quota Management (same as single project, but with proper indentation)
        if "quota_caps" in selected_steps:
            allow_gpus = SecurityProfiles.should_allow_gpus(profile)
            script_lines.extend([
                "  echo \"\"",
                "  echo \"================================================================================\"",
                "  echo \"GPU QUOTA ADJUSTMENT\"",
                "  echo \"================================================================================\"",
            ])
            if not allow_gpus:
                # For multi-project, we need to show project-specific links
                script_lines.extend([
                    "  echo \"\"",
                    "  echo '⚠️  GPU quota must be set to 0 to prevent crypto-mining attacks'",
                    "  echo \"\"",
                    "  echo 'IMPORTANT: GCP does not allow programmatic quota setting.'",
                    "  echo 'This is a security feature to prevent malicious quota manipulation.'",
                    "  echo \"\"",
                    "  echo 'Please follow these steps to adjust your GPU quota:'",
                    "  echo \"\"",
                    "  echo 'Option 1: Use GCP Console (Recommended)'",
                    "  echo \"  1. Open: https://console.cloud.google.com/iam-admin/quotas?project=$PROJECT_ID\"",
                    "  echo '  2. In the Filter box, type: GPU'",
                    "  echo '  3. Check the boxes next to GPU quotas you want to change'",
                    "  echo '  4. Click \"EDIT QUOTAS\" at the top'",
                    "  echo '  5. Set \"New limit\" to: 0'",
                    "  echo '  6. Provide justification: Security hardening - preventing crypto-mining attacks'",
                    "  echo '  7. Click \"DONE\" then \"SUBMIT REQUEST\"'",
                    "  echo '  8. Wait for approval (usually instant for decreases)'",
                    "  echo \"\"",
                    "  echo 'Option 2: Check Current Quotas with gcloud'",
                    "  echo '  Run this command to see current quotas:'",
                    "  echo \"\"",
                    "  echo '  for region in \\$(gcloud compute regions list --format=\"value(name)\"); do'",
                    "  echo '    echo \"Region: \\$region\"'",
                    "  echo '    gcloud compute regions describe \\$region --format=\"table(quotas.metric,quotas.limit,quotas.usage)\" | grep -i gpu'",
                    "  echo '  done'",
                    "  echo \"\"",
                    "  echo \"📋 Quick Link: https://console.cloud.google.com/iam-admin/quotas?project=$PROJECT_ID\"",
                    "  echo \"\"",
                    "  read -p 'Press Enter after you have adjusted the GPU quotas for this project to continue...'",
                    "",
                ])
            else:
                script_lines.extend([
                    "  echo '✓ GPU quota left unchanged (required for Vertex AI or ML workloads)'",
                    "  echo \"\"",
                ])
        
        script_lines.extend([
            "  echo \"✓ Lockdown completed for project: $PROJECT_ID\"",
            "  return 0",
            "}",
            "",
            "# Apply lockdown to each project",
            "SUCCESS_COUNT=0",
            "FAILED_COUNT=0",
            "",
            "for PROJECT_ID in \"${PROJECT_IDS[@]}\"; do",
            "  if apply_lockdown_to_project \"$PROJECT_ID\"; then",
            "    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))",
            "  else",
            "    FAILED_COUNT=$((FAILED_COUNT + 1))",
            "  fi",
            "done",
            "",
            "# Summary",
            "echo \"\"",
            "echo \"================================================================================\"",
            "echo \"Lockdown Summary\"",
            "echo \"================================================================================\"",
            "echo \"Total projects: ${#PROJECT_IDS[@]}\"",
            "echo \"Successful: $SUCCESS_COUNT\"",
            "echo \"Failed: $FAILED_COUNT\"",
            "echo \"\"",
            "echo \"Review the applied policies in GCP Console:\"",
            "for PROJECT_ID in \"${PROJECT_IDS[@]}\"; do",
            "  echo \"  https://console.cloud.google.com/iam-admin/orgpolicies?project=$PROJECT_ID\"",
            "done",
            "",
        ])
        
        return "\n".join(script_lines)
    
    @staticmethod
    def generate_backout_script(request: BackoutRequest) -> str:
        """
        Generate a shell script with gcloud commands for backout
        
        Args:
            request: Backout request
            
        Returns:
            Shell script as string
        """
        # Extract project_id from request or service account credentials
        project_id = request.project_id
        if not project_id and request.service_account_credentials:
            project_id = request.service_account_credentials.get('project_id')
        
        if not project_id:
            raise ValueError("Project ID is required. Please provide project_id in the request or ensure your service account key includes a project_id field.")
        
        logger.info(f"Generating backout script for project: {project_id}")
        
        script_lines = [
            "#!/bin/bash",
            "#",
            "# GCP Security Hardener - Backout Script",
            f"# Project: {project_id}",
            f"# Generated: {datetime.now().isoformat()}",
            "#",
            "# WARNING: This script will REMOVE security protections!",
            "# Your project will be vulnerable to the same risks that existed before.",
            "# Review all commands before executing.",
            "#",
            "",
            "# ============================================================================",
            "# CONFIGURATION",
            "# ============================================================================",
            f"PROJECT_ID=\"{project_id}\"",
            "",
            "# Validate that PROJECT_ID is set",
            "if [ -z \"$PROJECT_ID\" ]; then",
            "  echo \"ERROR: PROJECT_ID is not set. Please set it in this script.\"",
            "  exit 1",
            "fi",
            "",
            "echo \"================================================================================\"",
            f"echo \"Rolling back security lockdown for project: $PROJECT_ID\"",
            "echo \"================================================================================\"",
            "",
            "# Set the project",
            "echo \"Setting GCP project to: $PROJECT_ID\"",
            f"gcloud config set project $PROJECT_ID || {{",
            "  echo \"ERROR: Failed to set project. Please check that PROJECT_ID is correct.\"",
            "  exit 1",
            "}",
            "",
            "# Verify project exists and is accessible",
            "echo \"Verifying project access...\"",
            "gcloud projects describe $PROJECT_ID > /dev/null 2>&1 || {",
            "  echo \"ERROR: Cannot access project $PROJECT_ID. Please check:\"",
            "  echo \"  1. Project ID is correct\"",
            "  echo \"  2. You have permissions to access this project\"",
            "  echo \"  3. You are authenticated with gcloud\"",
            "  exit 1",
            "}",
            "echo \"✓ Project verified: $PROJECT_ID\"",
            "",
            "#",
            "# Step 1: Remove API Restrictions",
            "#",
            "echo 'Removing API restrictions...'",
            "# Remove or set empty policy to allow all APIs",
            "gcloud resource-manager org-policies delete \\",
            "  --project=$PROJECT_ID \\",
            "  --policy-name=constraints/serviceuser.services || echo 'Policy not found or already removed'",
            "",
            "#",
            "# Step 2: Remove Network Hardening",
            "#",
            "echo 'Removing network hardening...'",
            "gcloud resource-manager org-policies delete \\",
            "  --project=$PROJECT_ID \\",
            "  --policy-name=constraints/compute.vmExternalIpAccess || echo 'Policy not found or already removed'",
            "",
            "#",
            "# Step 3: Re-enable Service Account Key Creation",
            "#",
            "echo 'Re-enabling service account key creation...'",
            "gcloud resource-manager org-policies delete \\",
            "  --project=$PROJECT_ID \\",
            "  --policy-name=constraints/iam.disableServiceAccountKeyCreation || echo 'Policy not found or already removed'",
            "",
            "#",
            "# Step 4: Remove Region Lockdown",
            "#",
            "echo 'Removing region restrictions...'",
            "gcloud resource-manager org-policies delete \\",
            "  --project=$PROJECT_ID \\",
            "  --policy-name=constraints/compute.restrictAllowedResources || echo 'Policy not found or already removed'",
            "",
            "#",
            "# Step 5: Restore GPU Quota",
            "#",
            "echo 'GPU quota restrictions removed.'",
            "echo 'Note: You may need to request quota increases through GCP Console if you need GPUs.'",
            "",
            "#",
            "# Step 6: Remove Billing Kill Switch",
            "#",
            "echo 'Removing billing budgets...'",
            "# List and delete budgets created by security hardener",
            "BILLING_ACCOUNT=$(gcloud billing projects describe $PROJECT_ID --format='value(billingAccountName)' | cut -d'/' -f2)",
            "",
            "if [ -n \"$BILLING_ACCOUNT\" ]; then",
            "  echo 'Listing budgets for deletion...'",
            "  BUDGET_IDS=$(gcloud billing budgets list --billing-account=$BILLING_ACCOUNT --format='value(budgets.budget.budgetId)' --filter='displayName:Security Hardener')",
            "  for BUDGET_ID in $BUDGET_IDS; do",
            "    echo \"Deleting budget $BUDGET_ID...\"",
            "    gcloud billing budgets delete $BUDGET_ID --billing-account=$BILLING_ACCOUNT || echo 'Budget not found or already deleted'",
            "  done",
            "else",
            "  echo 'No billing account found - skipping budget deletion'",
            "fi",
            "",
            "# Note: You may also need to manually delete:",
            "# - Pub/Sub topics created for kill switch",
            "# - Cloud Functions deployed for kill switch",
            "",
            "#",
            "# Step 7: Remove Change Management Logging",
            "#",
            "echo 'Removing change monitoring...'",
            "# List and delete logging sinks",
            "SINK_NAMES=$(gcloud logging sinks list --format='value(name)' --filter='name:api-enablement-monitor')",
            "for SINK_NAME in $SINK_NAMES; do",
            "  echo \"Deleting logging sink $SINK_NAME...\"",
            "  gcloud logging sinks delete $SINK_NAME || echo 'Sink not found or already deleted'",
            "done",
            "",
            "#",
            "# Backout Complete",
            "#",
            "echo 'Backout script completed!'",
            "echo 'All security protections have been removed.'",
            "echo 'Review your project policies: https://console.cloud.google.com/iam-admin/orgpolicies?project='$PROJECT_ID",
            "",
        ]
        
        return "\n".join(script_lines)
