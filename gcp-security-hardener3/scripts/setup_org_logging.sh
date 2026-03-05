#!/bin/bash
#
# Organization-Level Logging Setup Script
# GCP Security Hardener
#
# This script sets up organization-wide security alerting using:
# - Aggregated Log Sink (org-level)
# - Central Log Bucket
# - Log-Based Metrics
# - Alert Policies with Email Notification
#

set -e  # Exit on any error

echo "=============================================="
echo "GCP Organization-Level Logging Setup"
echo "=============================================="
echo ""

# =============================================
# CONFIGURATION - EDIT THESE VALUES
# =============================================
ORG_ID=""                           # Your GCP Organization ID (e.g., "123456789012")
CENTRAL_PROJECT="gcp-lockdown-test-proj"  # Your central monitoring project
ALERT_EMAIL=""                       # Email for security alerts
BUCKET_NAME="security-org-logs"      # Log bucket name
# =============================================

# Validate configuration
if [ -z "$ORG_ID" ]; then
    echo "ERROR: Please edit this script and set ORG_ID"
    echo ""
    echo "To find your Organization ID, run:"
    echo "  gcloud organizations list"
    exit 1
fi

if [ -z "$ALERT_EMAIL" ]; then
    echo "ERROR: Please edit this script and set ALERT_EMAIL"
    exit 1
fi

echo "Configuration:"
echo "  Organization ID: $ORG_ID"
echo "  Central Project: $CENTRAL_PROJECT"
echo "  Alert Email:     $ALERT_EMAIL"
echo "  Bucket Name:     $BUCKET_NAME"
echo ""

# Confirm
read -p "Continue with this configuration? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Step 1/7: Authenticating..."
# Check if already authenticated
if ! gcloud auth print-identity-token &>/dev/null; then
    echo "  Please authenticate with gcloud..."
    gcloud auth login
fi
echo "  ✓ Authenticated"

echo ""
echo "Step 2/7: Creating Log Bucket..."
if gcloud logging buckets describe $BUCKET_NAME --project=$CENTRAL_PROJECT --location=global &>/dev/null 2>&1; then
    echo "  ✓ Bucket already exists"
else
    gcloud logging buckets create $BUCKET_NAME \
        --project=$CENTRAL_PROJECT \
        --location=global \
        --retention-days=30 \
        --description="Central bucket for org-wide security logs"
    echo "  ✓ Bucket created"
fi

echo ""
echo "Step 3/7: Creating Aggregated Sink..."
if gcloud logging sinks describe security-hardener-org-sink --organization=$ORG_ID &>/dev/null 2>&1; then
    echo "  ✓ Sink already exists"
else
    gcloud logging sinks create security-hardener-org-sink \
        logging.googleapis.com/projects/$CENTRAL_PROJECT/locations/global/buckets/$BUCKET_NAME \
        --organization=$ORG_ID \
        --include-children \
        --log-filter='logName:"cloudaudit.googleapis.com/activity" AND (protoPayload.methodName="google.api.serviceusage.v1.ServiceUsage.EnableService" OR protoPayload.methodName:"SetOrgPolicy" OR protoPayload.serviceName="billingbudgets.googleapis.com" OR resource.type="gce_firewall_rule" OR protoPayload.methodName="CreateProject")'
    echo "  ✓ Sink created"
fi

echo ""
echo "Step 4/7: Granting IAM to Sink Writer..."
WRITER_IDENTITY=$(gcloud logging sinks describe security-hardener-org-sink \
    --organization=$ORG_ID \
    --format='value(writerIdentity)')
echo "  Writer Identity: $WRITER_IDENTITY"

gcloud projects add-iam-policy-binding $CENTRAL_PROJECT \
    --member=$WRITER_IDENTITY \
    --role=roles/logging.bucketWriter \
    --condition=None \
    --quiet
echo "  ✓ IAM permission granted"

echo ""
echo "Step 5/7: Creating Log-Based Metric..."
if gcloud logging metrics describe api_enablement_metric --project=$CENTRAL_PROJECT &>/dev/null 2>&1; then
    echo "  ✓ Metric already exists"
else
    gcloud logging metrics create api_enablement_metric \
        --project=$CENTRAL_PROJECT \
        --description="Counts API enablement events across the organization" \
        --log-filter='resource.type="audited_resource" AND protoPayload.serviceName="serviceusage.googleapis.com" AND protoPayload.methodName=~"google.api.serviceusage.v1.*.EnableService"'
    echo "  ✓ Metric created"
fi

echo ""
echo "Step 6/7: Creating Notification Channel..."
# Check if channel exists
EXISTING_CHANNEL=$(gcloud alpha monitoring channels list \
    --project=$CENTRAL_PROJECT \
    --filter="displayName='Security Alerts'" \
    --format='value(name)' 2>/dev/null || echo "")

if [ -n "$EXISTING_CHANNEL" ]; then
    echo "  ✓ Notification channel already exists"
    CHANNEL_ID=$EXISTING_CHANNEL
else
    # Create channel config
    cat > /tmp/channel.json << EOF
{
  "type": "email",
  "displayName": "Security Alerts",
  "labels": {
    "email_address": "$ALERT_EMAIL"
  }
}
EOF
    
    gcloud alpha monitoring channels create \
        --project=$CENTRAL_PROJECT \
        --channel-content-from-file=/tmp/channel.json
    
    CHANNEL_ID=$(gcloud alpha monitoring channels list \
        --project=$CENTRAL_PROJECT \
        --filter="displayName='Security Alerts'" \
        --format='value(name)')
    echo "  ✓ Notification channel created"
fi

echo ""
echo "Step 7/7: Creating Alert Policy..."
# Check if policy exists
EXISTING_POLICY=$(gcloud alpha monitoring policies list \
    --project=$CENTRAL_PROJECT \
    --filter="displayName='API Enablement Alert'" \
    --format='value(name)' 2>/dev/null || echo "")

if [ -n "$EXISTING_POLICY" ]; then
    echo "  ✓ Alert policy already exists"
else
    # Create policy config
    cat > /tmp/policy.json << EOF
{
  "displayName": "API Enablement Alert",
  "combiner": "OR",
  "conditions": [{
    "displayName": "API Enablement Condition",
    "conditionThreshold": {
      "filter": "metric.type=\"logging.googleapis.com/user/api_enablement_metric\" resource.type=\"audited_resource\"",
      "aggregations": [{
        "alignmentPeriod": "60s",
        "perSeriesAligner": "ALIGN_SUM"
      }],
      "comparison": "COMPARISON_GT",
      "duration": "0s",
      "thresholdValue": 0,
      "trigger": {"count": 1}
    }
  }],
  "notificationChannels": ["$CHANNEL_ID"],
  "documentation": {"content": "An API was enabled in a project within the organization."},
  "enabled": true
}
EOF
    
    gcloud alpha monitoring policies create \
        --project=$CENTRAL_PROJECT \
        --policy-from-file=/tmp/policy.json
    echo "  ✓ Alert policy created"
fi

echo ""
echo "=============================================="
echo "✅ SETUP COMPLETE!"
echo "=============================================="
echo ""
echo "Resources created:"
echo "  • Log Bucket: $BUCKET_NAME"
echo "  • Aggregated Sink: security-hardener-org-sink"
echo "  • Log-Based Metric: api_enablement_metric"
echo "  • Notification Channel: Security Alerts ($ALERT_EMAIL)"
echo "  • Alert Policy: API Enablement Alert"
echo ""
echo "To test, run:"
echo "  gcloud services enable translate.googleapis.com --project=$CENTRAL_PROJECT"
echo ""
echo "Then wait 5-10 minutes and check your email for the alert."
echo ""
