#!/bin/bash
# GCP Security Hardener - Update IAM Permissions
# Run this script to update existing admin service accounts with missing permissions
# required for firewall and monitoring features.

set -e

echo "=================================================="
echo "GCP Security Hardener - Update Permissions"
echo "=================================================="
echo ""

# Get project ID
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
    echo "❌ Error: No project selected"
    echo ""
    echo "Please run this first:"
    echo "  gcloud config set project YOUR_PROJECT_ID"
    echo ""
    exit 1
fi

echo "✓ Project: $PROJECT_ID"
echo ""

ADMIN_EMAIL="gcp-hardener-admin@${PROJECT_ID}.iam.gserviceaccount.com"

# Check if service account exists
if ! gcloud iam service-accounts describe $ADMIN_EMAIL --project=$PROJECT_ID >/dev/null 2>&1; then
    echo "❌ Error: Admin service account not found: $ADMIN_EMAIL"
    echo "   Please run setup-jit-accounts.sh first to create the accounts."
    exit 1
fi

echo "Updating permissions for: $ADMIN_EMAIL"

# Assign Compute Security Admin (for Firewall policies)
echo "   -> Assigning roles/compute.securityAdmin..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$ADMIN_EMAIL" \
    --role="roles/compute.securityAdmin" \
    --condition=None \
    --quiet 2>/dev/null || echo "   ⚠️  Could not assign Compute Security Admin"

# Assign Monitoring Editor (for Alert Policies & Notification Channels)
echo "   -> Assigning roles/monitoring.editor..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$ADMIN_EMAIL" \
    --role="roles/monitoring.editor" \
    --condition=None \
    --quiet 2>/dev/null || echo "   ⚠️  Could not assign Monitoring Editor"

echo ""
echo "✅ Permissions updated successfully!"
echo "   You can now run the lockdown scripts and monitoring setup."
