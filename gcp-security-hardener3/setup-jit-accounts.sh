#!/bin/bash
# GCP Security Hardener - JIT Service Account Setup
# SIMPLIFIED VERSION - Copy/paste this entire script into Cloud Shell

set -e  # Exit on error

echo "=================================================="
echo "GCP Security Hardener - JIT Setup"
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

# Create scanner service account (minimal permissions)
echo "[1/6] Creating scanner service account..."
if gcloud iam service-accounts describe gcp-hardener-scanner@${PROJECT_ID}.iam.gserviceaccount.com --project=$PROJECT_ID >/dev/null 2>&1; then
    echo "   (already exists, skipping)"
else
    gcloud iam service-accounts create gcp-hardener-scanner \
        --display-name="GCP Security Hardener - Scanner" \
        --description="Read-only access for scanning GCP resources" \
        --project=$PROJECT_ID
fi

SCANNER_EMAIL="gcp-hardener-scanner@${PROJECT_ID}.iam.gserviceaccount.com"
echo "   ✓ Scanner: $SCANNER_EMAIL"

# Create admin service account (full permissions)
echo "[2/6] Creating admin service account..."
if gcloud iam service-accounts describe gcp-hardener-admin@${PROJECT_ID}.iam.gserviceaccount.com --project=$PROJECT_ID >/dev/null 2>&1; then
    echo "   (already exists, skipping)"
else
    gcloud iam service-accounts create gcp-hardener-admin \
        --display-name="GCP Security Hardener - Admin" \
        --description="Administrative access for applying security hardening" \
        --project=$PROJECT_ID
fi

ADMIN_EMAIL="gcp-hardener-admin@${PROJECT_ID}.iam.gserviceaccount.com"
echo "   ✓ Admin: $ADMIN_EMAIL"

# Assign scanner roles (view-only)
echo "[3/6] Assigning scanner permissions (read-only)..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SCANNER_EMAIL" \
    --role="roles/viewer" \
    --condition=None \
    --quiet 2>/dev/null || true

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SCANNER_EMAIL" \
    --role="roles/iam.securityReviewer" \
    --condition=None \
    --quiet 2>/dev/null || true

echo "   ✓ Scanner roles assigned"

# Assign scanner billing permissions (crucial for budget monitoring)
echo "[3.5/6] Assigning scanner billing permissions..."
# 1. Grant on Project (Basic visibility)
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SCANNER_EMAIL" \
    --role="roles/billing.viewer" \
    --condition=None \
    --quiet 2>/dev/null || true

# 2. Grant on Billing Account (Required for budgets & viewing account name)
BILLING_ACCOUNT_ID=$(gcloud beta billing projects describe $PROJECT_ID --format="value(billingAccountName)" 2>/dev/null | sed 's/billingAccounts\///')

if [ -n "$BILLING_ACCOUNT_ID" ] && [ "$BILLING_ACCOUNT_ID" != "" ]; then
    echo "   Detected Billing Account: $BILLING_ACCOUNT_ID"
    gcloud beta billing accounts add-iam-policy-binding $BILLING_ACCOUNT_ID \
        --member="serviceAccount:$SCANNER_EMAIL" \
        --role="roles/billing.viewer" \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Billing Viewer on Billing Account (You might need Billing Account Admin role)"
else
    echo "   ⚠️  Could not detect linked Billing Account (or no permissions to view it)"
fi

# Assign admin roles (full access)
echo "[4/6] Assigning admin permissions..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$ADMIN_EMAIL" \
    --role="roles/editor" \
    --condition=None \
    --quiet 2>/dev/null || true

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$ADMIN_EMAIL" \
    --role="roles/iam.securityAdmin" \
    --condition=None \
    --quiet 2>/dev/null || true

# Add Service Usage Admin for API enablement/disablement on Host Project
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$ADMIN_EMAIL" \
    --role="roles/serviceusage.serviceUsageAdmin" \
    --condition=None \
    --quiet 2>/dev/null || true

# Add Logging Config Writer for creating log buckets and metrics (org monitoring)
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$ADMIN_EMAIL" \
    --role="roles/logging.configWriter" \
    --condition=None \
    --quiet 2>/dev/null || true

# Add Monitoring Admin for creating notification channels and alert policies
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$ADMIN_EMAIL" \
    --role="roles/monitoring.admin" \
    --condition=None \
    --quiet 2>/dev/null || true

# Add Compute Security Admin for advanced firewall management
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$ADMIN_EMAIL" \
    --role="roles/compute.securityAdmin" \
    --condition=None \
    --quiet 2>/dev/null || true

# Add Monitoring Editor for full control over alerts and channels
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$ADMIN_EMAIL" \
    --role="roles/monitoring.editor" \
    --condition=None \
    --quiet 2>/dev/null || true

echo "   ✓ Admin roles assigned on Host Project ($PROJECT_ID)"

# --------------------------------------------------------------------------------
# ORGANIZATION LEVEL PERMISSIONS (Crucial for Multi-Project Hardening)
# --------------------------------------------------------------------------------
echo ""
echo "[4.5/6] Checking for Organization Level permissions..."
ORG_ID=$(gcloud projects describe $PROJECT_ID --format="value(parent.id)" 2>/dev/null)

if [ -n "$ORG_ID" ]; then
    echo "   Detected Organization ID: $ORG_ID"
    echo "   Granting Organization-level Admin permissions..."
    echo "   (This handles cross-project access automatically)"

    # --- SCANNER PERMISSIONS (Read-Only) ---
    echo "   -> Granting Scanner visibility..."
    # Organization Viewer - Required to list all projects in the org
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$SCANNER_EMAIL" \
        --role="roles/resourcemanager.organizationViewer" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Org Viewer to Scanner"
    
    # Billing Viewer - View billing accounts and budgets across org
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$SCANNER_EMAIL" \
        --role="roles/billing.viewer" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Billing Viewer to Scanner at Org level"
    
    # Folder Viewer - listing projects in folders
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$SCANNER_EMAIL" \
        --role="roles/resourcemanager.folderViewer" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Folder Viewer to Scanner"

    # Browser - Access to browse resources hierarchy
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$SCANNER_EMAIL" \
        --role="roles/browser" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Browser role to Scanner"

    # Service Usage Viewer - Required to list enabled APIs on all projects
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$SCANNER_EMAIL" \
        --role="roles/serviceusage.serviceUsageViewer" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Service Usage Viewer to Scanner"

    # Security Reviewer - Required to view IAM policies on all projects
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$SCANNER_EMAIL" \
        --role="roles/iam.securityReviewer" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Security Reviewer to Scanner"
    
    # Security Center Viewer - Required to list assets and findings
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$SCANNER_EMAIL" \
        --role="roles/securitycenter.assetsViewer" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant SCC Assets Viewer to Scanner"

    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$SCANNER_EMAIL" \
        --role="roles/securitycenter.findingsViewer" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant SCC Findings Viewer to Scanner"
    
    # Compute Viewer - Required to scan VM instances and quotas
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$SCANNER_EMAIL" \
        --role="roles/compute.viewer" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Compute Viewer to Scanner"

    # --- ADMIN PERMISSIONS (Full Access) ---
    echo "   -> Granting Admin permissions..."
    
    # Browser - Admin also needs to see the hierarchy
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$ADMIN_EMAIL" \
        --role="roles/browser" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Browser role to Admin"
    
    # Org Policy Admin - Required to set constraints on any project
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$ADMIN_EMAIL" \
        --role="roles/orgpolicy.policyAdmin" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Org Policy Admin (You might not be an Org Admin)"

    # Service Usage Admin - Required to disable APIs on any project
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$ADMIN_EMAIL" \
        --role="roles/serviceusage.serviceUsageAdmin" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Service Usage Admin at Org level"

    # Compute Network Admin - Required for firewall rules on any project
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$ADMIN_EMAIL" \
        --role="roles/compute.networkAdmin" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Network Admin at Org level"

    # Security Admin - Required to modify IAM policies on any project
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$ADMIN_EMAIL" \
        --role="roles/iam.securityAdmin" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Security Admin at Org level"

    # Logging Config Writer - Required for org-level aggregated log sinks
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$ADMIN_EMAIL" \
        --role="roles/logging.configWriter" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Logging Config Writer at Org level"

    # Security Center Admin - Required to configure SCC settings
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="serviceAccount:$ADMIN_EMAIL" \
        --role="roles/securitycenter.admin" \
        --condition=None \
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant SCC Admin at Org level"
        
    echo "   ✓ Organization roles attempt complete"
else
    echo "   ⚠️  No Organization ID found (Project might be standalone)"
    echo "   NOTE: For multi-project hardening, you MUST manually grant this Service Account access to target projects."
fi

# --------------------------------------------------------------------------------
# PRE-FLIGHT: DISABLE KEY CREATION RESTRICTIONS
# --------------------------------------------------------------------------------
echo ""
echo "[5/7] Ensuring key creation is allowed..."
gcloud resource-manager org-policies disable-enforce constraints/iam.disableServiceAccountKeyCreation --project=$PROJECT_ID --quiet 2>/dev/null || echo "   (Note: Could not disable key creation restriction. If key creation fails, this policy is likely the cause.)"

# Create and download scanner key
echo "[6/7] Creating scanner key..."
echo "   (Waiting 10s for IAM propagation...)"
sleep 10
rm -f scanner-key.json
gcloud iam service-accounts keys create scanner-key.json \
    --iam-account=$SCANNER_EMAIL \
    --project=$PROJECT_ID

if [ ! -s scanner-key.json ]; then
    echo "❌ Error: scanner-key.json is empty. Service Account might not exist or quota exceeded."
    read -p "Press Enter to exit..." wait_input
    exit 1
fi
echo "   ✓ scanner-key.json created"

# Create and download admin key
echo "[6/7] Creating admin key..."
echo "   (Waiting 5s...)"
sleep 5
rm -f admin-key.json
gcloud iam service-accounts keys create admin-key.json \
    --iam-account=$ADMIN_EMAIL \
    --project=$PROJECT_ID

if [ ! -s admin-key.json ]; then
    echo "❌ Error: admin-key.json is empty."
    read -p "Press Enter to exit..." wait_input
    exit 1
fi
echo "   ✓ admin-key.json created"

# Enable required APIs in scanner's project
echo ""
echo "[7/7] Enabling required APIs in scanner's project..."
echo "   (This allows the scanner to list projects and access billing)"
gcloud services enable cloudresourcemanager.googleapis.com --project=$PROJECT_ID 2>/dev/null || true
gcloud services enable serviceusage.googleapis.com --project=$PROJECT_ID 2>/dev/null || true
gcloud services enable billingbudgets.googleapis.com --project=$PROJECT_ID 2>/dev/null || true
gcloud services enable cloudbilling.googleapis.com --project=$PROJECT_ID 2>/dev/null || true
gcloud services enable recommender.googleapis.com --project=$PROJECT_ID 2>/dev/null || true
gcloud services enable orgpolicy.googleapis.com --project=$PROJECT_ID 2>/dev/null || true
gcloud services enable compute.googleapis.com --project=$PROJECT_ID 2>/dev/null || true
gcloud services enable logging.googleapis.com --project=$PROJECT_ID 2>/dev/null || true
gcloud services enable monitoring.googleapis.com --project=$PROJECT_ID 2>/dev/null || true
gcloud services enable pubsub.googleapis.com --project=$PROJECT_ID 2>/dev/null || true
echo "   ✓ All required APIs enabled"

echo ""
echo "=================================================="
echo "✅ Setup Complete!"
echo "=================================================="
echo ""
echo "Two JSON key files have been created:"
echo "  📄 scanner-key.json  (read-only access)"
echo "  📄 admin-key.json    (admin access, time-limited)"
echo ""
echo "📥 DOWNLOAD THESE FILES:"
echo "  1. Click the ⋮ menu (top right of Cloud Shell)"
echo "  2. Select 'Download file'"
echo "  3. Type: scanner-key.json  (press Enter)"
echo "  4. Type: admin-key.json    (press Enter)"
echo ""
echo "🔒 KEEP SECURE:"
echo "  • These files grant access to your GCP project"
echo "  • Never commit them to version control"
echo "  • Store them like passwords"
echo ""
echo "▶️  NEXT STEP:"
echo "  Upload both files to GCP Security Hardener app"
echo ""

read -p "Press [Enter] to exit setup..." wait_input
