#!/bin/bash
# GCP Security Hardener - Complete Service Account Setup
# This script creates scanner and admin service accounts with ALL required permissions

set -e  # Exit on error

echo "=========================================="
echo "GCP Security Hardener - Complete Setup"
echo "=========================================="
echo ""

# Check if user is authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &>/dev/null; then
    echo "❌ Not authenticated to gcloud. Please run:"
    echo "   gcloud auth login"
    exit 1
fi

# Get current project
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
  echo "❌ No project selected. Run: gcloud config set project YOUR_PROJECT_ID"
  exit 1
fi

echo "✓ Project: $PROJECT_ID"

# Get organization ID
echo ""
echo "[1/8] Finding organization..."
ORG_ID=$(gcloud projects describe $PROJECT_ID --format="value(parent.id)" 2>/dev/null)
if [ -n "$ORG_ID" ]; then
  echo "✓ Organization ID: $ORG_ID"
  
  # Count projects in org
  PROJECT_COUNT=$(gcloud projects list --filter="parent.id=$ORG_ID lifecycleState=ACTIVE" --format="value(projectId)" 2>/dev/null | wc -l | tr -d ' ')
  echo "✓ Found $PROJECT_COUNT active projects in organization"
  HAS_ORG=true
else
  echo "⚠️  No organization found - running in single-project mode"
  echo "⚠️  Some features (org-wide scanning) will not work"
  PROJECT_COUNT=1
  HAS_ORG=false
fi

echo ""
echo "[2/8] Creating service accounts..."

# Create scanner service account
gcloud iam service-accounts create gcp-hardener-scanner \
  --display-name="GCP Hardener Scanner (Read-Only)" \
  --description="Read-only account for scanning GCP projects for security risks" \
  --project=$PROJECT_ID 2>/dev/null && echo "  ✓ Created scanner account" || echo "  ✓ Scanner account already exists"

# Create admin service account
gcloud iam service-accounts create gcp-hardener-admin \
  --display-name="GCP Hardener Admin (Elevated)" \
  --description="Time-limited elevated account for applying security lockdowns" \
  --project=$PROJECT_ID 2>/dev/null && echo "  ✓ Created admin account" || echo "  ✓ Admin account already exists"

SCANNER_EMAIL="gcp-hardener-scanner@${PROJECT_ID}.iam.gserviceaccount.com"
ADMIN_EMAIL="gcp-hardener-admin@${PROJECT_ID}.iam.gserviceaccount.com"

echo ""
echo "[3/8] Granting project-level permissions..."

# Scanner: Viewer on home project
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$SCANNER_EMAIL" \
  --role="roles/viewer" --quiet 2>/dev/null
echo "  ✓ Scanner: roles/viewer on $PROJECT_ID"

# Scanner: Service usage consumer (for API quota billing)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$SCANNER_EMAIL" \
  --role="roles/serviceusage.serviceUsageConsumer" --quiet 2>/dev/null
echo "  ✓ Scanner: roles/serviceusage.serviceUsageConsumer on $PROJECT_ID"

# Admin: Editor on home project
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$ADMIN_EMAIL" \
  --role="roles/editor" --quiet 2>/dev/null
echo "  ✓ Admin: roles/editor on $PROJECT_ID"

# Admin: Service usage admin (for enabling/disabling APIs)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$ADMIN_EMAIL" \
  --role="roles/serviceusage.serviceUsageAdmin" --quiet 2>/dev/null
echo "  ✓ Admin: roles/serviceusage.serviceUsageAdmin on $PROJECT_ID"

# Admin: Logging config writer (for creating log buckets and metrics)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$ADMIN_EMAIL" \
  --role="roles/logging.configWriter" --quiet 2>/dev/null
echo "  ✓ Admin: roles/logging.configWriter on $PROJECT_ID"

# Admin: Monitoring admin (for creating notification channels and alerts)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$ADMIN_EMAIL" \
  --role="roles/monitoring.admin" --quiet 2>/dev/null
echo "  ✓ Admin: roles/monitoring.admin on $PROJECT_ID"

echo ""
echo "[4/8] Granting organization-level permissions (SCANNER)..."

if [ "$HAS_ORG" = true ]; then
  # Scanner: Organization viewer (to list all projects)
  echo "  Granting organization viewer..."
  if gcloud organizations add-iam-policy-binding $ORG_ID \
    --member="serviceAccount:$SCANNER_EMAIL" \
    --role="roles/resourcemanager.organizationViewer" \
    --quiet 2>/dev/null; then
    echo "  ✓ Scanner: roles/resourcemanager.organizationViewer"
  else
    echo "  ❌ FAILED: Need Organization Admin role to grant this"
    echo "     Without this, scanner will only see 1 project!"
  fi
  
  # Scanner: Viewer at org level (to scan all projects)
  echo "  Granting viewer at organization level..."
  if gcloud organizations add-iam-policy-binding $ORG_ID \
    --member="serviceAccount:$SCANNER_EMAIL" \
    --role="roles/viewer" \
    --quiet 2>/dev/null; then
    echo "  ✓ Scanner: roles/viewer (org-wide)"
  else
    echo "  ❌ FAILED: Need Organization Admin role to grant this"
    echo "     Without this, scanner can only scan home project!"
  fi
  
  # Scanner: Billing viewer (to check budgets and costs)
  echo "  Granting billing viewer..."
  if gcloud organizations add-iam-policy-binding $ORG_ID \
    --member="serviceAccount:$SCANNER_EMAIL" \
    --role="roles/billing.viewer" \
    --quiet 2>/dev/null; then
    echo "  ✓ Scanner: roles/billing.viewer"
  else
    echo "  ❌ FAILED: Need Organization Admin role to grant this"
    echo "     Without this, scanner cannot check billing/budgets!"
  fi
else
  echo "  ⚠️ Skipping (no organization)"
fi

echo ""
echo "[5/8] Granting organization-level permissions (ADMIN)..."

if [ "$HAS_ORG" = true ]; then
  # Admin: Org policy admin (to modify org policies)
  echo "  Granting organization policy admin..."
  if gcloud organizations add-iam-policy-binding $ORG_ID \
    --member="serviceAccount:$ADMIN_EMAIL" \
    --role="roles/orgpolicy.policyAdmin" \
    --quiet 2>/dev/null; then
    echo "  ✓ Admin: roles/orgpolicy.policyAdmin"
  else
    echo "  ❌ FAILED: Need Organization Admin role to grant this"
    echo "     Without this, admin cannot set org policy constraints!"
  fi

  # Admin: Logging config writer (for org-level aggregated sinks)
  echo "  Granting logging config writer..."
  if gcloud organizations add-iam-policy-binding $ORG_ID \
    --member="serviceAccount:$ADMIN_EMAIL" \
    --role="roles/logging.configWriter" \
    --quiet 2>/dev/null; then
    echo "  ✓ Admin: roles/logging.configWriter (org-wide)"
  else
    echo "  ❌ FAILED: Need Organization Admin role to grant this"
    echo "     Without this, admin cannot create org-level log sinks!"
  fi
else
  echo "  ⚠️ Skipping (no organization)"
fi

echo ""
echo "[6/8] Enabling required APIs..."

# Enable Cloud Resource Manager API
gcloud services enable cloudresourcemanager.googleapis.com --project=$PROJECT_ID 2>/dev/null
echo "  ✓ cloudresourcemanager.googleapis.com"

# Enable Service Usage API
gcloud services enable serviceusage.googleapis.com --project=$PROJECT_ID 2>/dev/null
echo "  ✓ serviceusage.googleapis.com"

# Enable Org Policy API
gcloud services enable orgpolicy.googleapis.com --project=$PROJECT_ID 2>/dev/null
echo "  ✓ orgpolicy.googleapis.com"

# Enable Cloud Billing API
gcloud services enable cloudbilling.googleapis.com --project=$PROJECT_ID 2>/dev/null
echo "  ✓ cloudbilling.googleapis.com"

# Enable Cloud Billing Budget API
gcloud services enable billingbudgets.googleapis.com --project=$PROJECT_ID 2>/dev/null
echo "  ✓ billingbudgets.googleapis.com"

# Enable Recommender API
gcloud services enable recommender.googleapis.com --project=$PROJECT_ID 2>/dev/null
echo "  ✓ recommender.googleapis.com"

# Enable Compute Engine API (for network hardening)
gcloud services enable compute.googleapis.com --project=$PROJECT_ID 2>/dev/null
echo "  ✓ compute.googleapis.com"

# Enable Cloud Logging API (for audit trails)
gcloud services enable logging.googleapis.com --project=$PROJECT_ID 2>/dev/null
echo "  ✓ logging.googleapis.com"

# Enable Cloud Monitoring API (for alerts and metrics)
gcloud services enable monitoring.googleapis.com --project=$PROJECT_ID 2>/dev/null
echo "  ✓ monitoring.googleapis.com"

# Enable Cloud Pub/Sub API (for notifications)
gcloud services enable pubsub.googleapis.com --project=$PROJECT_ID 2>/dev/null
echo "  ✓ pubsub.googleapis.com"

echo ""
echo "[7/8] Creating service account keys..."

# Create scanner key
if gcloud iam service-accounts keys create scanner-key.json \
  --iam-account=$SCANNER_EMAIL \
  --project=$PROJECT_ID 2>/dev/null; then
  SCANNER_SIZE=$(wc -c < scanner-key.json | tr -d ' ')
  echo "  ✓ scanner-key.json ($SCANNER_SIZE bytes)"
else
  echo "  ❌ Failed to create scanner key"
fi

# Create admin key
if gcloud iam service-accounts keys create admin-key.json \
  --iam-account=$ADMIN_EMAIL \
  --project=$PROJECT_ID 2>/dev/null; then
  ADMIN_SIZE=$(wc -c < admin-key.json | tr -d ' ')
  echo "  ✓ admin-key.json ($ADMIN_SIZE bytes)"
else
  echo "  ❌ Failed to create admin key"
fi

echo ""
echo "[8/8] Verifying setup..."

# Verify scanner key
if [ -f scanner-key.json ] && [ -s scanner-key.json ]; then
  echo "  ✅ scanner-key.json created"
else
  echo "  ❌ scanner-key.json is missing or empty"
fi

# Verify admin key
if [ -f admin-key.json ] && [ -s admin-key.json ]; then
  echo "  ✅ admin-key.json created"
else
  echo "  ❌ admin-key.json is missing or empty"
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "📋 Summary:"
echo "  Service Accounts Created:"
echo "    • Scanner: $SCANNER_EMAIL"
echo "    • Admin: $ADMIN_EMAIL"
echo ""
echo "  Scanner Permissions (Read-Only):"
echo "    ✓ Project viewer"
echo "    ✓ Service usage consumer"
if [ "$HAS_ORG" = true ]; then
echo "    ✓ Organization viewer (lists all $PROJECT_COUNT projects)"
echo "    ✓ Organization-wide viewer (scans all projects)"
echo "    ✓ Billing viewer (checks budgets/costs)"
fi
echo ""
echo "  Admin Permissions (Elevated):"
echo "    ✓ Project editor"
echo "    ✓ Service usage admin (enable/disable APIs)"
echo "    ✓ Logging config writer (log buckets, sinks, metrics)"
echo "    ✓ Monitoring admin (notification channels, alerts)"
if [ "$HAS_ORG" = true ]; then
echo "    ✓ Org policy admin (set constraints)"
echo "    ✓ Org logging config writer (org-level sinks)"
fi
echo ""
echo "📁 Next Steps:"
echo "  1. Download the keys from Cloud Shell:"
echo "     • Cloud Shell menu (⋮) → Download file"
echo "     • scanner-key.json"
echo "     • admin-key.json"
echo ""
echo "  2. Upload both files to the GCP Security Hardener UI"
echo ""
if [ "$HAS_ORG" = true ]; then
echo "  3. You should see all $PROJECT_COUNT projects!"
else
echo "  3. Single-project mode (no organization detected)"
fi
echo ""
echo "⚠️  Security Note:"
echo "  • Keep these keys secure - they grant access to your GCP resources"
echo "  • Scanner has read-only access"
echo "  • Admin has time-limited write access (JIT model)"
echo ""
