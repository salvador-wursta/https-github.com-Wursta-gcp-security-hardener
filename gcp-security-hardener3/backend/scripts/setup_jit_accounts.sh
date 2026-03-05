#!/bin/bash
# GCP Security Hardener - JIT Service Account Setup
# This script creates service accounts, assigns permissions, and implicitly ENABLES REQUIRED APIS.
set -e

echo "=================================================="
echo "GCP Security Hardener - JIT Setup (Bash)"
echo "=================================================="
echo ""

# Get project ID
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
    echo "❌ Error: No project selected"
    echo "Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo "✓ Project: ${PROJECT_ID}"

# 0. Enable APIs First (Critical for permission assignment logic to work)
echo ""
echo "[1/5] Enabling required APIs..."
APIS=(
  "serviceusage.googleapis.com"
  "cloudresourcemanager.googleapis.com"
  "iam.googleapis.com"
  "cloudbilling.googleapis.com"
  "billingbudgets.googleapis.com"
  "recommender.googleapis.com"
  "orgpolicy.googleapis.com"
  "compute.googleapis.com"
  "logging.googleapis.com"
  "monitoring.googleapis.com"
  "pubsub.googleapis.com"
  "cloudasset.googleapis.com"
  "apikeys.googleapis.com"
  "securitycenter.googleapis.com"
  "ids.googleapis.com"
)

for api in "${APIS[@]}"; do
  echo "   Enabling $api..."
  # Try to enable, print warning on failure but don't exit script immediately
  gcloud services enable "$api" --project="${PROJECT_ID}" --quiet || echo "   ⚠️  Failed to enable $api"
done
echo "   ✓ API enablement attempt complete."


# 1. Create Scanner SA
echo ""
echo "[2/5] Creating Scanner account..."
if ! gcloud iam service-accounts describe gcp-hardener-scanner@${PROJECT_ID}.iam.gserviceaccount.com --project=${PROJECT_ID} >/dev/null 2>&1; then
    gcloud iam service-accounts create gcp-hardener-scanner --display-name="GCP Hardener Scanner" --project=${PROJECT_ID} --quiet
fi
SCANNER_EMAIL="gcp-hardener-scanner@${PROJECT_ID}.iam.gserviceaccount.com"
echo "   ✓ Scanner: ${SCANNER_EMAIL}"

# 2. Create Admin SA
echo ""
echo "[3/5] Creating Admin account..."
if ! gcloud iam service-accounts describe gcp-hardener-admin@${PROJECT_ID}.iam.gserviceaccount.com --project=${PROJECT_ID} >/dev/null 2>&1; then
    gcloud iam service-accounts create gcp-hardener-admin --display-name="GCP Hardener Admin" --project=${PROJECT_ID} --quiet
fi
ADMIN_EMAIL="gcp-hardener-admin@${PROJECT_ID}.iam.gserviceaccount.com"
echo "   ✓ Admin: ${ADMIN_EMAIL}"


# 3. Grant Permissions
echo ""
echo "[4/5] Granting permissions..."
# Scanner Roles
SCANNER_ROLES=(
  "roles/viewer"
  "roles/iam.securityReviewer"
  "roles/billing.viewer"
  "roles/cloudasset.viewer"
  "roles/serviceusage.serviceUsageConsumer"
  "roles/serviceusage.apiKeysViewer"
  "roles/securitycenter.findingsViewer"
  "roles/browser"
)

for role in "${SCANNER_ROLES[@]}"; do
  gcloud projects add-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SCANNER_EMAIL}" --role="$role" --quiet >/dev/null
done
echo "   ✓ Scanner permissions assigned"

# Admin Roles
ADMIN_ROLES=(
  "roles/editor"
  "roles/iam.securityAdmin"
  "roles/serviceusage.serviceUsageAdmin"
  "roles/serviceusage.apiKeysAdmin"
  "roles/logging.configWriter"
  "roles/monitoring.admin"
  "roles/compute.securityAdmin"
  "roles/cloudasset.owner"
)

for role in "${ADMIN_ROLES[@]}"; do
  gcloud projects add-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${ADMIN_EMAIL}" --role="$role" --quiet >/dev/null
done
echo "   ✓ Admin permissions assigned"

# 4. Create Keys
echo ""
echo "[5/5] Generating keys..."
rm -f scanner-key.json admin-key.json
gcloud iam service-accounts keys create scanner-key.json --iam-account=${SCANNER_EMAIL} --project=${PROJECT_ID} --quiet
gcloud iam service-accounts keys create admin-key.json --iam-account=${ADMIN_EMAIL} --project=${PROJECT_ID} --quiet

echo ""
echo "✅ Setup Complete!"
echo "Files generated:"
echo " - scanner-key.json"
echo " - admin-key.json"
echo "You can verify enabled services with: gcloud services list --enabled --project=${PROJECT_ID}"
