#!/bin/bash
# Fix scanner permissions to see all organization projects

echo "🔍 Fixing scanner service account permissions..."
echo ""

# Get current project
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
  echo "❌ No project selected. Run: gcloud config set project YOUR_PROJECT_ID"
  exit 1
fi

echo "Current project: $PROJECT_ID"
echo ""

# Get organization ID
echo "Finding organization..."
ORG_ID=$(gcloud projects describe $PROJECT_ID --format="value(parent.id)" 2>/dev/null)

if [ -z "$ORG_ID" ]; then
  echo "❌ No organization found for this project."
  echo "This project may not be part of an organization."
  echo ""
  echo "To see all projects, you need to:"
  echo "1. Have an organization"
  echo "2. Grant the scanner account access to each project individually, OR"
  echo "3. Grant organization-level permissions"
  exit 1
fi

echo "✓ Found organization: $ORG_ID"
echo ""

# Grant organization viewer permission
echo "Granting organization-level viewer permission to scanner..."
gcloud organizations add-iam-policy-binding $ORG_ID \
  --member="serviceAccount:gcp-hardener-scanner@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/resourcemanager.organizationViewer"

if [ $? -eq 0 ]; then
  echo ""
  echo "✅ Success! Scanner can now see all organization projects."
  echo ""
  echo "Next steps:"
  echo "1. Refresh your browser"
  echo "2. Upload scanner-key.json and admin-key.json again"
  echo "3. You should now see all projects in the organization"
else
  echo ""
  echo "❌ Failed to grant permissions."
  echo ""
  echo "This usually means you don't have Organization Admin role."
  echo ""
  echo "Ask your organization administrator to run:"
  echo ""
  echo "gcloud organizations add-iam-policy-binding $ORG_ID \\"
  echo "  --member=\"serviceAccount:gcp-hardener-scanner@${PROJECT_ID}.iam.gserviceaccount.com\" \\"
  echo "  --role=\"roles/resourcemanager.organizationViewer\""
fi
