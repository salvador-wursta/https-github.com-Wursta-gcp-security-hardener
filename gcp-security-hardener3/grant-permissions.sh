#!/bin/bash

# Script to grant yourself project-level permissions
# Usage: ./grant-permissions.sh YOUR_EMAIL@domain.com PROJECT_ID

EMAIL=$1
PROJECT_ID=$2

if [ -z "$EMAIL" ] || [ -z "$PROJECT_ID" ]; then
    echo "Usage: ./grant-permissions.sh YOUR_EMAIL@domain.com PROJECT_ID"
    echo ""
    echo "Example:"
    echo "  ./grant-permissions.sh admin@example.com servers"
    exit 1
fi

echo "Granting permissions to $EMAIL for project $PROJECT_ID..."
echo ""

# Set project
gcloud config set project $PROJECT_ID

# Grant roles
echo "Granting Service Account Admin..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="user:$EMAIL" \
  --role="roles/iam.serviceAccountAdmin"

echo "Granting Service Account Key Admin..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="user:$EMAIL" \
  --role="roles/iam.serviceAccountKeyAdmin"

echo "Granting Project IAM Admin..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="user:$EMAIL" \
  --role="roles/resourcemanager.projectIamAdmin"

echo ""
echo "✅ Permissions granted!"
echo ""
echo "Wait 10-30 seconds for permissions to propagate, then try setup again."

