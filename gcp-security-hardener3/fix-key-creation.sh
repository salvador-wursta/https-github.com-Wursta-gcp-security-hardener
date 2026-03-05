#!/bin/bash
# Script to re-enable Service Account Key Creation
# Use this if you get "Policy prevented this request" when creating keys

set -e

PROJECT_ID=$(gcloud config get-value project 2>/dev/null)

if [ -z "$PROJECT_ID" ]; then
    echo "❌ Error: No project selected"
    echo "Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo "Project: $PROJECT_ID"
echo "------------------------------------------------"
echo "Attempting to disable 'iam.disableServiceAccountKeyCreation' constraint..."
echo "------------------------------------------------"

# Try to disable enforcement at the project level
gcloud resource-manager org-policies disable-enforce constraints/iam.disableServiceAccountKeyCreation --project=$PROJECT_ID && echo "✅ Successfully disabled key creation restriction." || echo "⚠️  Failed to disable restriction. You might need Org Admin permissions or to check Organization-level policies."

echo ""
echo "Attempting to disable 'iam.disableServiceAccountKeyUpload' constraint (just in case)..."
gcloud resource-manager org-policies disable-enforce constraints/iam.disableServiceAccountKeyUpload --project=$PROJECT_ID 2>/dev/null || true

echo ""
echo "------------------------------------------------"
echo "Done. You can now try creating keys again."
echo "------------------------------------------------"
