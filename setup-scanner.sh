#!/bin/bash
PROJECT_ID="sam-quota-project"
ORG_ID="407092023846"
SA_NAME="gcp-scanner-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "Creating dedicated scanning service account..."
gcloud iam service-accounts create $SA_NAME --display-name="GCP Security Scanner" --project=$PROJECT_ID

echo "Binding Read-Only Organization Roles..."
gcloud organizations add-iam-policy-binding $ORG_ID --member="serviceAccount:$SA_EMAIL" --role="roles/browser"
gcloud organizations add-iam-policy-binding $ORG_ID --member="serviceAccount:$SA_EMAIL" --role="roles/iam.securityReviewer"
gcloud organizations add-iam-policy-binding $ORG_ID --member="serviceAccount:$SA_EMAIL" --role="roles/billing.viewer"
gcloud organizations add-iam-policy-binding $ORG_ID --member="serviceAccount:$SA_EMAIL" --role="roles/securitycenter.adminViewer"

echo "Setup complete. Authenticating locally to use this service account:"
gcloud auth application-default login --impersonate-service-account=$SA_EMAIL
