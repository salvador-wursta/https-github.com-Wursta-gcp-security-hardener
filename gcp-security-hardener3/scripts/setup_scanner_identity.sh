#!/bin/bash
# Run this ONCE to set up your local development identity.

PROJECT_ID=$(gcloud config get-value project)
USER_EMAIL=$(gcloud config get-value account)
SA_NAME="scanner-core"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "🔧 Setting up Dev Identity: ${SA_EMAIL}"

# 1. Create SA if not exists
if ! gcloud iam service-accounts describe ${SA_EMAIL} --project=${PROJECT_ID} >/dev/null 2>&1; then
    gcloud iam service-accounts create ${SA_NAME} --display-name="Core Scanner Identity"
fi

# 2. Grant YOU permission to impersonate it (Crucial for local dev)
gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} \
    --member="user:${USER_EMAIL}" \
    --role="roles/iam.serviceAccountTokenCreator" \
    --condition=None

# 3. Grant SA permissions to run the app (Vertex AI, etc)
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/aiplatform.user"
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/datastore.user"

echo ""
echo "✅ Setup Complete. To run the app as this user:"
echo "export GOOGLE_IMPERSONATE_SERVICE_ACCOUNT=${SA_EMAIL}"
echo "uvicorn app.main:app --reload"
