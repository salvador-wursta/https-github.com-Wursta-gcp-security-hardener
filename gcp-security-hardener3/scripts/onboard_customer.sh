#!/bin/bash
# GCP Security Hardener - Customer Onboarding Script
# Usage: ./onboard_customer.sh [CUSTOMER_PROJECT_ID] [TOOLING_SA_EMAIL]

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 [CUSTOMER_PROJECT_ID] [TOOLING_SA_EMAIL]"
  echo "Example: $0 my-customer-project-123 app-identity@my-tooling-project.iam.gserviceaccount.com"
  exit 1
fi

CUSTOMER_PROJECT=$1
TOOLING_SA=$2

echo "--------------------------------------------------------"
echo "Onboarding Customer Project: $CUSTOMER_PROJECT"
echo "Granting access to: $TOOLING_SA"
echo "--------------------------------------------------------"

# 1. Grant Security Reviewer (for CAI and IAM scans)
echo "Granting roles/iam.securityReviewer..."
gcloud projects add-iam-policy-binding $CUSTOMER_PROJECT \
  --member="serviceAccount:$TOOLING_SA" \
  --role="roles/iam.securityReviewer" \
  --condition=None

# 2. Grant Service Usage Consumer (for API enablement checks)
echo "Granting roles/serviceusage.serviceUsageConsumer..."
gcloud projects add-iam-policy-binding $CUSTOMER_PROJECT \
  --member="serviceAccount:$TOOLING_SA" \
  --role="roles/serviceusage.serviceUsageConsumer" \
  --condition=None

echo "--------------------------------------------------------"
echo "Onboarding Complete!"
echo "The SaaS application can now scan $CUSTOMER_PROJECT."
echo "--------------------------------------------------------"
