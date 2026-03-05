#!/bin/bash
# Enable required APIs for GCP Security Hardener

PROJECT_ID="gcp-lockdown-test-proj"

echo "================================================================"
echo "Enabling Required APIs for GCP Security Hardener"
echo "================================================================"
echo ""
echo "Target Project: $PROJECT_ID"
echo ""

# APIs to enable
APIS=(
    "orgpolicy.googleapis.com"
    "cloudresourcemanager.googleapis.com"
    "billingbudgets.googleapis.com"
    "compute.googleapis.com"
    "serviceusage.googleapis.com"
    "logging.googleapis.com"
    "pubsub.googleapis.com"
)

echo "Enabling ${#APIS[@]} APIs..."
echo ""

for API in "${APIS[@]}"; do
    echo "Enabling $API..."
    gcloud services enable "$API" --project="$PROJECT_ID"
    
    if [ $? -eq 0 ]; then
        echo "  ✓ $API enabled"
    else
        echo "  ✗ Failed to enable $API"
    fi
    echo ""
done

echo "================================================================"
echo "API Enablement Complete!"
echo "================================================================"
echo ""
echo "Next steps:"
echo "1. Wait 1-2 minutes for APIs to fully activate"
echo "2. Re-run diagnostic: ./run_diagnostic.sh --project $PROJECT_ID --credentials PATH"
echo "3. Test lockdown functionality"
