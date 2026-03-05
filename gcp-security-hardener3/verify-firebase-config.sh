#!/bin/bash

# Firebase Configuration Verification Script
# Checks if your .env.local has valid Firebase config

echo "🔍 Checking Firebase Configuration..."
echo ""

ENV_FILE="frontend/.env.local"

if [ ! -f "$ENV_FILE" ]; then
    echo "❌ Error: $ENV_FILE not found!"
    echo "   Make sure you're in the project root directory"
    exit 1
fi

echo "✅ Found $ENV_FILE"
echo ""

# Check each required variable
MISSING=0

check_var() {
    local var_name=$1
    local value=$(grep "^${var_name}=" "$ENV_FILE" | cut -d'=' -f2- | tr -d ' ')
    
    if [ -z "$value" ] || [[ "$value" == *"your_"* ]] || [[ "$value" == *"TODO"* ]]; then
        echo "❌ $var_name: Not configured (still has placeholder)"
        MISSING=$((MISSING + 1))
    else
        echo "✅ $var_name: Configured"
    fi
}

echo "Checking required variables:"
echo ""

check_var "NEXT_PUBLIC_FIREBASE_API_KEY"
check_var "NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN"
check_var "NEXT_PUBLIC_FIREBASE_PROJECT_ID"
check_var "NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET"
check_var "NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID"
check_var "NEXT_PUBLIC_FIREBASE_APP_ID"

echo ""

if [ $MISSING -eq 0 ]; then
    echo "✅ All Firebase configuration values are set!"
    echo ""
    echo "Next steps:"
    echo "1. Restart your frontend: cd frontend && npm run dev"
    echo "2. Open http://localhost:3000"
    echo "3. Test the sign-in button"
else
    echo "⚠️  $MISSING configuration value(s) still need to be set"
    echo ""
    echo "To fix this:"
    echo "1. Go to: https://console.firebase.google.com/"
    echo "2. Follow the guide in: FIREBASE_SETUP_GUIDE.md"
    echo "3. Or see: FIND_FIREBASE_KEYS.md for detailed instructions"
    echo ""
    echo "After updating .env.local, run this script again to verify"
fi

echo ""

