#!/bin/bash

# Log Collection Script
# Helps collect error logs for analysis

echo "🔍 GCP Security Hardener - Log Collection"
echo "=========================================="
echo ""

echo "This script will help you collect error logs."
echo ""

# Check backend
echo "1. Checking backend status..."
BACKEND_STATUS=$(curl -s http://localhost:8000/health 2>&1)
if echo "$BACKEND_STATUS" | grep -q "healthy"; then
    echo "✅ Backend is running"
else
    echo "❌ Backend is NOT running or not accessible"
    echo "   Response: $BACKEND_STATUS"
    echo ""
    echo "   Start backend with:"
    echo "   cd backend && source venv/bin/activate && uvicorn app.main:app --reload"
fi

echo ""

# Check frontend
echo "2. Checking frontend status..."
FRONTEND_STATUS=$(curl -s http://localhost:3000 2>&1 | head -1)
if echo "$FRONTEND_STATUS" | grep -q "html\|<!DOCTYPE"; then
    echo "✅ Frontend is running"
else
    echo "❌ Frontend is NOT running or not accessible"
    echo ""
    echo "   Start frontend with:"
    echo "   cd frontend && npm run dev"
fi

echo ""

# Check environment files
echo "3. Checking configuration..."
if [ -f "frontend/.env.local" ]; then
    echo "✅ frontend/.env.local exists"
    # Check if Firebase config is set
    if grep -q "your_firebase\|your_project\|TODO" frontend/.env.local; then
        echo "⚠️  Firebase config may not be set (contains placeholders)"
    else
        echo "✅ Firebase config appears to be set"
    fi
else
    echo "❌ frontend/.env.local not found"
fi

if [ -f "backend/.env" ]; then
    echo "✅ backend/.env exists"
else
    echo "⚠️  backend/.env not found (using defaults)"
fi

echo ""

# Network check
echo "4. Testing API connectivity..."
SCAN_TEST=$(curl -s -X POST http://localhost:8000/api/v1/scan/ \
    -H "Content-Type: application/json" \
    -d '{"project_id":"test","access_token":"test"}' 2>&1)

if echo "$SCAN_TEST" | grep -q "detail\|error\|Authentication"; then
    echo "✅ API endpoint is accessible (returned expected error for test data)"
else
    echo "⚠️  API endpoint may not be responding correctly"
    echo "   Response: $SCAN_TEST"
fi

echo ""
echo "=========================================="
echo "📋 Next Steps:"
echo ""
echo "1. Open browser console (F12)"
echo "2. Go to Console tab"
echo "3. Look for errors (red text)"
echo "4. Copy the error messages"
echo "5. Check Network tab for failed requests"
echo ""
echo "6. Check backend terminal for error logs"
echo "7. Copy the last 20-30 lines of backend output"
echo ""
echo "Share these logs and I can help analyze them!"
echo ""

