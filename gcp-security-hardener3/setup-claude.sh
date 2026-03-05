#!/bin/bash

# Claude AI Setup Script for GCP Security Hardener
# This script helps set up Claude AI integration

set -e

echo "🚀 Setting up Claude AI integration..."
echo ""

# Check if we're in the right directory
if [ ! -d "backend" ]; then
    echo "❌ Error: Please run this script from the project root directory"
    exit 1
fi

# Step 1: Install Python dependencies
echo "📦 Step 1: Installing Python dependencies..."
cd backend

if [ -d "venv" ]; then
    echo "   Activating virtual environment..."
    source venv/bin/activate
fi

echo "   Installing anthropic package..."
pip install anthropic==0.34.2

echo "   ✅ Dependencies installed"
echo ""

# Step 2: Check for API key
echo "🔑 Step 2: Checking for Claude API key..."
cd ..

if [ -f "backend/.env" ]; then
    if grep -q "CLAUDE_API_KEY" backend/.env || grep -q "ANTHROPIC_API_KEY" backend/.env; then
        echo "   ✅ API key found in backend/.env"
    else
        echo "   ⚠️  API key not found in backend/.env"
        echo ""
        echo "   Please add one of the following to backend/.env:"
        echo "   CLAUDE_API_KEY=sk-ant-your-api-key-here"
        echo "   or"
        echo "   ANTHROPIC_API_KEY=sk-ant-your-api-key-here"
        echo ""
        read -p "   Do you want to add it now? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            read -p "   Enter your Claude API key: " api_key
            echo "CLAUDE_API_KEY=$api_key" >> backend/.env
            echo "   ✅ API key added to backend/.env"
        fi
    fi
else
    echo "   ⚠️  backend/.env file not found"
    echo ""
    read -p "   Do you want to create it and add your API key? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "   Enter your Claude API key: " api_key
        echo "CLAUDE_API_KEY=$api_key" > backend/.env
        echo "   ✅ Created backend/.env with API key"
    else
        echo "   ℹ️  You can set the API key later by:"
        echo "      export CLAUDE_API_KEY=sk-ant-your-api-key-here"
        echo "      or add it to backend/.env"
    fi
fi

echo ""

# Step 3: Verify installation
echo "🔍 Step 3: Verifying installation..."
cd backend

if python3 -c "import anthropic" 2>/dev/null; then
    echo "   ✅ anthropic package is installed"
else
    echo "   ❌ anthropic package not found. Please run: pip install anthropic==0.34.2"
    exit 1
fi

# Check if API key is set (in environment or .env)
if [ -n "$CLAUDE_API_KEY" ] || [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "   ✅ API key is set in environment"
elif [ -f ".env" ] && (grep -q "CLAUDE_API_KEY" .env || grep -q "ANTHROPIC_API_KEY" .env); then
    echo "   ✅ API key is set in .env file"
else
    echo "   ⚠️  API key not found. Please set CLAUDE_API_KEY or ANTHROPIC_API_KEY"
fi

echo ""

# Step 4: Summary
echo "✨ Setup Summary:"
echo "   - Python package: ✅"
if python3 -c "import anthropic" 2>/dev/null; then
    echo "   - anthropic installed: ✅"
else
    echo "   - anthropic installed: ❌"
fi

if [ -n "$CLAUDE_API_KEY" ] || [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "   - API key configured: ✅ (environment)"
elif [ -f ".env" ] && (grep -q "CLAUDE_API_KEY" .env || grep -q "ANTHROPIC_API_KEY" .env); then
    echo "   - API key configured: ✅ (.env file)"
else
    echo "   - API key configured: ⚠️  (not set)"
fi

echo ""
echo "📝 Next Steps:"
echo "   1. If API key is not set, add it to backend/.env or export it"
echo "   2. Restart your backend server:"
echo "      cd backend"
echo "      uvicorn app.main:app --reload"
echo "   3. Test Claude in the UI by running a scan and clicking the 'Claude' button"
echo ""
echo "🎉 Setup complete! (or mostly complete if API key needs to be set)"
echo ""
