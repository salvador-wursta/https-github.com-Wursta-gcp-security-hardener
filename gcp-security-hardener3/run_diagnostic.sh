#!/bin/bash
# Run diagnostic using backend's virtual environment

echo "GCP Lockdown Diagnostic Runner (using backend venv)"
echo "=================================================="
echo ""

# Navigate to backend directory
cd "$(dirname "$0")/backend" || exit 1

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate venv
echo "Activating virtual environment..."
source venv/bin/activate

# Check if google-cloud libraries are installed
if ! python -c "import google.oauth2" 2>/dev/null; then
    echo "Installing dependencies..."
    pip install -q google-auth google-api-python-client google-cloud-resource-manager
fi

# Run diagnostic from parent directory
cd ..

echo ""
echo "Running diagnostic..."
echo ""

python diagnose_lockdown.py "$@"

RESULT=$?

# Deactivate venv
deactivate

exit $RESULT
