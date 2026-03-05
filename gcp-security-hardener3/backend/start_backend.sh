#!/bin/bash
# Robust startup script for the backend
# Ensures correct working directory and PYTHONPATH

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to that directory
cd "$SCRIPT_DIR"

# Activate venv just in case, or use direct path
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Set PYTHONPATH to current directory to ensure 'app' module is found
export PYTHONPATH=$PYTHONPATH:.

# Start uvicorn
echo "Starting Backend Server on port 8000..."
./venv/bin/uvicorn app.main:app --port 8000
