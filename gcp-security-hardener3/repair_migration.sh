#!/bin/bash
set -e

echo "🛠️  Starting Migration Repair for GCP-Security-Hardener3/Wursta"
echo ""

# 1. Clean Backend Venv (Broken by move)
echo "🧹 Cleaning Backend Environment..."
rm -rf backend/venv
rm -rf backend/__pycache__

# 2. Re-create Backend Venv
echo "🐍 Rebuilding Python Virtual Environment..."
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd ..

# 3. Clean Frontend Node Modules (Broken by move)
echo "🧹 Cleaning Frontend Environment..."
rm -rf frontend/node_modules
# Do not remove package-lock.json unless necessary to keep versions stable
# rm frontend/package-lock.json 

# 4. Re-install Frontend
echo "📦 Reinstalling Frontend Dependencies..."
cd frontend
npm install @coreui/react @coreui/coreui @coreui/icons @coreui/icons-react
npm install
cd ..

echo ""
echo "✅ Migration Repair Complete!"
echo "You can now run './start-dev.sh'"
