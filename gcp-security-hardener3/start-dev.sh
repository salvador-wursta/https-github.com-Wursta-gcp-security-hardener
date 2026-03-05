#!/bin/bash

# Development Startup Script
# Starts both backend and frontend in separate terminals

echo "🚀 Starting GCP Security Hardener Development Environment"
echo ""

# Check if backend venv exists
if [ ! -d "backend/venv" ]; then
    echo "❌ Backend virtual environment not found!"
    echo "Run: cd backend && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# Check if frontend node_modules exists
if [ ! -d "frontend/node_modules" ]; then
    echo "❌ Frontend dependencies not installed!"
    echo "Run: cd frontend && npm install"
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""
echo "Starting servers..."
echo ""
echo "📦 Backend will start on: http://localhost:8000"
echo "🌐 Frontend will start on: http://localhost:3001"
echo ""
echo "Press Ctrl+C to stop all servers"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping servers..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    exit
}

trap cleanup SIGINT SIGTERM

# Start backend
echo "Starting backend (Logs: backend.log)..."
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 > ../backend.log 2>&1 &
BACKEND_PID=$!
cd ..

# Wait a moment for backend to start
sleep 2

# Start frontend
echo "Starting frontend (Logs: frontend.log)..."
cd frontend
npm run dev -- -p 3001 > ../frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..

# Wait for both processes
wait $BACKEND_PID $FRONTEND_PID

