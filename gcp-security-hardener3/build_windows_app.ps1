<#
.SYNOPSIS
    Automated Local Build Script for Windows
.DESCRIPTION
    Compiles the Backend (Python) and Frontend (Electron) into a single installer.
    Prerequisites: Python 3.10+, Node.js 18+
#>

$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   GCP Security Hardener - Automated Builder" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Prereqs
if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Error "Python not found. Please install Python 3.10+."
    exit 1
}
if (-not (Get-Command "npm" -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js (npm) not found. Please install Node.js 18+."
    exit 1
}

# 2. Build Backend
Write-Host "[1/4] Building Backend Service..." -ForegroundColor Yellow
if (Test-Path "backend\dist") { Remove-Item -Recurse -Force "backend\dist" }

Push-Location "backend"
try {
    if (-not (Test-Path "venv_build")) {
        Write-Host "Creating Python venv..."
        python -m venv venv_build
    }
    & "venv_build\Scripts\activate.ps1"
    
    Write-Host "Installing Python deps..."
    pip install -r requirements.txt
    pip install pyinstaller
    
    Write-Host "Compiling to EXE..."
    pyinstaller --clean build_backend.spec
}
finally {
    if (Test-Path "venv_build\Scripts\deactivate.ps1") {
        & "venv_build\Scripts\deactivate.ps1"
    }
    Pop-Location
}

if (-not (Test-Path "backend\dist\gcp-scanner-backend.exe")) {
    Write-Error "Backend compilation failed. EXE not found."
    exit 1
}
Write-Host "Backend built successfully." -ForegroundColor Green

# 3. Build Frontend
Write-Host "[2/4] Building Frontend Interface..." -ForegroundColor Yellow
Push-Location "frontend"
try {
    npm install
    npm run build
}
finally {
    Pop-Location
}
Write-Host "Frontend built successfully." -ForegroundColor Green

# 4. Build Electron
Write-Host "[3/4] Packaging Electron App..." -ForegroundColor Yellow
# Install root dependencies (electron-builder)
npm install

# Run builder
npm run build:win

# 5. Summary
Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   BUILD COMPLETE" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""
if (Test-Path "dist") {
    $installers = Get-ChildItem "dist\*.exe"
    foreach ($i in $installers) {
        Write-Host "Created Installer: $($i.FullName)" -ForegroundColor Green
    }
    Invoke-Item "dist"
}
Read-Host "Press Enter to exit"
