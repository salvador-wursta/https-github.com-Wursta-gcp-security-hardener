@echo off
SETLOCAL EnableDelayedExpansion

echo ====================================================
echo      GCP Security Hardener - Windows Compiler
echo ====================================================
echo.

:: Check for Python
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ and try again.
    pause
    exit /b 1
)

cd backend

echo [1/3] Setting up Build Environment...
if not exist "venv_build" (
    python -m venv venv_build
)
call venv_build\Scripts\activate.bat

echo [2/3] Installing Dependencies...
pip install -r requirements.txt
pip install pyinstaller

echo [3/3] Compiling Backend to EXE...
pyinstaller --clean build_backend.spec

if exist "dist\gcp-scanner-backend.exe" (
    echo.
    echo [SUCCESS] Compilation Complete!
    echo executable is located at: backend\dist\gcp-scanner-backend.exe
) else (
    echo.
    echo [ERROR] Compilation failed. Check console output.
)

deactivate
cd ..
pause
