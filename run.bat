@echo off
setlocal enabledelayedexpansion
title MAILTRACE AI — Production Defense Platform Launcher
color 0A

echo ==============================================================================
echo                 MAILTRACE AI -- EMAIL THREAT DETECTION PLATFORM
echo ==============================================================================
echo.

:: 1. CHECK FOR PYTHON
echo [*] Checking Python installation...
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    color 0C
    echo [!] ERROR: Python is not installed or not found in system PATH.
    echo Please install Python 3.10+ from https://www.python.org/ and check "Add to PATH".
    pause
    exit /b 1
)
python --version

:: 2. CHECK FOR NODE.JS & NPM
echo.
echo [*] Checking Node.js and npm installation...
node --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    color 0C
    echo [!] ERROR: Node.js is not installed or not found in system PATH.
    echo Please install Node.js 18+ from https://nodejs.org/
    pause
    exit /b 1
)
node --version
npm --version

:: 3. ENVIRONMENT FILE CHECK
echo.
echo [*] Checking environment configuration...
if not exist ".env" (
    echo [!] .env not found. Creating default .env from .env.example...
    copy .env.example .env >nul
    echo [*] Default .env created. You can customize API keys and Database URLs anytime.
) else (
    echo [OK] .env configuration file found.
)

:: 4. BACKEND SETUP & VIRTUAL ENVIRONMENT
echo.
echo [*] Initializing Backend Environment...
if not exist "backend\venv\Scripts\activate.bat" (
    echo [*] Creating Python virtual environment in backend\venv...
    python -m venv backend\venv
    if %ERRORLEVEL% NEQ 0 (
        color 0C
        echo [!] Failed to create Python virtual environment.
        pause
        exit /b 1
    )
)

echo [*] Activating virtual environment & verifying dependencies...
call backend\venv\Scripts\activate.bat
pip install -r backend\requirements.txt --quiet

:: 5. DATABASE TABLE VERIFICATION & AUTO-MIGRATION
echo.
echo [*] Connecting to Database and initializing tables...
python backend\init_db.py
if %ERRORLEVEL% NEQ 0 (
    echo [!] Warning: Database initialization encountered an issue. Backend will attempt table creation at runtime.
)

:: 6. FRONTEND SETUP & DEPENDENCIES
echo.
echo [*] Initializing Frontend Environment...
if not exist "frontend\node_modules" (
    echo [*] Installing frontend packages (npm install)...
    cd frontend && call npm install && cd ..
)

:: 7. LAUNCH BACKEND & FRONTEND SERVERS
echo.
echo ==============================================================================
echo   STARTING SERVICES...
echo   Backend  : http://localhost:8000  (API Docs: http://localhost:8000/docs)
echo   Frontend : http://localhost:5173
echo ==============================================================================

:: Start Backend in dedicated window
start "MAILTRACE AI — Backend (Port 8000)" cmd /k "title MAILTRACE AI - Backend [8000] && cd backend && call venv\Scripts\activate.bat && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

:: Start Frontend in dedicated window
start "MAILTRACE AI — Frontend (Port 5173)" cmd /k "title MAILTRACE AI - Frontend [5173] && cd frontend && npm run dev"

:: Wait 3 seconds for servers to bind
timeout /t 3 /nobreak >nul

:: Automatically open browser
echo [*] Launching MAILTRACE AI in your default web browser...
start http://localhost:5173

echo.
echo [OK] Platform is running!
echo.
echo Default Logins:
echo   - Admin User   : admin   / Admin@12345
echo   - Analyst User : analyst / Analyst@12345
echo.
echo To stop the servers, close the two opened server terminal windows or run stop.bat.
echo.
pause
