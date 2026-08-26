@echo off
title MAILTRACE AI — Shutdown Utility
color 0E

echo ==============================================================================
echo                 MAILTRACE AI -- SERVICE SHUTDOWN UTILITY
echo ==============================================================================
echo.

echo [*] Stopping Python Backend (Uvicorn / FastAPI on port 8000)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    echo [*] Terminating process PID %%a on port 8000...
    taskkill /F /PID %%a >nul 2>&1
)

echo [*] Stopping Frontend Server (Vite / Node on port 5173)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5173" ^| findstr "LISTENING"') do (
    echo [*] Terminating process PID %%a on port 5173...
    taskkill /F /PID %%a >nul 2>&1
)

echo.
echo [OK] All MAILTRACE AI servers have been stopped.
echo.
pause
