@echo off
title VPN Audit Tool
cd /d "%~dp0"

:: Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ============================================
    echo  ERROR: Administrator privileges required
    echo ============================================
    echo.
    echo  Scapy needs admin access for packet capture.
    echo  Right-click this file and select
    echo  "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: Check Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Install Python 3.10+ and add to PATH.
    pause
    exit /b 1
)

:: Install dependencies if needed
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)
call .venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements.txt --quiet

:: Start the server
echo.
echo ============================================
echo  VPN Audit Tool - Starting...
echo  Dashboard: http://localhost:8000
echo  API docs:  http://localhost:8000/docs
echo  Press Ctrl+C to stop
echo ============================================
echo.
:: Start server in background, wait for it, then open browser
start /b python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
echo Waiting for server to start...
:wait_loop
timeout /t 1 /nobreak >nul
curl -s http://127.0.0.1:8000/api/health >nul 2>&1
if %errorlevel% neq 0 goto wait_loop
start http://localhost:8000
echo Server is running. Press Ctrl+C to stop.
pause >nul
