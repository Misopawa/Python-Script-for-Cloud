@echo off
REM ===========================================================================
REM  Launcher for the AI-Powered Cloud Monitoring & Auto-Healing System (Windows).
REM
REM  Usage:
REM    install\run.bat           (console mode, default)
REM    install\run.bat --tui     (rich terminal dashboard)
REM
REM  Extra arguments are forwarded to src\main.py.
REM ===========================================================================
setlocal

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "PROJECT_ROOT=%%~fI"
set "VENV_PY=%PROJECT_ROOT%\.venv\Scripts\python.exe"

if not exist "%VENV_PY%" (
    echo [FAIL] Virtual environment not found. Run install\install.bat first.
    exit /b 1
)

cd /d "%PROJECT_ROOT%"
set "PYTHONPATH=src;%PYTHONPATH%"

echo [INFO] Starting AI-Powered Auto-Healing System (Ctrl+C to stop) ...
"%VENV_PY%" src\main.py %*
