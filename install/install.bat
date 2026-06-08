@echo off
REM ===========================================================================
REM  Clean installer for the AI-Powered Cloud Monitoring & Auto-Healing System
REM  (Windows).
REM
REM  Steps performed:
REM    1. Locate the Python launcher / interpreter.
REM    2. Create a FRESH virtual environment in .venv (existing one is removed).
REM    3. Upgrade pip and install everything from requirements.txt.
REM    4. Run install\verify_installation.py to confirm the install.
REM
REM  Usage:
REM    install\install.bat            (clean install + verify)
REM    install\install.bat --keep     (reuse .venv if present)
REM ===========================================================================
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "PROJECT_ROOT=%%~fI"
set "VENV_DIR=%PROJECT_ROOT%\.venv"
set "REQUIREMENTS=%PROJECT_ROOT%\requirements.txt"

set "KEEP_VENV=0"
if /I "%~1"=="--keep" set "KEEP_VENV=1"

echo ============================================================
echo  AI-Powered Cloud Monitoring ^& Auto-Healing System
echo  Clean installation (Windows)
echo ============================================================
echo [INFO] Project root: %PROJECT_ROOT%

REM --- 1. Find Python ---------------------------------------------------------
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo [FAIL] Python 3 not found. Install it from https://www.python.org/downloads/
    echo         and tick "Add Python to PATH" during setup.
    exit /b 1
)
echo [ OK ] Using Python launcher: %PY%
%PY% --version

if not exist "%REQUIREMENTS%" (
    echo [FAIL] requirements.txt not found at %REQUIREMENTS%
    exit /b 1
)

REM --- 2. Fresh virtual environment ------------------------------------------
if exist "%VENV_DIR%" if "%KEEP_VENV%"=="0" (
    echo [INFO] Removing existing virtual environment for a clean install...
    rmdir /s /q "%VENV_DIR%"
)

if not exist "%VENV_DIR%" (
    echo [INFO] Creating virtual environment: %VENV_DIR%
    %PY% -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [FAIL] Could not create the virtual environment.
        exit /b 1
    )
    echo [ OK ] Virtual environment created
) else (
    echo [WARN] Reusing existing virtual environment (--keep)
)

set "VENV_PY=%VENV_DIR%\Scripts\python.exe"
if not exist "%VENV_PY%" (
    echo [FAIL] Virtual environment python not found at %VENV_PY%
    exit /b 1
)

REM --- 3. Install dependencies -----------------------------------------------
echo [INFO] Upgrading pip / setuptools / wheel ...
"%VENV_PY%" -m pip install --upgrade pip setuptools wheel
echo [INFO] Installing dependencies from requirements.txt ...
"%VENV_PY%" -m pip install -r "%REQUIREMENTS%"
if errorlevel 1 (
    echo [FAIL] Dependency installation failed.
    exit /b 1
)
echo [ OK ] All dependencies installed

REM --- 4. Verify -------------------------------------------------------------
echo [INFO] Verifying installation ...
"%VENV_PY%" "%SCRIPT_DIR%verify_installation.py"
if errorlevel 1 (
    echo [FAIL] Verification reported problems. See the report above.
    exit /b 1
)

echo.
echo [ OK ] Installation complete and verified.
echo.
echo Next steps:
echo    Run (console)   : install\run.bat
echo    Run (dashboard) : install\run.bat --tui
exit /b 0
