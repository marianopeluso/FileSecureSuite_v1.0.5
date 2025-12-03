@echo off
REM FileSecureSuite v1.0.5 - Windows Installation Script
REM This script checks for Python, optionally creates a venv, and installs dependencies

setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo                  FileSecureSuite v1.0.5 - Windows Installation
echo ================================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] Python not found!
    echo.
    echo To install Python:
    echo   1. Download from: https://www.python.org/downloads/
    echo   2. During installation, CHECK "Add Python to PATH"
    echo   3. During installation, CHECK "Add Python to environment variables"
    echo   4. After installation, RESTART YOUR COMPUTER
    echo   5. Open a NEW Command Prompt window
    echo   6. Run this script again
    echo.
    echo IMPORTANT: If you already installed Python but see this error,
    echo you likely forgot to check "Add Python to PATH"
    echo Uninstall Python and reinstall, checking ALL the boxes!
    echo.
    echo For detailed instructions, see: WINDOWS_PYTHON_INSTALLATION_GUIDE.md
    echo.
    pause
    exit /b 1
)

echo [OK] Python found:
python --version
echo.

REM Verify pip
pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip not found. Please reinstall Python with "Add Python to PATH" checked.
    pause
    exit /b 1
)

echo [OK] pip found:
pip --version
echo.

REM Get current directory
set "CURRENT_DIR=%cd%"
echo [INFO] Installation directory: %CURRENT_DIR%
echo.

REM Ask about venv
set /p VENV_CHOICE="Do you want to create a virtual environment (venv)? (y/n): "

if /i "%VENV_CHOICE%"=="y" (
    echo.
    echo [INFO] Creating virtual environment...
    python -m venv venv
    
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    
    echo [OK] Virtual environment created
    echo.
    echo [INFO] Activating virtual environment...
    call venv\Scripts\activate.bat
    
    if errorlevel 1 (
        echo [ERROR] Failed to activate virtual environment
        pause
        exit /b 1
    )
    
    echo [OK] Virtual environment activated
    echo.
) else (
    echo [INFO] Skipping virtual environment creation
    echo.
)

REM Upgrade pip
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip --quiet
if errorlevel 1 (
    echo [WARNING] pip upgrade encountered issues, continuing anyway...
)
echo [OK] pip is ready
echo.

REM Install dependencies
echo [INFO] Installing dependencies...
echo.

REM Required dependency
echo   - Installing cryptography (REQUIRED)...
pip install --quiet cryptography>=41.0.0
if errorlevel 1 (
    echo   [ERROR] cryptography installation failed. This is required.
    pause
    exit /b 1
) else (
    echo   [OK] cryptography installed
)
echo.

REM Optional dependencies with graceful fallback
echo [INFO] Installing optional dependencies (graceful fallback if failed)...
echo.

set "optional_deps=colorama>=0.4.6 pyperclip>=1.8.2 qrcode[pil]>=8.0"

for %%d in (%optional_deps%) do (
    echo   - Installing %%d...
    pip install --quiet %%d
    if errorlevel 1 (
        echo   [WARNING] %%d installation failed (this is optional, continuing)
    ) else (
        echo   [OK] %%d installed
    )
)

echo.
echo ================================================================================
echo                         Installation Complete!
echo ================================================================================
echo.

if /i "%VENV_CHOICE%"=="y" (
    echo [INFO] Virtual environment is ACTIVE
    echo.
    echo To launch FileSecureSuite:
    echo   python FileSecureSuite_1_0_5.py
    echo.
    echo When done, deactivate the venv with:
    echo   deactivate
    echo.
) else (
    echo [INFO] No virtual environment was created
    echo.
    echo To launch FileSecureSuite:
    echo   python FileSecureSuite_1_0_5.py
    echo.
)

echo [NOTE] Make sure FileSecureSuite_1_0_5.py is in: %CURRENT_DIR%
echo.
echo ================================================================================
echo.
echo [INFO] Optional Features:
echo   - Colored output: requires colorama
echo   - QR code generation: requires qrcode[pil]
echo   - Clipboard operations: requires pyperclip
echo.
echo If any optional dependency failed to install, FileSecureSuite will continue
echo to work with graceful fallback (some features may be limited).
echo.
echo ================================================================================
echo.

pause
