#!/bin/bash

# FileSecureSuite v1.0.5 - macOS Installation Script
# This script checks for Python, optionally creates a venv, and installs dependencies

echo ""
echo "================================================================================"
echo "                  FileSecureSuite v1.0.5 - macOS Installation"
echo "================================================================================"
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 not found!"
    echo ""
    echo "To install Python 3 on macOS:"
    echo "  Option 1 - Using Homebrew (recommended):"
    echo "    1. Install Homebrew: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    echo "    2. Install Python: brew install python@3.11"
    echo ""
    echo "  Option 2 - Direct download:"
    echo "    Download from: https://www.python.org/downloads/macos/"
    echo ""
    exit 1
fi

echo "[OK] Python 3 found:"
python3 --version
echo ""

# Verify pip
if ! command -v pip3 &> /dev/null; then
    echo "[ERROR] pip3 not found. Please reinstall Python with pip included."
    exit 1
fi

echo "[OK] pip3 found:"
pip3 --version
echo ""

# Get current directory
CURRENT_DIR="$(pwd)"
echo "[INFO] Installation directory: $CURRENT_DIR"
echo ""

# Ask about venv
read -p "Do you want to create a virtual environment (venv)? (y/n): " VENV_CHOICE

if [[ "$VENV_CHOICE" =~ ^[Yy]$ ]]; then
    echo ""
    echo "[INFO] Creating virtual environment..."
    python3 -m venv venv
    
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to create virtual environment"
        exit 1
    fi
    
    echo "[OK] Virtual environment created"
    echo ""
    echo "[INFO] Activating virtual environment..."
    source venv/bin/activate
    
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to activate virtual environment"
        exit 1
    fi
    
    echo "[OK] Virtual environment activated"
    echo ""
    VENV_CREATED=true
else
    echo "[INFO] Skipping virtual environment creation"
    echo ""
    VENV_CREATED=false
fi

# Upgrade pip
echo "[INFO] Upgrading pip..."
python3 -m pip install --upgrade pip --quiet
if [ $? -ne 0 ]; then
    echo "[WARNING] pip upgrade encountered issues, continuing anyway..."
fi
echo "[OK] pip is ready"
echo ""

# Install dependencies
echo "[INFO] Installing dependencies..."
echo ""

# Required dependency
echo "   - Installing cryptography (REQUIRED)..."
pip3 install --quiet "cryptography>=41.0.0"
if [ $? -ne 0 ]; then
    echo "   [ERROR] cryptography installation failed. This is required."
    exit 1
else
    echo "   [OK] cryptography installed"
fi
echo ""

# Optional dependencies with graceful fallback
echo "[INFO] Installing optional dependencies (graceful fallback if failed)..."
echo ""

OPTIONAL_DEPS="colorama>=0.4.6 pyperclip>=1.8.2 qrcode[pil]>=8.0"

for dep in $OPTIONAL_DEPS; do
    echo "   - Installing $dep..."
    pip3 install --quiet "$dep"
    if [ $? -ne 0 ]; then
        echo "   [WARNING] $dep installation failed (this is optional, continuing)"
    else
        echo "   [OK] $dep installed"
    fi
done

echo ""
echo "================================================================================"
echo "                         Installation Complete!"
echo "================================================================================"
echo ""

if [ "$VENV_CREATED" = true ]; then
    echo "[INFO] Virtual environment is ACTIVE"
    echo ""
    echo "To launch FileSecureSuite:"
    echo "  python3 FileSecureSuite_1_0_5.py"
    echo ""
    echo "When done, deactivate the venv with:"
    echo "  deactivate"
    echo ""
else
    echo "[INFO] No virtual environment was created"
    echo ""
    echo "To launch FileSecureSuite:"
    echo "  python3 FileSecureSuite_1_0_5.py"
    echo ""
fi

echo "[NOTE] Make sure FileSecureSuite_1_0_5.py is in: $CURRENT_DIR"
echo ""
echo "================================================================================"
echo ""
echo "[INFO] Optional Features:"
echo "   - Colored output: requires colorama"
echo "   - QR code generation: requires qrcode[pil]"
echo "   - Clipboard operations: requires pyperclip"
echo ""
echo "If any optional dependency failed to install, FileSecureSuite will continue"
echo "to work with graceful fallback (some features may be limited)."
echo ""
echo "================================================================================"
echo ""
