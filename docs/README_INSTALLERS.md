# FileSecureSuite v1.0.5 - Installation Files

## What You Need

Choose based on your operating system:

### Windows
- **File:** `install_filesecure_windows.bat`
- **What to do:** Double-click or run in Command Prompt
- **Also need:** `FileSecureSuite_1_0_5.py` in the same folder

### Linux
- **File:** `install_filesecure_linux.sh`
- **What to do:** `bash install_filesecure_linux.sh`
- **Also need:** `FileSecureSuite_1_0_5.py` in the same folder

### macOS
- **File:** `install_filesecure_macos.sh`
- **What to do:** `bash install_filesecure_macos.sh`
- **Also need:** `FileSecureSuite_1_0_5.py` in the same folder

---

## Quick Start (3 Steps)

1. **Download all three files:**
   - `install_filesecure_*.bat/.sh` (for your OS)
   - `FileSecureSuite_1_0_5.py`
   - Put them in the same folder

2. **Run the installer:**
   - **Windows:** Double-click `install_filesecure_windows.bat`
   - **Linux:** `bash install_filesecure_linux.sh`
   - **macOS:** `bash install_filesecure_macos.sh`

3. **Follow the prompts:**
   - Confirm Python installation
   - Choose if you want a virtual environment (recommended: yes)
   - Wait for dependencies to install
   - See "Installation Complete!" message

---

## What the Installer Does

✅ Checks for Python 3.8+  
✅ Offers to create a virtual environment (optional)  
✅ Installs cryptography (REQUIRED) - Encryption library  
✅ Installs optional features (colorama, qrcode, pyperclip)  
✅ Tells you exactly how to launch the app  

---

## Dependencies Installed

### Required (Must Install)
- **cryptography ≥ 41.0.0** - AES-256-GCM and RSA-4096 encryption

### Optional (Graceful Fallback)
- **colorama ≥ 0.4.6** - Colored terminal output
- **qrcode[pil] ≥ 8.0** - QR code generation
- **pyperclip ≥ 1.8.2** - Clipboard operations

If optional features fail to install, FileSecureSuite will still work with reduced functionality.

---

## After Installation

The installer will tell you how to run the app. Typically:

**Windows:**
```cmd
python FileSecureSuite_1_0_5.py
```

**Linux/macOS (with venv):**
```bash
source venv/bin/activate
python3 FileSecureSuite_1_0_5.py
```

**Linux/macOS (without venv):**
```bash
python3 FileSecureSuite_1_0_5.py
```

---

## System Requirements

- **Python 3.8 or higher** (not installed? Download from https://www.python.org)
- **Internet connection** (for first installation only)
- **5-10 minutes** for complete setup

---

## If Something Goes Wrong

### Windows - Python Not Found

1. Download Python: https://www.python.org/downloads/
2. During install, CHECK "Add Python to PATH"
3. Restart Command Prompt
4. Try installer again

### Linux - Python Not Found

```bash
# Ubuntu/Debian
sudo apt install python3 python3-pip python3-venv -y

# Fedora
sudo dnf install python3 python3-pip -y

# Arch
sudo pacman -S python python-pip -y
```

### macOS - Python Not Found

```bash
# Using Homebrew (recommended)
brew install python@3.11

# OR download from https://www.python.org/downloads/macos/
```

### Optional Features Not Installing

If colorama, qrcode, or pyperclip fail to install:

1. FileSecureSuite will still work (graceful fallback)
2. You can install them manually later:
   ```bash
   pip install colorama qrcode[pil] pyperclip
   ```

---

## Manual Installation (Without Installer)

If installer doesn't work, install manually:

**Windows:**
```cmd
python -m pip install cryptography>=41.0.0
python -m pip install colorama qrcode[pil] pyperclip
python FileSecureSuite_1_0_5.py
```

**Linux/macOS:**
```bash
python3 -m pip install cryptography>=41.0.0
python3 -m pip install colorama qrcode[pil] pyperclip
python3 FileSecureSuite_1_0_5.py
```

---

## Full Documentation

- **Installation Details:** [INSTALLATION_INSTRUCTIONS.md](INSTALLATION_INSTRUCTIONS.md)
- **Windows Setup:** [WINDOWS_PYTHON_INSTALLATION_GUIDE.md](WINDOWS_PYTHON_INSTALLATION_GUIDE.md)
- **Quick Start:** [QUICKSTART.md](QUICKSTART.md)
- **Security:** [SECURITY.md](SECURITY.md)
- **What's New:** [CHANGELOG.md](CHANGELOG.md)

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Python not found | Download from python.org, check "Add to PATH" |
| pip not found | Use `python -m pip` or reinstall Python |
| Permission denied (Linux/macOS) | Run `chmod +x install_filesecure_*.sh` first |
| Optional features fail | Still works! Install manually if needed |
| Installation stuck | Check internet connection, try manual install |

---

**Ready to go!** 🚀

FileSecureSuite v1.0.5 - Enterprise encryption for everyone  
*Last Updated: 2025-12-02*
