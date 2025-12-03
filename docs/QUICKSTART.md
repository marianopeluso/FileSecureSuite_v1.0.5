# FileSecureSuite v1.0.5 - Quick Start Guide

## Installation (2 minutes)

### Windows
```bash
python -m pip install cryptography
python FileSecureSuite_1_0_5.py
```

### macOS / Linux
```bash
python3 -m pip install cryptography
python3 FileSecureSuite_1_0_5.py
```

### Using Automated Installers (Recommended)
- **Windows:** Double-click `install_filesecure_windows.bat`
- **Linux:** `bash install_filesecure_linux.sh`
- **macOS:** `bash install_filesecure_macos.sh`

---

## Usage

Launch the application:
```bash
python3 FileSecureSuite_1_0_5.py
```

### Main Menu Options

**[1] Generate RSA-4096 Key Pair**
- Create new encryption keys for public-key encryption

**[2] Encrypt**
- Choose between text or file encryption
- Select AES-256-GCM (password-based) or RSA-4096 (public-key)

**[3] Decrypt**
- Decrypt text (Base64 format from clipboard)
- Decrypt files (automatic format detection)

**[4] Key Management** ⭐ NEW in v1.0.5
- Backup keys securely to backup/ directory
- Export public keys from private keys
- View key fingerprints

**[5] View Audit Log**
- Review all encryption/decryption operations
- Compliance and security tracking

**[6] Credits**
- About FileSecureSuite
- Support options

**[7] Exit**
- Close the application

---

## Common Operations

### Encrypt a File
1. Press `[2]` for Encrypt
2. Press `[2]` for File
3. Choose method: `[1]` for AES-256-GCM or `[2]` for RSA-4096
4. Enter password or select public key
5. Select file to encrypt
6. File saved as `encrypted_<filename>_<timestamp>.aes` or `.rsa`

### Decrypt a File
1. Press `[3]` for Decrypt
2. Press `[2]` for File
3. Select encrypted file
4. Enter password or provide private key
5. File decrypted and verified

### Backup Keys
1. Press `[4]` for Key Management
2. Press `[1]` for Backup Keys
3. Choose: Backup all or select specific keys
4. Keys saved to `./backup/` directory

---

## Requirements
- Python 3.8+
- pip
- Internet (first installation only)

### Dependencies

**Required:**
- `cryptography` - Encryption algorithms

**Optional (with graceful fallback):**
- `colorama` - Colored terminal output
- `qrcode[pil]` - QR code display
- `pyperclip` - Clipboard operations

---

## Troubleshooting

**Python not found?**
- Windows: Download from https://www.python.org/downloads/ (check "Add Python to PATH")
- Linux: `sudo apt install python3 python3-pip`
- macOS: `brew install python@3.11`

**pip not found?**
```bash
python -m pip install cryptography
python3 -m pip install cryptography
```

**Missing colored output or QR codes?**
```bash
pip install colorama qrcode[pil]
```

**Files not decrypting?**
- Ensure file has correct extension (.aes, .aes.b64, .rsa, .rsa.b64)
- Verify correct password or private key
- Check audit log for operation history

---

## Documentation

- [INSTALLATION_INSTRUCTIONS.md](INSTALLATION_INSTRUCTIONS.md) - Full setup guide
- [WINDOWS_PYTHON_INSTALLATION_GUIDE.md](WINDOWS_PYTHON_INSTALLATION_GUIDE.md) - Windows detailed setup
- [README_INSTALLERS.md](README_INSTALLERS.md) - Installer guide
- [SECURITY.md](SECURITY.md) - Security best practices
- [CHANGELOG.md](CHANGELOG.md) - What's new in v1.0.5

---

## Key Management Best Practices

1. **Backup Keys Regularly** - Use Key Management menu
2. **Verify Key Fingerprints** - Compare fingerprints when sharing public keys
3. **Strong Passwords** - Key passwords require: 12+ chars, mixed case, numbers, symbols
4. **Secure Storage** - Keep private keys and backups in secure location
5. **Review Audit Log** - Monitor encryption operations

---

## What's New in v1.0.5?

✅ **Key Management System** - Backup and export keys with fingerprinting  
✅ **Enhanced Security** - Stricter key password validation  
✅ **Better UI** - Dedicated submenus for easier navigation  
✅ **Audit Logging** - Track key operations for compliance  
✅ **Optional Dependencies** - Graceful fallback if features unavailable  

---

## License
MIT License - See [LICENSE](LICENSE)

---

**FileSecureSuite v1.0.5 - Enterprise encryption for everyone**  
*Last Updated: 2025-12-02*
