# Changelog

All notable changes to FileSecureSuite are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.5] - 2025-12-02

### Added
- **Key Management System**
  - New `backup_keys()` function for secure RSA key backup
  - New `export_public_key()` function to extract public keys from private keys
  - Dedicated keys directory with restricted permissions (700)
  - Dedicated backup directory for key exports
  - Password protection validation for key operations

- **Enhanced Audit Logging**
  - New audit log fields: `keyname`, `key_protected`, `key_fingerprint`
  - Improved key operation tracking for compliance
  - Key fingerprint calculation and logging
  - Better log formatting and field alignment

### Improved
- **User Interface**
  - New submenu structure for Encrypt/Decrypt operations
  - Dedicated Key Management submenu in main navigation (option [4])
  - Enhanced menu navigation with consistent "Back to Menu" options
  - Password attempt tracking with exponential backoff (2^n seconds)
  - Better error messaging for key operations
  - Consistent emoji indicators for all menu options

- **Backup Functionality**
  - Support for selective key backup (users can choose specific keys by number)
  - Automatic backup directory creation with secure permissions (0o700)
  - Individual success/failure reporting for each key backup
  - Duplicate detection in user input with automatic removal
  - Comprehensive logging of backup operations with key counts
  - Two backup modes: backup all keys or select specific keys

- **Dependency Management**
  - QRCode and PIL now optional with graceful fallback (HAS_QRCODE flag)
  - Removed automatic pip installation of qrcode[pil]
  - Removed tqdm dependency
  - Added threading support for background clipboard operations

- **Security**
  - New `validate_password_strength_key()` function for stricter key password validation
  - Key passwords now require: 12+ chars, uppercase, lowercase, digit, and special char
  - PBKDF2 iterations increased from 480000 to 600000 (OpenSSL 3.0 default)
  - Explicit PBKDF2_HASH_ALGORITHM constant (SHA-256)
  - Background clipboard auto-clear using threading

- **Code Quality**
  - Removed debug statements from password input handling
  - Improved documentation and inline comments
  - Better constant definitions (AES_KEY_SIZE, PBKDF2_HASH_ALGORITHM)
  - Enhanced log entry formatting (operation field: 12 → 15 chars)

### Technical Details
- Key management menu added to main interface with submenu structure
- Key backup includes fingerprint calculation and audit logging
- Public key export with validation, password attempt handling, and logging
- All key directories created with secure 0o700 permissions
- Clipboard clear operations now non-blocking with threading
- Exponential backoff implementation: 2^n seconds between failed password attempts
- Selective backup validation prevents invalid key selections

---

## [1.0.4] - 2025-11-17

### Fixed
- **Encrypted filename truncation issue**
  - Removed 25-character limit on original filenames in encrypted output
  - Files now retain complete names during encryption process
  - Affected both AES-256-GCM and RSA-4096 encryption modes
  - Fixed in single-file encryption operations

### Technical Details
- Filename preservation now supports full path lengths
- Cross-platform filename handling maintained
- All encryption formats (AES, RSA, Base64) updated

---

## [1.0.3] - 2025-11-16

### Improved
- **QR Code display functionality**
  - Replaced PNG file generation with ASCII art terminal display using `print_ascii()`
  - QR code now displayed only when user selects option [1] "View QR Code"
  - Removed file I/O operations (.qrcode directory creation)
  - Ephemeral QR code display (no files left on disk)
  - Unified navigation: both Credits and QR Code pages return to Main Menu
  - Enhanced terminal-based user experience

### Changed
- Removed `generate_lightning_qr()` function (PNG generation)
- Removed `open_qr_image()` function (image viewer integration)
- Renamed QR generation to `generate_and_display_lightning_qr()` (ASCII display)
- Credits page now shows menu before displaying QR code

### Technical Details
- Uses `qrcode.print_ascii(invert=True)` for better terminal readability
- Maintains ERROR_CORRECT_L for Lightning address accuracy
- Cross-platform compatible (Windows/Linux/macOS terminals)
- No external image viewer dependencies required

---

## [1.0.2] - 2025-11-14

### Fixed
- **SyntaxError in QR code display** (line 1372)
  - Fixed f-string expression containing backslash character
  - Moved newlines outside f-string expression for Python 3.6+ compatibility
- **QR code viewer not opening on Linux/macOS**
  - Fixed subprocess calls not properly backgrounding image viewers
  - Improved xdg-open and eog compatibility
  - Added proper error handling for missing viewers

### Improved
- Cross-platform image viewer handling (Windows/Linux/macOS)
- Subprocess error handling and fallback mechanisms
- Headless environment detection and handling
- File permission handling across platforms

### Tested On
- Windows 10/11 (CMD)
- Linux Desktop (GNOME/KDE/XFCE)
- Kali Linux (Headless SSH)
- Remote Desktop environments

---

## [1.0.1] - 2025-11-13

### Fixed
- Cross-platform line ending normalization (CRLF → LF)
- UTF-8 encoding issues on Linux systems
- File encoding standardization for Python 3.6+ compatibility

---

## [1.0.0] - 2025-11-13

### Added
- Core encryption features with AES-256-GCM and RSA-4096
- Interactive CLI menu system with color-coded output
- File encryption/decryption with HMAC verification
- Text encryption/decryption from command line
- RSA key pair generation and management
- QR code generation for key sharing
- PBKDF2 key derivation with configurable iterations
- Batch file processing capabilities
- Cross-platform support (Windows, macOS, Linux)
- Automated installers for all platforms
- Progress bars for file operations
- Clipboard integration for key management

### Security
- AES-256-GCM for authenticated encryption
- RSA-4096 for asymmetric encryption
- PBKDF2 with SHA-256 for key derivation
- HMAC-based integrity verification
- Secure random salt generation
- Restrictive file permissions (owner only)
- No plaintext key storage

### Documentation
- Comprehensive README with features and quick start
- Detailed installation instructions for all platforms
- Windows Python installation guide
- Installer usage documentation

---

## Future Releases

### Planned for v1.1.0
- Command-line interface improvements (argparse)
- Performance optimizations
- Enhanced error messages
- Password strength meter UI improvements

### Planned for v2.0.0
- GUI application (Tkinter/PyQt)
- Streaming encryption for large files
- Compression before encryption
- Certificate-based encryption
- Advanced batch processing with filters

---

**Current Version:** 1.0.5  
**Release Date:** 2025-12-02  
**Status:** Production Ready
