# Changelog

All notable changes to FileSecureSuite are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

**Current Version:** 1.0.4  
**Release Date:** 2025-11-17  
**Status:** Production Ready
