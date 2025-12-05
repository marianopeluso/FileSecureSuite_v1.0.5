# 🔐 FileSecureSuite - Security Policy

**FileSecureSuite - Enterprise-grade file encryption with AES-256-GCM and RSA-4096**

## Release Verification

All FileSecureSuite releases are cryptographically signed with GPG to ensure authenticity and integrity.

### How to Verify a Release

#### Step 1: Import the Public Key (First Time Only)

```bash
# Download the public key
curl -O https://github.com/marianopeluso/FileSecureSuite/raw/main/filesecuresuite_pub.asc

# Import it into GPG
gpg --import filesecuresuite_pub.asc
```

#### Step 2: Download the Release Files

```bash
# Download from GitHub Releases
VERSION="1.0.5"
BASE_URL="https://github.com/marianopeluso/FileSecureSuite/releases/download/v${VERSION}"

# Download archive and signature
curl -LO "${BASE_URL}/filesecuresuite.zip"
curl -LO "${BASE_URL}/filesecuresuite.zip.asc"
curl -LO "${BASE_URL}/filesecuresuite.zip.sha256"
```

#### Step 3: Verify the GPG Signature

```bash
gpg --verify filesecuresuite.zip.asc filesecuresuite.zip
```

**Expected output:**
```
gpg: Signature made [DATE]
gpg:                using RSA key F20494B9FAB53C10
gpg: Good signature from "Mariano Peluso <mariano@peluso.me>"
```

✅ **"Good signature"** means the file is authentic and hasn't been tampered with.

⚠️ The warning `[unknown]` is normal and means you haven't personally verified the key owner's identity. This is acceptable for open-source projects.

#### Step 4: Verify the Checksum

```bash
# Verify SHA-256
sha256sum -c filesecuresuite.zip.sha256

# Or manually compare
sha256sum filesecuresuite.zip
cat filesecuresuite.zip.sha256
```

**Expected output:**
```
filesecuresuite.zip: OK
```

### Windows Users

**Install GPG:**
1. Download Gpg4win: https://www.gpg4win.org/download.html
2. Install with default options

**Verify signature:**
```cmd
gpg --verify filesecuresuite.zip.asc filesecuresuite.zip
```

**Verify checksum (without GPG):**
```cmd
certutil -hashfile filesecuresuite.zip SHA256
```
Compare the output with the hash in `filesecuresuite.zip.sha256`

---

## Public Key Fingerprint

**Key ID:** `F20494B9FAB53C10`
**Fingerprint:** `0FD97EB855F7C5BB1048D424F20494B9FAB53C10`

The public key is available:
- In this repository: [`filesecuresuite_pub.asc`](./filesecuresuite_pub.asc)
- On keyservers: `keys.openpgp.org`
- In GitHub Releases

To view the fingerprint:
```bash
gpg --fingerprint mariano@peluso.me
```

---

## Security Best Practices

When using FileSecureSuite:

1. **Verify every release** before installation
2. **Use strong passwords** for encryption (12+ chars with mixed case, numbers, symbols)
3. **Keep private keys secure** and backed up using Key Management
4. **Verify key fingerprints** when sharing public keys
5. **Verify file integrity** after decryption
6. **Update regularly** to get security patches
7. **Review audit logs** for compliance and security monitoring

---

## Key Management Security

### Secure Key Backup

FileSecureSuite provides secure key backup functionality:

- **Automatic Directory Management** - Dedicated backup directory with restricted permissions (0o700)
- **Selective Backup** - Choose which keys to backup or backup all at once
- **Audit Logging** - All backup operations are logged for compliance
- **Password Protection** - Private keys can be encrypted with strong passwords
- **Fingerprint Verification** - Public keys include fingerprints for verification

### Key Password Requirements

Key passwords must meet strict requirements:
- **Minimum 12 characters**
- **At least one uppercase letter**
- **At least one lowercase letter**
- **At least one digit**
- **At least one special character**

This ensures high entropy and resistance to brute-force attacks.

### Public Key Export

When exporting public keys from private keys:

- **Automatic Fingerprint Calculation** - SHA-256 fingerprints for verification
- **File Integrity** - Public keys exported with secure permissions
- **Audit Trail** - All export operations are logged
- **Password Attempt Limiting** - Exponential backoff on failed password attempts (2^n seconds)

---

## Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability in FileSecureSuite:

### Please DO:
- ✅ Email us privately at: **mariano@peluso.me**
- ✅ Provide detailed steps to reproduce
- ✅ Allow us 90 days to fix before public disclosure
- ✅ Include proof-of-concept code if possible

### Please DO NOT:
- ❌ Open a public GitHub issue
- ❌ Disclose the vulnerability publicly before we've patched it
- ❌ Exploit the vulnerability maliciously

### Response Timeline

- **Initial Response:** Within 48 hours
- **Status Update:** Within 7 days
- **Fix Target:** Within 30-90 days (depending on severity)

### Hall of Fame

We'll acknowledge security researchers who responsibly disclose vulnerabilities.

---

## Supported Versions

| Version | Status             | Support Until |
| ------- | ------------------ | ------------- |
| 1.0.5   | ✅ Active support  | TBD           |
| 1.0.4   | ⚠️ Limited support | 2025-12-31    |
| 1.0.x   | ✅ Ongoing support | TBD           |
| < 1.0   | ❌ No longer supported | - |

---

## Cryptographic Details

### Encryption Algorithms

**AES-256-GCM:**
- Key size: 256 bits
- IV/Nonce: 12 bytes (randomly generated)
- Authentication: Built-in GCM authentication
- Mode: Authenticated encryption with associated data (AEAD)
- Implementation: Cryptography library (OpenSSL backend)

**RSA-4096:**
- Key size: 4096 bits
- Padding: OAEP (Optimal Asymmetric Encryption Padding)
- Hash: SHA-256
- MGF: MGF1 with SHA-256
- Use: Hybrid encryption key exchange
- Key Format: PEM (Privacy Enhanced Mail)

**PBKDF2:**
- Hash Algorithm: SHA-256
- Iterations: 600,000 (OpenSSL 3.0 default, increased from 480,000 in v1.0.4)
- Salt: 16 bytes (randomly generated)
- Output: 32 bytes (256-bit key)
- RFC Compliance: PKCS #5 v2.0

### Random Number Generation

FileSecureSuite uses `os.urandom()` for cryptographic random number generation, which is:
- Suitable for cryptographic use
- Platform-specific:
  - Linux: `/dev/urandom`
  - Windows: `CryptGenRandom()` via OpenSSL
  - macOS: Kernel secure random number generator
- Non-blocking and entropy-sufficient
- Suitable for generating keys, IVs, and salts

### Hash Functions

- **SHA-256** - Used for key derivation, fingerprinting, and authentication
- **HMAC** - For integrity verification of encrypted data
- **Fingerprint Method** - SHA-256 hash of public key in PEM format

---

## Integrity Verification

### File Integrity

All encrypted files include:
- **Magic Number:** `FSS1` (FileSecureSuite v1 format)
- **Version Byte:** Format version identifier
- **File Hash:** SHA-256 hash of original plaintext
- **Encryption Metadata:** Salt, nonce, key length
- **Ciphertext:** Encrypted data with GCM authentication

### Hash Verification Process

1. Decryption extracts the embedded file hash
2. Decrypted plaintext is hashed with SHA-256
3. Hash is compared using constant-time comparison
4. Mismatch indicates corruption or tampering

### Constant-Time Comparison

Sensitive hash comparisons use `hmac.compare_digest()`:
- Prevents timing attacks
- Takes same time regardless of where bytes match
- Cryptographically secure comparison

---

## Dependencies

FileSecureSuite relies on several libraries. We monitor them for vulnerabilities:

### Required
- **cryptography>=41.0.0** - NIST-approved cryptographic primitives from OpenSSL

### Optional (with graceful fallback)
- **qrcode[pil]>=8.0** - QR code generation
- **colorama>=0.4.6** - Terminal colors
- **pyperclip>=1.8.2** - Clipboard operations

### Removed (no longer required as of v1.0.5)
- **tqdm** - Functionality maintained with native Python

Run `pip install --upgrade -r requirements.txt` regularly to get security updates.

---

## Compliance

### Open Source License

FileSecureSuite is released under the MIT License. See [LICENSE](./LICENSE) file for details.

### Standards & Certifications

FileSecureSuite implements:
- **NIST SP 800-38D** - Galois/Counter Mode (GCM)
- **NIST SP 800-132** - PBKDF2 key derivation
- **RFC 3394** - AES Key Wrap Algorithm
- **PKCS #1 v2.2** - RSA cryptography standard
- **FIPS 180-4** - SHA hash standards

### Enterprise Compliance

Suitable for use in organizations requiring:
- **GDPR** - Data protection (encryption recommended)
- **HIPAA** - Healthcare data security
- **ISO 27001** - Information security management
- **PCI DSS** - Payment card data security
- **SOC 2** - Security controls

### Export Compliance

This software uses cryptographic functions. Some countries may have restrictions on the import, possession, use, and/or re-export of encryption software. Please check your local laws before using or distributing this software.

**United States:** Subject to EAR (Export Administration Regulations) for items on the Commerce Control List.

---

## Security Audit Logging

FileSecureSuite maintains comprehensive audit logs:

### Logged Operations
- File encryption/decryption operations
- Key generation and management
- Key backup and export operations
- Authentication failures
- File access and verification results

### Audit Log Fields
- **Timestamp** - ISO 8601 format
- **Operation** - Type of operation (ENCRYPT, DECRYPT, KEYGEN, BACKUP, etc.)
- **Filepath** - File being operated on
- **Method** - Encryption method used (AES, RSA, etc.)
- **Status** - SUCCESS or FAILED
- **Key Information** - Key name, protection status, fingerprint
- **Error Details** - If operation failed
- **Traceback** - Full exception information for debugging

### Log Location
```
./logs/encryption_audit.log
```

### Viewing Logs
Use the "View Audit Log" option in the main menu to review operations.

---

## Additional Resources

- [Installation Guide](./INSTALLATION_INSTRUCTIONS.md)
- [Quick Start Guide](./QUICKSTART.md)
- [Changelog](./CHANGELOG.md)
- [GPG Documentation](https://www.gnupg.org/documentation/)
- [Python Cryptography Library](https://cryptography.io/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/)

---

## Updates and Announcements

Security updates will be announced via:
- GitHub Releases
- Repository Security Advisories
- Commit messages with `[SECURITY]` tag
- Email notifications (if subscribed)

Subscribe to repository notifications to stay informed.

---

## Version 1.0.5 Security Updates

### New in v1.0.5
- ✅ Enhanced key password validation (12+ chars with complexity requirements)
- ✅ PBKDF2 iterations increased to 600,000 (OpenSSL 3.0 default)
- ✅ Key fingerprint verification system
- ✅ Secure key backup with audit logging
- ✅ Public key export with password protection
- ✅ Exponential backoff on password failure attempts
- ✅ Threading support for non-blocking clipboard operations
- ✅ Improved audit logging with key operation tracking

### Security Best Practices Updated
- Key password requirements strengthened
- Key management operations now fully auditable
- Fingerprint-based key verification enabled
- Backup operations included in audit trail

---

**Last Updated:** 2025-12-02  
**Version:** 1.0.5  
**Status:** Security Review Completed
