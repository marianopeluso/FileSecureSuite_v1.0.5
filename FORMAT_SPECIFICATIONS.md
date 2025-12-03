# File Secure Suite v1.0.5 - Complete Encryption Format Specification

**Version:** 1.0.5  
**Last Updated:** 2025-12-02  
**Status:** Final 
**License:** Open Source (Format Documentation)

---

## Abstract

This document provides complete technical specification for File Secure Suite v1.0.5 hybrid encryption format. It enables independent implementation of decryption tools in any programming language, ensuring encrypted files remain decryptable indefinitely regardless of application availability.

---

## Table of Contents

1. [Overview](#overview)
2. [Encryption Architecture](#encryption-architecture)
3. [Cryptographic Parameters](#cryptographic-parameters)
4. [Key Management](#key-management)
5. [Format Specification](#format-specification)
   - [AES-256-GCM Format](#aes-256-gcm-format)
   - [RSA-4096 Hybrid Format](#rsa-4096-hybrid-format)
6. [Encryption Process](#encryption-process)
7. [Decryption Process](#decryption-process)
8. [Format Detection](#format-detection)
9. [Interoperability](#interoperability)
10. [Implementation Examples](#implementation-examples)
11. [Test Vectors](#test-vectors)

---

## Overview

File Secure Suite uses **hybrid encryption** combining:
- **AES-256-GCM** - Fast symmetric encryption for data (password-based or key-based)
- **RSA-4096 OAEP** - Asymmetric encryption for AES key (public-key infrastructure)

### Use Cases

| Method | Encryption | Decryption | Scenario |
|--------|-----------|-----------|----------|
| **AES-256-GCM (Password)** | Password → PBKDF2 → AES key | Password required | Shared files, text encryption |
| **RSA-4096 Hybrid** | Random AES key + RSA public key | RSA private key required | File sharing with key pairs |

### Key Properties

- ✅ Authenticated encryption (GCM tags prevent tampering)
- ✅ SHA-256 hash for additional integrity verification
- ✅ Deterministic format (fully specified, no ambiguity)
- ✅ OpenSSL-compatible key formats
- ✅ Supports unlimited file sizes
- ✅ Optional filename preservation in encrypted payload

---

## Encryption Architecture

### Password-Based (AES-256-GCM)

```
User Password
    ↓
PBKDF2 (600,000 iterations, SHA-256)
    ↓
AES-256 Key (32 bytes)
    ↓
AES-256-GCM Encryption
    ↓
Encrypted Container (.aes)
```

### Public Key (RSA-4096 Hybrid)

```
Random AES-256 Key
    ├─→ Encrypts file data (AES-256-GCM)
    └─→ Encrypts AES key (RSA-4096 OAEP)
              ↓
        RSA Public Key
              ↓
        Encrypted Container (.rsa)
```

---

## Cryptographic Parameters

### Algorithm Specifications

| Component | Algorithm | Standard | Key/Parameter Details |
|-----------|-----------|----------|----------------------|
| **Symmetric Encryption** | AES-256-GCM | NIST SP 800-38D | 256-bit key, 96-bit nonce |
| **Asymmetric Encryption** | RSA-4096 OAEP | RFC 3447 (PKCS#1 v2.1) | 4096-bit modulus, e=65537 |
| **OAEP Hash** | SHA-256 | FIPS 180-4 | 32-byte output |
| **OAEP MGF** | MGF1-SHA256 | RFC 3447 | Mask generation function |
| **Key Derivation** | PBKDF2-HMAC-SHA256 | NIST SP 800-132 | 600,000 iterations, 16-byte salt |
| **Integrity Hash** | SHA-256 | FIPS 180-4 | 32-byte hash of plaintext |
| **Private Key Format** | PKCS#8 PEM | RFC 5208 | Optionally password-protected |
| **Public Key Format** | X.509 SubjectPublicKeyInfo | RFC 5280 | PEM-encoded |

### Specific Values

```python
# AES Parameters
AES_KEY_SIZE = 32                    # 256 bits
AES_NONCE_SIZE = 12                  # 96 bits (12 bytes)
AES_SALT_SIZE = 16                   # 16 bytes

# RSA Parameters
RSA_KEY_SIZE = 4096                  # 4096 bits
RSA_PADDING = OAEP                   # PKCS#1 v2.1
RSA_PADDING_HASH = SHA256            # For OAEP padding
RSA_OAEP_MGF = MGF1(SHA256)         # Mask generation function

# PBKDF2 Parameters
PBKDF2_ITERATIONS = 600000           # OpenSSL 3.0 default
PBKDF2_HASH = SHA256
PBKDF2_SALT_SIZE = 16

# SHA-256 Hash
SHA256_OUTPUT_SIZE = 32              # 32 bytes (256 bits)

# Container Constraints
MIN_ENCRYPTED_SIZE = 32              # Minimum valid encrypted payload
MAX_FILE_SIZE = 1073741824           # 1 GB (application limit, not format)
```

---

## Key Management

### Private Key (Secret)

**Format:** PKCS#8 PEM (RFC 5208)

```
-----BEGIN PRIVATE KEY-----
MIIJRAIBADANBgkqhkiG9w0BAQEFAASCCSowggkmAgEAAoICAQC7zN8IPTtLBLo...
[Base64-encoded key material]
-----END PRIVATE KEY-----
```

**Properties:**
- Key size: 4096 bits
- Public exponent: 65537 (0x10001)
- Password protection: Optional (PBKDF2-HMAC-SHA256, 600,000 iterations)
- Format: PKCS#8 unencrypted or PKCS#8 encrypted

**Protection:** Must be stored securely. Password protection strongly recommended.

### Public Key (Shareable)

**Format:** X.509 SubjectPublicKeyInfo PEM (RFC 5280)

```
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAu8zfCD07SwS6GlGYzYd...
[Base64-encoded key material]
-----END PUBLIC KEY-----
```

**Properties:**
- Derived from private key
- Contains only public exponent and modulus
- Safe to share openly

### Key Fingerprint

**Calculation:** SHA-256(public key PEM) → first 16 hex characters

**Purpose:** Identify keys, verify key authenticity, prevent accidental misuse

**Example:**
```
Public Key: -----BEGIN PUBLIC KEY-----...
SHA256: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6...
Fingerprint (first 16 chars): A1B2C3D4E5F6A7B8
```

---

## Format Specification

### Magic Header & Version

All encrypted containers start with:

| Offset | Size | Field | Value | Description |
|--------|------|-------|-------|-------------|
| 0 | 4 | Magic | `FSS1` | ASCII string "FSS1" (0x46 0x53 0x53 0x31) |
| 4 | 1 | Version | 0x01 | Format version 1 |

---

## AES-256-GCM Format

### Use Case
- Password-protected file encryption
- Text encryption with password
- Faster encryption/decryption (no RSA overhead)

### Binary Structure

```
Offset  Size  Field              Description
──────  ────  ─────────────────  ──────────────────────────────────
0       4     Magic              FSS1
4       1     Version            0x01
5       4     Hash Length        0x00000020 (32 bytes, big-endian)
9       32    File Hash          SHA-256(plaintext)
41      16    Salt               Random salt for PBKDF2
57      12    Nonce              Random nonce for AES-GCM
69      N     Ciphertext         AES-256-GCM encrypted data
```

### Total Minimum Size
```
4 (magic) + 1 (version) + 4 (hash_len) + 32 (hash) + 16 (salt) + 12 (nonce) + 1 (min ciphertext)
= 70 bytes minimum
```

### Detailed Encryption (AES with Password)

**Input:**
- `plaintext`: File content or text (any length)
- `password`: User-provided password (8-128 characters)

**Process:**

```
1. Generate random salt (16 bytes)

2. Derive AES key from password:
   key = PBKDF2-HMAC-SHA256(
       password=password.encode('utf-8'),
       salt=salt,
       iterations=600000,
       dklen=32
   )

3. Compute integrity hash:
   hash = SHA256(plaintext)

4. Generate random nonce (12 bytes)

5. Encrypt with AES-256-GCM:
   ciphertext, tag = AES-GCM-Encrypt(
       key=key,
       nonce=nonce,
       plaintext=plaintext,
       aad=None
   )
   Note: GCM tag is appended to ciphertext

6. Build container:
   container = b'FSS1'                    # Magic (4 bytes)
             + b'\x01'                    # Version (1 byte)
             + len(hash).to_bytes(4, 'big')  # Hash length = 32 (4 bytes)
             + hash                        # File hash (32 bytes)
             + salt                        # PBKDF2 salt (16 bytes)
             + nonce                       # GCM nonce (12 bytes)
             + ciphertext_with_tag        # Encrypted data + GCM tag
```

### Decryption (AES with Password)

**Input:**
- `container`: Encrypted bytes
- `password`: User password

**Process:**

```
1. Parse container:
   magic = container[0:4]                 # Should be b'FSS1'
   version = container[4]                 # Should be 0x01
   hash_len = struct.unpack('>I', container[5:9])[0]  # Should be 32
   file_hash = container[9:9+hash_len]    # 32 bytes
   salt = container[9+hash_len:9+hash_len+16]         # 16 bytes
   nonce = container[9+hash_len+16:9+hash_len+28]     # 12 bytes
   ciphertext_with_tag = container[9+hash_len+28:]    # Remaining

2. Derive AES key from password and salt:
   key = PBKDF2-HMAC-SHA256(
       password=password.encode('utf-8'),
       salt=salt,
       iterations=600000,
       dklen=32
   )

3. Decrypt with AES-256-GCM:
   cipher = AES-GCM(key)
   plaintext = cipher.decrypt(nonce, ciphertext_with_tag)
   (GCM automatically verifies tag; raises exception if invalid)

4. Verify file integrity:
   computed_hash = SHA256(plaintext)
   assert computed_hash == file_hash, "Integrity verification failed"

5. Return plaintext
```

---

## RSA-4096 Hybrid Format

### Use Case
- Asymmetric encryption with public/private key pairs
- Secure key sharing without pre-shared password
- File encryption for specific recipients

### Binary Structure

```
Offset  Size  Field                 Description
──────  ────  ───────────────────   ──────────────────────────────────
0       4     Magic                 FSS1
4       1     Version               0x01
5       4     Hash Length           0x00000020 (32 bytes, big-endian)
9       32    File Hash             SHA-256(plaintext)
41      2     Key Length            RSA encrypted key size (big-endian)
43      N     Encrypted AES Key     RSA-OAEP encrypted AES key
43+N    16    Salt                  Random salt (for potential use)
59+N    12    Nonce                 Random nonce for AES-GCM
71+N    M     Ciphertext            AES-256-GCM encrypted data
```

### Total Minimum Size
```
4 (magic) + 1 (version) + 4 (hash_len) + 32 (hash) + 2 (key_len) + 512 (min RSA key) + 16 (salt) + 12 (nonce) + 1 (min ciphertext)
= 584 bytes minimum
```

### Detailed Encryption (RSA Hybrid)

**Input:**
- `plaintext`: File content or text (any length)
- `public_key_pem`: RSA-4096 public key in PEM format

**Process:**

```
1. Generate random AES-256 key (32 bytes)
   aes_key = os.urandom(32)

2. Generate random salt (16 bytes)
   salt = os.urandom(16)

3. Compute integrity hash:
   hash = SHA256(plaintext)

4. Generate random nonce (12 bytes)
   nonce = os.urandom(12)

5. Encrypt plaintext with AES-256-GCM:
   cipher = AES-GCM(aes_key)
   ciphertext_with_tag = cipher.encrypt(nonce, plaintext)

6. Encrypt AES key with RSA-4096 OAEP:
   encrypted_aes_key = RSA-OAEP-Encrypt(
       public_key=public_key_pem,
       plaintext=aes_key,
       hash_algorithm=SHA256,
       mgf=MGF1(SHA256)
   )

7. Build container:
   key_len = len(encrypted_aes_key).to_bytes(2, 'big')
   container = b'FSS1'                    # Magic (4 bytes)
             + b'\x01'                    # Version (1 byte)
             + len(hash).to_bytes(4, 'big')  # Hash length = 32 (4 bytes)
             + hash                        # File hash (32 bytes)
             + key_len                     # RSA key length (2 bytes)
             + encrypted_aes_key           # RSA-encrypted AES key
             + salt                        # Random salt (16 bytes)
             + nonce                       # GCM nonce (12 bytes)
             + ciphertext_with_tag        # Encrypted data + GCM tag
```

### Decryption (RSA Hybrid)

**Input:**
- `container`: Encrypted bytes
- `private_key_pem`: RSA-4096 private key in PEM format
- `private_key_password`: Optional password for encrypted private key

**Process:**

```
1. Parse container:
   magic = container[0:4]                 # Should be b'FSS1'
   version = container[4]                 # Should be 0x01
   hash_len = struct.unpack('>I', container[5:9])[0]  # Should be 32
   file_hash = container[9:9+hash_len]    # 32 bytes
   key_len = struct.unpack('>H', container[41:43])[0] # RSA key size
   encrypted_aes_key = container[43:43+key_len]
   salt = container[43+key_len:43+key_len+16]         # 16 bytes
   nonce = container[43+key_len+16:43+key_len+28]     # 12 bytes
   ciphertext_with_tag = container[43+key_len+28:]

2. Load and decrypt private key (if password-protected):
   private_key = Load-PEM-Private-Key(
       private_key_pem,
       password=private_key_password.encode() if password else None
   )

3. Decrypt AES key with RSA-4096 OAEP:
   aes_key = RSA-OAEP-Decrypt(
       private_key=private_key,
       ciphertext=encrypted_aes_key,
       hash_algorithm=SHA256,
       mgf=MGF1(SHA256)
   )

4. Decrypt file with AES-256-GCM:
   cipher = AES-GCM(aes_key)
   plaintext = cipher.decrypt(nonce, ciphertext_with_tag)

5. Verify file integrity:
   computed_hash = SHA256(plaintext)
   assert computed_hash == file_hash, "Integrity verification failed"

6. Return plaintext
```

---

## Format Detection

### Automatic Format Detection

When a file is decrypted, the application automatically determines whether it's AES-256-GCM or RSA-4096 format:

**Algorithm:**

```
1. Read first 41 bytes to get:
   - Magic (4 bytes): Must be b'FSS1'
   - Version (1 byte): Must be 0x01
   - Hash length (4 bytes): Must be 32 (0x00000020)
   - File hash (32 bytes)

2. Parse bytes 41-42 as big-endian integer:
   key_length_bytes = container[41:43]
   potential_key_len = struct.unpack('>H', key_length_bytes)[0]

3. Check if key_length is valid RSA range (100-1024 bytes):
   if 100 <= potential_key_len <= 1024:
       Format = RSA-4096 Hybrid
   else:
       Format = AES-256-GCM (bytes 41-42 are random)

4. Optional: Use file extension as hint (before magic header check):
   - .aes, .aes.b64 → Assume AES-256-GCM
   - .rsa, .rsa.b64 → Assume RSA-4096 Hybrid
```

### Example Detection Logic (Python)

```python
def detect_format(encrypted_bytes):
    """Detect encryption format from first 43 bytes"""
    
    if len(encrypted_bytes) < 43:
        raise ValueError("File too short to be valid encrypted container")
    
    # Check magic and version
    magic = encrypted_bytes[0:4]
    if magic != b'FSS1':
        raise ValueError("Invalid magic header")
    
    version = encrypted_bytes[4]
    if version != 0x01:
        raise ValueError(f"Unsupported version: {version}")
    
    hash_len = struct.unpack('>I', encrypted_bytes[5:9])[0]
    if hash_len != 32:
        raise ValueError(f"Invalid hash length: {hash_len}")
    
    # Parse potential key length at offset 41-42
    key_len_bytes = encrypted_bytes[41:43]
    key_len = struct.unpack('>H', key_len_bytes)[0]
    
    # RSA encrypted keys are typically 256-512 bytes (depends on RSA key size)
    # AES format has random bytes here, unlikely to be in this range
    if 100 <= key_len <= 1024:
        return "RSA"  # RSA-4096 format
    else:
        return "AES"  # AES-256-GCM format
```

---

## Interoperability

### Cross-Platform Support

The format is **platform-agnostic** and can be implemented in any language:

- **Windows, macOS, Linux:** Binary format identical
- **Big-Endian Systems:** Format uses big-endian integers; systems must byte-swap appropriately
- **Encryption Libraries:** Standard algorithms; use any NIST-approved implementation

### Language Implementations

**Python:**
```python
import os
import struct
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
```

**Go:**
```go
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rsa"
    "crypto/sha256"
    "golang.org/x/crypto/pbkdf2"
)
```

**Rust:**
```rust
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rsa::{RsaPrivateKey, Padding};
use sha2::{Sha256, Digest};
use pbkdf2::pbkdf2;
```

---

## Implementation Examples

### Python Implementation (AES Decryption)

```python
def decrypt_aes_file(encrypted_bytes, password):
    """Decrypt AES-256-GCM encrypted file"""
    
    # Parse container
    magic = encrypted_bytes[0:4]
    assert magic == b'FSS1', "Invalid magic header"
    
    version = encrypted_bytes[4]
    assert version == 0x01, "Unsupported version"
    
    hash_len = struct.unpack('>I', encrypted_bytes[5:9])[0]
    assert hash_len == 32, "Invalid hash length"
    
    expected_hash = encrypted_bytes[9:41]
    salt = encrypted_bytes[41:57]
    nonce = encrypted_bytes[57:69]
    ciphertext_with_tag = encrypted_bytes[69:]
    
    # Derive key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = kdf.derive(password.encode('utf-8'))
    
    # Decrypt with AES-256-GCM
    cipher = AESGCM(key)
    plaintext = cipher.decrypt(nonce, ciphertext_with_tag, None)
    
    # Verify integrity
    computed_hash = hashlib.sha256(plaintext).digest()
    assert computed_hash == expected_hash, "Integrity verification failed"
    
    return plaintext


def decrypt_rsa_file(encrypted_bytes, private_key_pem, password=None):
    """Decrypt RSA-4096 hybrid encrypted file"""
    
    # Parse container
    magic = encrypted_bytes[0:4]
    assert magic == b'FSS1', "Invalid magic header"
    
    version = encrypted_bytes[4]
    assert version == 0x01, "Unsupported version"
    
    hash_len = struct.unpack('>I', encrypted_bytes[5:9])[0]
    assert hash_len == 32, "Invalid hash length"
    
    expected_hash = encrypted_bytes[9:41]
    
    key_len = struct.unpack('>H', encrypted_bytes[41:43])[0]
    encrypted_aes_key = encrypted_bytes[43:43+key_len]
    
    salt = encrypted_bytes[43+key_len:43+key_len+16]
    nonce = encrypted_bytes[43+key_len+16:43+key_len+28]
    ciphertext_with_tag = encrypted_bytes[43+key_len+28:]
    
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem,
        password=password.encode('utf-8') if password else None,
    )
    
    # Decrypt AES key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt file
    cipher = AESGCM(aes_key)
    plaintext = cipher.decrypt(nonce, ciphertext_with_tag, None)
    
    # Verify hash
    import hashlib
    computed_hash = hashlib.sha256(plaintext).digest()
    assert computed_hash == expected_hash, "Integrity verification failed"
    
    return plaintext
```

### Rust Implementation (Conceptual)

```rust
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rsa::{RsaPrivateKey, Padding};
use sha2::{Sha256, Digest};
use pbkdf2::pbkdf2;

const PBKDF2_ITERATIONS: u32 = 600000;

fn decrypt_aes_file(encrypted: &[u8], password: &str) -> Result<Vec<u8>> {
    // Parse container
    assert_eq!(&encrypted[0..4], b"FSS1");
    assert_eq!(encrypted[4], 0x01);
    
    let hash_len = u32::from_be_bytes([
        encrypted[5], encrypted[6], encrypted[7], encrypted[8]
    ]) as usize;
    assert_eq!(hash_len, 32);
    
    let expected_hash = &encrypted[9..41];
    let salt = &encrypted[41..57];
    let nonce = &encrypted[57..69];
    let ciphertext = &encrypted[69..];
    
    // Derive key using PBKDF2
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut key,
    );
    
    // Decrypt
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from(key));
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext)?;
    
    // Verify hash
    let mut hasher = Sha256::new();
    hasher.update(&plaintext);
    let computed_hash = hasher.finalize();
    
    assert_eq!(&computed_hash[..], expected_hash);
    Ok(plaintext)
}
```

---

## Filename Embedding Specification

### Overview

FileSecureSuite preserves original filenames inside encrypted files for recovery during decryption. This ensures users can identify files without relying on external metadata.

### Technical Details

**Embedding Method:**

The original filename is embedded directly in the plaintext before encryption:

```
Data structure BEFORE encryption:
┌──────────────────────────┬────┬──────────────────┐
│ Original Filename (UTF-8) │ 0x00 │ File Content     │
└──────────────────────────┴────┴──────────────────┘
                            ↓
                    Prepended to plaintext
```

**Example:**

```
Filename: "document.txt"
File content: "Important data..."

Data to encrypt:
document.txt<0x00>Important data...
```

### Hash Computation

**Critical:** The SHA-256 hash is computed on **both filename and content**:

```python
data_to_hash = filename.encode('utf-8') + b'\x00' + file_content
file_hash = SHA256(data_to_hash)
```

This ensures:
- Filename tampering is detected
- Hash verification confirms both filename and content integrity
- Recovery during decryption is validated

### Decryption and Recovery

When decrypting, the process is:

```python
1. Decrypt using password or RSA key
2. Locate null byte (0x00) separator
3. Split at separator:
   - Before 0x00 = original filename
   - After 0x00 = file content
4. Verify SHA-256 hash on combined data
5. Write recovered file with original name
```

### Null Byte Handling

**Important:** The null byte (0x00) is a **separator**, not part of the filename:

```python
null_index = decrypted_data.find(b'\x00')
filename = decrypted_data[:null_index].decode('utf-8')  # Doesn't include 0x00
content = decrypted_data[null_index+1:]                   # Starts after 0x00
```

### UTF-8 Encoding

Filenames are encoded as UTF-8:
- Supports international characters (Chinese, Arabic, etc.)
- Decoded to string for display/recovery
- Maximum filename length depends on file system (typically 255 bytes on ext4/NTFS)

### Examples

**Example 1: Simple filename**
```
Filename: "report.pdf"
Hex: 7265706f72742e706466 00
     (r e p o r t . p d f) (null)
```

**Example 2: Unicode filename**
```
Filename: "文档.txt" (Chinese: "document.txt")
Hex: e6 96 87 e6 a1 a3 2e 74 78 74 00
     (UTF-8 for 文档.txt) (null)
```

**Example 3: Filename with spaces**
```
Filename: "my file.docx"
Hex: 6d 79 20 66 69 6c 65 2e 64 6f 63 78 00
     (m y   f i l e . d o c x) (null)
```

---

## Test Vectors

### Test Vector 1: AES-256-GCM Encryption (Verified)

**Input:**
```
Plaintext: "Hello, World!"
Password: "test_password_12345"
```

**Computed Hash (SHA-256):**
```
dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
```

**Actual Encrypted Output (Hex):**
```
465353310100000020dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f90a405e30f68c27b490b63cfa9139fdc3db2bb6cab3b04b13e78a77e24e61ca0a37dc6adf519e3d35405d44ff8ed55762bb9640d076097e357
```

**Parsed Structure:**
```
Offset 0-3:     46 53 53 31            (Magic: FSS1)
Offset 4:       01                     (Version: 1)
Offset 5-8:     00 00 00 20            (Hash length: 32 in big-endian)
Offset 9-40:    dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f (SHA256)
Offset 41-56:   90a405e30f68c27b490b63cfa9139fdc (16-byte random salt)
Offset 57-68:   3db2bb6cab3b04b13e78a77e (12-byte random nonce)
Offset 69+:     24e61ca0a37dc6adf519e3d35405d44ff8ed55762bb9640d076097e357 (AES-GCM ciphertext + tag)

Total Length: 98 bytes
```

**Verification:**
```python
# Decryption with password "test_password_12345"
Decrypted plaintext: b"Hello, World!"
Hash match: ✓ VERIFIED
Decryption successful: ✓ VERIFIED
```

---

### Test Vector 2: RSA-4096 Hybrid Encryption (Verified)

**Input:**
```
Plaintext: "Sensitive document"
RSA-4096 Public Key: [PKCS#8 PEM, 4096-bit]
```

**Computed Hash (SHA-256):**
```
e7ce11eed0303fc8690bcc07828db0e8726835d0688e96a0e2fa75f6fda5343e
```

**Actual Encrypted Output (Hex, truncated):**
```
465353310100000020e7ce11eed0303fc8690bcc07828db0e8726835d0688e96a0e2fa75f6fda5343e
0200 [373 bytes of RSA OAEP encrypted AES key]
3758c3575e8cef97b7ba8fafdc381ee7 (16-byte salt)
1693c79fb6a020e50a765776 (12-byte nonce)
[AES-GCM ciphertext + tag]
```

**Parsed Structure:**
```
Offset 0-3:     46 53 53 31            (Magic: FSS1)
Offset 4:       01                     (Version: 1)
Offset 5-8:     00 00 00 20            (Hash length: 32)
Offset 9-40:    e7ce11eed0303fc8690bcc07828db0e8726835d0688e96a0e2fa75f6fda5343e (SHA256)
Offset 41-42:   02 00                  (RSA key length: 512 bytes in big-endian)
Offset 43-554:  [512-byte RSA-4096 OAEP encrypted AES-256 key]
Offset 555-570: 3758c3575e8cef97b7ba8fafdc381ee7 (16-byte salt)
Offset 571-582: 1693c79fb6a020e50a765776 (12-byte nonce)
Offset 583+:    [AES-GCM encrypted plaintext + tag]

Total Length: 617 bytes
```

**Verification:**
```python
# Decryption with RSA-4096 private key
Decrypted plaintext: b"Sensitive document"
Hash match: ✓ VERIFIED
Decryption successful: ✓ VERIFIED
```

---

### Test Vector 3: Filename Embedding (Verified)

**Important:** FileSecureSuite embeds original filenames inside encrypted files for recovery during decryption.

**Input:**
```
Original filename: "document.txt"
File content: "This is a test document."
Password: "file_password_123"
```

**Data Structure (Before Encryption):**
```
filename_with_separator = b"document.txt\x00"
data_with_filename = b"document.txt\x00This is a test document."
```

**Hex Representation:**
```
646f63756d656e742e74787400546869732069732061207465737420646f63756d656e742e
│                  └─ 0x00 (null separator)
└─ "document.txt"    "This is a test document."
```

**Hash Computed On:**
```
SHA256(filename + 0x00 + content)
= SHA256(b"document.txt\x00This is a test document.")
= 971756d75849dfd72b6d56cab8a2fbd41cd015c93adbc6fa1691287048451d02
```

**Encrypted Container (AES-256-GCM):**
```
Total Length: 122 bytes
Ciphertext (first 50 hex chars): 
c7879d61927dcd7de43aab06055c577aaf1b17fce73c0113c0123c3dfdc670c2...
```

**Recovery During Decryption:**
```python
# After decrypting:
decrypted_data = b"document.txt\x00This is a test document."

# Split at null separator:
null_index = decrypted_data.find(b'\x00')
recovered_filename = decrypted_data[:null_index].decode('utf-8')     # "document.txt"
recovered_content = decrypted_data[null_index+1:]                     # "This is a test document."

# Results:
Recovered filename: "document.txt" ✓ VERIFIED
Recovered content: "This is a test document." ✓ VERIFIED
Hash verification: ✓ VERIFIED
```

---

### Test Vector 4: Format Detection

**Scenario 1: Extension-based Detection**
```
Filename: "document.rsa"
Result: Format = RSA (from .rsa extension)
```

**Scenario 2: Magic Header Analysis (AES)**
```
File Header (first 50 bytes):
46 53 53 31 01 00 00 00 20 [32-byte hash] 
7f 3e 8c 2a [random bytes]

Parse bytes 41-42 as key length (big-endian):
key_len = 0x7f3e = 32,830 (decimal)

Range check: 100 <= 32830 <= 1024? NO
Result: Format = AES (random bytes outside RSA range)
```

**Scenario 3: Magic Header Analysis (RSA)**
```
File Header (first 50 bytes):
46 53 53 31 01 00 00 00 20 [32-byte hash]
02 00 [RSA encrypted key...]

Parse bytes 41-42 as key length (big-endian):
key_len = 0x0200 = 512 (decimal)

Range check: 100 <= 512 <= 1024? YES
Result: Format = RSA (key length in expected range)
```

---

## Implementation Checklist

This section provides a checklist for developers implementing independent FileSecureSuite decryption tools.

### Basic Structure Parsing

- [ ] Read and verify magic header (must be `b'FSS1'`)
- [ ] Read and verify version byte (must be 0x01)
- [ ] Read hash length as big-endian 32-bit integer (must be 32)
- [ ] Validate minimum encrypted size (at least 70 bytes for AES, 584 for RSA)

### Format Detection

- [ ] Attempt to read 2-byte key length at offset 41-42
- [ ] If key_length is 100-1024: Process as RSA-4096 Hybrid
- [ ] If key_length is random/outside range: Process as AES-256-GCM
- [ ] Optional: Check file extension (.aes, .rsa) as hint

### AES-256-GCM Decryption

- [ ] Extract file hash (32 bytes at offset 9-40)
- [ ] Extract salt (16 bytes at offset 41-56)
- [ ] Extract nonce (12 bytes at offset 57-68)
- [ ] Extract ciphertext+tag (remaining bytes from offset 69+)
- [ ] Implement PBKDF2-HMAC-SHA256 with 600,000 iterations
- [ ] Derive 32-byte AES key from password + salt
- [ ] Use AES-256-GCM to decrypt ciphertext with nonce
- [ ] Compute SHA256 hash of decrypted data
- [ ] Verify computed hash matches embedded hash (use constant-time comparison)
- [ ] Extract filename: split at first null byte (0x00)
- [ ] Decode filename as UTF-8

### RSA-4096 Hybrid Decryption

- [ ] Extract file hash (32 bytes at offset 9-40)
- [ ] Extract RSA key length (2 bytes at offset 41-42, big-endian)
- [ ] Validate key length (100-1024 bytes)
- [ ] Extract encrypted AES key (key_length bytes starting at offset 43)
- [ ] Extract salt (16 bytes)
- [ ] Extract nonce (12 bytes)
- [ ] Extract ciphertext+tag (remaining bytes)
- [ ] Load RSA-4096 private key (PKCS#8 PEM format)
- [ ] Handle password-protected private keys
- [ ] Decrypt AES key using RSA-4096 OAEP with SHA-256 hash and MGF1
- [ ] Use AES-256-GCM with decrypted key and nonce to decrypt ciphertext
- [ ] Compute SHA256 hash of decrypted data
- [ ] Verify computed hash matches embedded hash (constant-time comparison)
- [ ] Extract filename: split at first null byte (0x00)
- [ ] Decode filename as UTF-8

### Hash Verification

- [ ] **Important:** Hash includes filename + null byte + content
  ```
  hash_input = filename.encode('utf-8') + b'\x00' + file_content
  computed_hash = SHA256(hash_input)
  ```
- [ ] Use constant-time comparison (e.g., `hmac.compare_digest()` in Python)
- [ ] Fail decryption if hash doesn't match
- [ ] Report "Integrity verification failed" if mismatch

### Filename Recovery

- [ ] Find first occurrence of 0x00 byte in decrypted data
- [ ] If no 0x00 found: entire data is content (no filename embedded)
- [ ] If 0x00 found:
  - [ ] Extract bytes before 0x00 as filename (UTF-8 encoded)
  - [ ] Extract bytes after 0x00 as file content
- [ ] Decode filename UTF-8 with error handling (use replacement character for invalid bytes)
- [ ] Sanitize filename for file system (remove path separators, etc.)
- [ ] Write decrypted content to file system with recovered filename

### Error Handling

- [ ] Handle invalid magic header with clear error message
- [ ] Handle unsupported version with clear error message
- [ ] Handle invalid hash length with clear error message
- [ ] Handle decryption failures (wrong password/key)
- [ ] Handle AES-GCM authentication tag failures
- [ ] Handle RSA decryption failures
- [ ] Handle SHA256 hash verification failures
- [ ] Provide user-friendly error messages
- [ ] Log all errors for debugging

### Testing Recommendations

- [ ] Test with Test Vector 1 (AES-256-GCM)
- [ ] Test with Test Vector 2 (RSA-4096 Hybrid)
- [ ] Test with Test Vector 3 (Filename embedding)
- [ ] Test with files of various sizes (small, medium, large)
- [ ] Test with different filenames (ASCII, UTF-8 with unicode)
- [ ] Test with wrong passwords/keys
- [ ] Test with corrupted encrypted files
- [ ] Cross-test with official FileSecureSuite application
- [ ] Test on multiple platforms (Windows, Linux, macOS)

### Security Checklist

- [ ] Use constant-time hash comparison (prevent timing attacks)
- [ ] Clear sensitive data from memory after use (passwords, keys, plaintext)
- [ ] Use cryptographically secure random number generators (if implementing encryption)
- [ ] Validate all inputs (file sizes, key lengths, etc.)
- [ ] Use TLS when transmitting encrypted files
- [ ] Store private keys with password protection (PBKDF2)
- [ ] Document security assumptions and limitations
- [ ] Keep cryptography library updated

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| **Passive eavesdropping** | AES-256-GCM encryption |
| **File tampering** | SHA-256 + AESGCM authentication tags |
| **Replay attacks** | Random nonce per encryption; not applicable to static files |
| **Key recovery** | RSA-4096; no practical attacks known |
| **Brute-force password** | PBKDF2 with 600,000 iterations (2+ seconds per attempt) |
| **Side-channel attacks on decryption** | Constant-time comparison for hash verification |

### Best Practices

1. **Use strong passwords:** Minimum 8 characters with mixed case, numbers, symbols
2. **Protect private keys:** Store with password protection (PBKDF2)
3. **Share public keys safely:** Verify key fingerprint before use
4. **Regenerate keys periodically:** Create new keypairs every 2-3 years
5. **Backup encrypted:** Keep backup copies of private keys in secure locations

---

## Algorithm Strength Assessment

| Algorithm | Status | Timeline |
|-----------|--------|----------|
| **AES-256** | ✅ Secure | Approved indefinitely by NIST; NSA Suite B successor |
| **RSA-4096** | ✅ Secure | NIST-approved until 2030+ for confidentiality |
| **SHA-256** | ✅ Secure | No practical attacks; NIST-approved |
| **PBKDF2** | ⚠️ Adequate | Adequate for passwords; Argon2 recommended for new designs |

**Longevity:** Format remains secure for files encrypted today and decryptable for 20+ years with high confidence.

---

## Future Extensions

### Version 2 Considerations (Not Implemented)

Potential enhancements for future versions:

- **Authenticated encryption:** Add per-message authentication (currently per-file)
- **Key derivation:** Support Argon2 for password-based encryption
- **Compression:** Optional built-in compression before encryption
- **Streaming:** Support streaming decryption for large files
- **Forward secrecy:** Ephemeral key agreement (hybrid with X25519)

**Backward Compatibility:** Version field (currently 0x01) allows safe extension without breaking existing files.

---

## References

### Standards & Specifications

1. **NIST SP 800-38D** - Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
2. **RFC 3447** - PKCS #1: RSA Cryptography Specifications Version 2.1
3. **RFC 5208** - PKCS #8: Private-Key Information Syntax Specification
4. **RFC 5280** - Internet X.509 Public Key Infrastructure Certificate and CRL Profile
5. **NIST SP 800-132** - Password-Based Key Derivation (PBKDF2)
6. **FIPS 180-4** - Secure Hash Standard (SHA and SHA-3)
7. **FIPS 197** - Advanced Encryption Standard (AES)

### Libraries

- **Python:** `cryptography >= 3.4` https://cryptography.io/
- **Go:** `crypto/aes`, `crypto/rsa`, `golang.org/x/crypto/pbkdf2`
- **Rust:** `aes-gcm`, `rsa`, `sha2`, `pbkdf2`
- **Node.js:** `crypto`, `node-rsa`, `bcrypt`

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.5 | 2025-12-02 | FileSecureSuite Project | Added real test vectors (verified with actual encryption), filename embedding specification, and implementation checklist |
| 1.0 | 2024-12-02 | FileSecureSuite Project | Complete specification for v1.0 |

---

## License

The File Secure Suite application is open source and available under the [MIT License](https://opensource.org/licenses/MIT).

---

**Status:** Final - Ready for Implementation  
**Last Updated:** 2025-12-02  
**Specification Version:** 1.0.5
