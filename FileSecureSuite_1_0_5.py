#!/usr/bin/env python3
"""
File Secure Suite v1.0.5 - Enterprise Encryption Suite
Secure file and text encryption with AES-256-GCM and RSA-4096
OpenSSL compatible encryption using PBKDF2 key derivation
"""

import os
import sys
import getpass
import time
import threading
import hashlib
import hmac
import struct
import random
import base64
import datetime
import traceback
import tempfile
from pathlib import Path
import platform
from typing import Tuple, Optional

try:
    import qrcode
    from PIL import Image
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

os.umask(0o077)  # Only owner can read/write files
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = ""
    class Style:
        BRIGHT = RESET_ALL = ""

try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False


def verify_hash_constant_time(stored_hash_hex: str, computed_hash_hex: str) -> bool:
    stored_bytes = bytes.fromhex(stored_hash_hex)
    computed_bytes = bytes.fromhex(computed_hash_hex)
    return hmac.compare_digest(stored_bytes, computed_bytes)


def clear_clipboard_after(timeout: int):
    """Clear clipboard after specified timeout (seconds) in background"""
    time.sleep(timeout)
    try:
        if HAS_PYPERCLIP:
            import pyperclip
            pyperclip.copy('')
    except Exception:
        pass


def log_exception(operation: str, filepath: str, method: str, exception: Exception):
    tb_str = traceback.format_exc()[:1000]
    log_operation(operation, filepath, method, "FAILED", error=str(exception), traceback_str=tb_str)


def color_success(text):
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def color_error(text):
    return f"{Fore.RED}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def color_warning(text):
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def color_info(text):
    return f"{Fore.CYAN}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def color_bright(text):
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text


IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'encryption_audit.log')
KEYS_DIR = os.path.join(BASE_DIR, 'keys')
BACKUP_DIR = os.path.join(BASE_DIR, 'backup')
PBKDF2_ITERATIONS = 600000  # OpenSSL 3.0 default
PBKDF2_HASH_ALGORITHM = hashes.SHA256()
AES_KEY_SIZE = 32  # 256 bits
RSA_KEY_SIZE = 4096
MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024
CLIPBOARD_CLEAR_TIMEOUT = 30
MIN_ENCRYPTED_SIZE = 32


def ensure_log_dir():
    try:
        os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)  # Only owner can access
        os.chmod(LOG_DIR, 0o700)  # Ensure permissions even if dir existed
    except Exception as e:
        print(color_warning(f"⚠️  Log directory error: {e}"))


def ensure_keys_dir():
    """Create keys directory with restricted permissions (700)"""
    try:
        os.makedirs(KEYS_DIR, mode=0o700, exist_ok=True)  # Only owner can access
        os.chmod(KEYS_DIR, 0o700)  # Ensure permissions even if dir existed
    except Exception as e:
        print(color_warning(f"⚠️  Keys directory error: {e}"))


def ensure_backup_dir():
    """Create backup directory with restricted permissions (700)"""
    try:
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)  # Only owner can access
        os.chmod(BACKUP_DIR, 0o700)  # Ensure permissions even if dir existed
    except Exception as e:
        print(color_warning(f"⚠️  Backup directory error: {e}"))



def log_operation(operation: str, filepath: str, method: str, status: str, 
                  file_hash: str = "", error: str = "", additional: str = "", traceback_str: str = "",
                  keyname: str = "", key_protected: bool = False, 
                  key_fingerprint: str = ""):
    ensure_log_dir()
    try:
        timestamp = datetime.datetime.now().isoformat()
        basename = os.path.basename(filepath)
        log_entry = f"[{timestamp}] {operation:15} | file: {basename:40} | method: {method:5} | status: {status:15}"
        
        if keyname:
            log_entry += f" | keyname: {keyname}"
        if key_protected:
            log_entry += f" | key_protected: YES"
        if key_fingerprint:
            log_entry += f" | key_fingerprint: {key_fingerprint}"
        if file_hash:
            log_entry += f" | hash: {file_hash[:16]}..."
        if additional:
            log_entry += f" | {additional}"
        if error:
            log_entry += f" | error: {error}"
        if traceback_str:
            log_entry += f" | traceback: {traceback_str[:500]}"
        
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry + '\n')
            f.flush()
            try:
                os.fsync(f.fileno())
            except (AttributeError, OSError):
                pass
        try:
            os.chmod(LOG_FILE, 0o600)
        except (AttributeError, OSError):
            pass
    except Exception as e:
        print(color_warning(f"⚠️  Audit log error: {e}"))


def get_audit_log() -> Optional[str]:
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                return f.read()
    except Exception as e:
        print(color_warning(f"⚠️  Cannot read log: {e}"))
    return None


def safe_input(prompt: str, password: bool = False) -> Optional[str]:
    try:
        if password:
            result = getpass.getpass(prompt)
        else:
            result = input(prompt).strip()
        
        return result if result else None
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled.")
        return None
    except EOFError:
        return None


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def clean_path(path: str) -> str:
    if not path:
        return path
    path = path.strip().strip('"\'').replace('"', '').replace("'", '')
    return path


def validate_password_strength(password: str) -> Tuple[bool, str]:
    if not password:
        return False, "Password cannot be empty"
    if len(password) < 8:
        return False, "Password too short (minimum 8 characters)"
    if len(password) > 128:
        return False, "Password too long (maximum 128 characters)"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    score = sum([has_upper, has_lower, has_digit, has_special])
    
    if score < 2:
        return False, "Password too weak (need uppercase, lowercase, digit, or special char)"
    return True, "Password strength: OK"


def validate_password_strength_key(password: str) -> Tuple[bool, str]:
    """Stricter validation for RSA key protection (12+ chars, number, uppercase, symbol required)"""
    if not password:
        return False, "Password cannot be empty"
    if len(password) < 12:
        return False, "Key password too short (minimum 12 characters)"
    if len(password) > 128:
        return False, "Password too long (maximum 128 characters)"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    # For keys: ALL requirements must be met
    if not has_upper:
        return False, "Key password must contain uppercase letter (A-Z)"
    if not has_lower:
        return False, "Key password must contain lowercase letter (a-z)"
    if not has_digit:
        return False, "Key password must contain digit (0-9)"
    if not has_special:
        return False, "Key password must contain special character (!@#$%^&*...)"
    
    return True, "Key password strength: STRONG ✅"


def calculate_file_hash(filepath: str, chunk_size: int = 8192) -> str:
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(color_error(f"❌ Hash error: {e}"))
        return ""


def sanitize_filename(filepath: str) -> str:
    basename = os.path.basename(filepath)
    basename = basename.replace('/', '_').replace('\\', '_').replace('..', '_')
    basename = ''.join(c if ord(c) >= 32 and ord(c) < 127 and c not in '<>:"|?*' else '_' 
                       for c in basename)
    return basename


def validate_output_path(filepath: str, base_dir: str = BASE_DIR) -> str:
    abs_filepath = os.path.abspath(filepath)
    abs_base_dir = os.path.abspath(base_dir)
    try:
        common_path = os.path.commonpath([abs_base_dir, abs_filepath])
        if common_path != abs_base_dir:
            raise ValueError(f"Path outside allowed directory: {filepath}")
    except ValueError:
        raise ValueError(f"Path outside allowed directory: {filepath}")
    return abs_filepath


def validate_file_size(filepath: str) -> bool:
    try:
        if not os.path.exists(filepath):
            log_operation("VALIDATE", filepath, "FILE_SIZE", "FAILED", 
                         error="File not found")
            print(color_error("❌ File not found"))
            return False
        size = os.path.getsize(filepath)
        if size == 0:
            log_operation("VALIDATE", filepath, "FILE_SIZE", "FAILED", 
                         error="File is empty")
            print(color_error("❌ File is empty"))
            return False
        if size > MAX_FILE_SIZE:
            log_operation("VALIDATE", filepath, "FILE_SIZE", "FAILED", 
                         error=f"File size {size} exceeds limit {MAX_FILE_SIZE}")
            print(color_error(f"❌ File too large (max {format_size(MAX_FILE_SIZE)})"))
            return False
        return True
    except Exception as e:
        log_operation("VALIDATE", filepath, "FILE_SIZE", "FAILED", 
                     error=str(e))
        print(color_error(f"❌ Size check failed: {e}"))
        return False


def write_file_atomic(filepath: str, data: bytes) -> bool:
    temp_filepath = None
    try:
        directory = os.path.dirname(filepath) or '.'
        with tempfile.NamedTemporaryFile(delete=False, dir=directory, suffix='.tmp') as f:
            temp_filepath = f.name
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except (AttributeError, OSError):
                pass
        os.replace(temp_filepath, filepath)
        return True
    except Exception as e:
        if temp_filepath and os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
            except:
                pass
        log_operation("WRITE", filepath, "FILE_IO", "FAILED", 
                     error=str(e))
        print(color_error(f"❌ Write error: {e}"))
        return False


def get_unique_filename(base_name: str, extension: str = "") -> str:
    timestamp = int(time.time() * 1000)
    random_suffix = random.randint(10000, 99999)
    if extension and not extension.startswith('.'):
        extension = '.' + extension
    return f"{base_name}_{timestamp}_{random_suffix}{extension}"


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (0.0 to 8.0 for bytes)"""
    if not data:
        return 0.0
    from math import log2
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * log2(p)
    return entropy


def get_key_filename(keyname: str, is_public: bool, public_fingerprint: str) -> str:
    """Generate key filename using public key fingerprint for both keys"""
    fingerprint_short = public_fingerprint[:8].upper()
    key_type = "public" if is_public else "private"
    return f"{keyname}_{key_type}_{fingerprint_short}.pem"


def detect_encryption_format(file_path: str) -> Optional[str]:
    try:
        if not os.path.exists(file_path):
            print(color_error(f"❌ File not found: {file_path}"))
            return None

        file_size = os.path.getsize(file_path)
        filename = os.path.basename(file_path).lower()
        
        if filename.endswith('.rsa.b64') or filename.endswith('.rsa'):
            return 'rsa'
        elif filename.endswith('.aes.b64') or filename.endswith('.aes'):
            return 'aes'

        if file_size < MIN_ENCRYPTED_SIZE:
            print(color_warning(f"⚠️  File small ({file_size} bytes) - format unclear"))
            return None

        # Read header for magic header and entropy analysis
        with open(file_path, 'rb') as f:
            header = f.read(min(1024, file_size))
        
        # Check for FSS1 magic header first (most reliable indicator)
        if header.startswith(b"FSS1"):
            # FSS1 format - distinguish between AES and RSA based on payload structure
            try:
                # Minimum: magic(4) + version(1) + hash_len(4) + hash(32) + key_len(2)
                if len(header) < 9 + 32 + 2:
                    return 'aes'  # Default fallback for undersized header
                
                version = header[4]
                if version != 1:
                    return None  # Unsupported version
                
                hash_length = struct.unpack('>I', header[5:9])[0]
                if hash_length != 32:
                    return None  # Invalid hash length for this version
                
                # Read potential key_len field (2 bytes after hash in RSA format)
                # Position: magic(4) + version(1) + hash_len(4) + hash(32) = byte 41
                potential_key_len = struct.unpack('>H', header[9+hash_length:9+hash_length+2])[0]
                
                # RSA hybrid encryption uses key_len to store encrypted_aes_key length
                # Typical range: 512 bytes for RSA-4096 OAEP
                # AES format has salt (16 random bytes) at this position instead
                # Probability of 2 random bytes (0-65535) falling in [100, 1024] is ~0.4%
                # This makes key_len range a reliable discriminant
                RSA_KEY_LEN_MIN = 100
                RSA_KEY_LEN_MAX = 1024
                
                if RSA_KEY_LEN_MIN <= potential_key_len <= RSA_KEY_LEN_MAX:
                    # Highly likely RSA encrypted_aes_key length
                    return 'rsa'
                else:
                    # Random bytes unlikely to be in RSA range, assume AES
                    return 'aes'
            except Exception:
                # If FSS1 structure parsing fails, default to AES as safe fallback
                return 'aes'
        
        # Fallback: Use Shannon entropy to distinguish RSA vs AES
        ent = shannon_entropy(header)
        
        # High entropy (>7.0) suggests encrypted data, lower suggests plaintext/AES patterns
        return 'rsa' if ent > 7.0 else 'aes'

    except IOError as e:
        print(color_error(f"❌ Read error: {e}"))
        return None
    except Exception as e:
        print(color_warning(f"⚠️  Format detection error: {e}"))
        return None


def format_size(bytes_size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} TB"


def prompt_format_selection() -> Optional[str]:
    print(f"\n{color_info('─' * 60)}")
    print(color_warning("⚠️  Could not auto-detect format"))
    print(f"{color_info('─' * 60)}")
    print("\n[1] 🔐 AES-256-GCM (password-based)")
    print("[2] 🔒 RSA-4096 (key-based)\n")
    choice = safe_input("Select format (1-2): ")
    return 'aes' if choice == '1' else 'rsa' if choice == '2' else None


def show_file_stats(original_path: str, encrypted_path: str, operation_time: float):
    try:
        original_size = os.path.getsize(original_path) if os.path.exists(original_path) else 0
        encrypted_size = os.path.getsize(encrypted_path) if os.path.exists(encrypted_path) else 0
        
        if original_size == 0 or encrypted_size == 0:
            return
        
        ratio = (encrypted_size / original_size * 100) if original_size > 0 else 0
        print(f"\n{color_info('─' * 60)}")
        print(color_info("📊 OPERATION STATISTICS"))
        print(f"{color_info('─' * 60)}")
        print(f"  Original size:   {format_size(original_size)}")
        print(f"  Result size:     {format_size(encrypted_size)}")
        print(f"  Size ratio:      {ratio:.1f}%")
        print(f"  Time taken:      {operation_time:.2f} seconds")
        if operation_time > 0:
            speed = (original_size / operation_time) / 1024 / 1024
            print(f"  Speed:           {speed:.2f} MB/s")
        print(color_info('─' * 60))
    except Exception as e:
        print(color_warning(f"⚠️  Stats error: {e}"))


def display_header():
    clear_screen()
    print("=" * 60)
    print(color_bright("      File Secure Suite v1.0.5 - Encryption Tool"))
    print("=" * 60)


def display_menu():
    print("\n" + "=" * 60)
    print(color_bright("                    MAIN MENU"))
    print("=" * 60)
    print("\n[1] 🔑  Generate RSA-4096 Key Pair")
    print("[2] 🔐  Encrypt")
    print("[3] 🔓  Decrypt")
    print("[4] 🗝️  Key Management")
    print("[5] 📊  View Audit Log")
    print("[6] ℹ️  Credits")
    print("[7] ❌  Exit\n")


def derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt


def aes_encrypt_with_hash(data: bytes, password: str, file_hash: str) -> bytes:
    """Encrypt with AES-256-GCM using PBKDF2 (OpenSSL compatible)"""
    key, salt = derive_key_from_password(password)
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, data, None)
    hash_bytes = bytes.fromhex(file_hash)
    
    magic = b"FSS1"
    version = struct.pack('>B', 1)  # Version 1 = PBKDF2 (OpenSSL compatible)
    result = magic + version + struct.pack('>I', len(hash_bytes)) + hash_bytes + salt + nonce + ciphertext
    return result


def aes_decrypt_with_hash(encrypted_data: bytes, password: str) -> Tuple[bytes, str]:
    """
    Decrypt AES-256-GCM encrypted data with hash verification.
    Uses PBKDF2 for OpenSSL compatibility.
    
    NOTE: Returned plaintext should be handled carefully and cleared from memory
    after use. Caller is responsible for: del plaintext or plaintext = b""
    """
    if len(encrypted_data) < MIN_ENCRYPTED_SIZE:
        raise ValueError("Invalid encrypted data (too short)")

    if not encrypted_data.startswith(b"FSS1"):
        raise ValueError("Invalid file format - not a File Secure Suite v1 file")
    
    version = encrypted_data[4]
    if version not in [1]:
        raise ValueError(f"Unsupported version: {version}. This version uses PBKDF2 encryption.")

    hash_length = struct.unpack('>I', encrypted_data[5:9])[0]
    if hash_length != 32:
        raise ValueError(f"Invalid hash length: {hash_length}")
    
    min_required = 5 + 4 + hash_length + 16 + 12 + 1
    if len(encrypted_data) < min_required:
        raise ValueError(f"Invalid format (got {len(encrypted_data)} bytes, need {min_required})")
    
    hash_bytes = encrypted_data[9:9+hash_length]
    hash_hex = hash_bytes.hex()
    salt = encrypted_data[9+hash_length:9+hash_length+16]
    nonce = encrypted_data[9+hash_length+16:9+hash_length+28]
    ciphertext = encrypted_data[9+hash_length+28:]

    # Use PBKDF2 for decryption (OpenSSL compatible)
    key, _ = derive_key_from_password(password, salt)
    
    cipher = AESGCM(key)
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

    return plaintext, hash_hex


def rsa_encrypt_hybrid_with_hash(data: bytes, public_key_pem: str, file_hash: str) -> bytes:
    aes_key = os.urandom(32)
    salt = os.urandom(16)
    nonce = os.urandom(12)

    cipher = AESGCM(aes_key)
    ciphertext = cipher.encrypt(nonce, data, None)

    public_key = serialization.load_pem_public_key(
        public_key_pem.encode()
    )

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    hash_bytes = bytes.fromhex(file_hash)
    key_len = len(encrypted_aes_key).to_bytes(2, 'big')
    
    magic = b"FSS1"
    version = struct.pack('>B', 1)
    result = (magic + version + struct.pack('>I', len(hash_bytes)) + hash_bytes + 
              key_len + encrypted_aes_key + salt + nonce + ciphertext)
    return result


def rsa_decrypt_hybrid_with_hash(encrypted_data: bytes, private_key_pem: str,
                                 private_key_password: Optional[str] = None,
                                 private_key_file: Optional[str] = None) -> Tuple[bytes, str]:
    if len(encrypted_data) < MIN_ENCRYPTED_SIZE:
        raise ValueError("Invalid encrypted data (too short)")

    if not encrypted_data.startswith(b"FSS1"):
        raise ValueError("Invalid file format - not a File Secure Suite v1 file")
    
    version = encrypted_data[4]
    if version != 1:
        raise ValueError(f"Unsupported version: {version}")

    hash_length = struct.unpack('>I', encrypted_data[5:9])[0]
    if hash_length != 32:
        raise ValueError(f"Invalid hash length: {hash_length}")
    
    try:
        key_len = int.from_bytes(encrypted_data[9+hash_length:9+hash_length+2], 'big')
    except (struct.error, IndexError):
        raise ValueError("Cannot read key length")
    
    if key_len < 100 or key_len > 1024:
        raise ValueError(f"Invalid RSA key size: {key_len}")
    
    min_required = 5 + 4 + hash_length + 2 + key_len + 16 + 12 + 1
    if len(encrypted_data) < min_required:
        raise ValueError(f"Invalid format (got {len(encrypted_data)} bytes, need {min_required})")
    
    hash_bytes = encrypted_data[9:9+hash_length]
    hash_hex = hash_bytes.hex()
    encrypted_aes_key = encrypted_data[9+hash_length+2:9+hash_length+2+key_len]
    salt = encrypted_data[9+hash_length+2+key_len:9+hash_length+2+key_len+16]
    nonce = encrypted_data[9+hash_length+2+key_len+16:9+hash_length+2+key_len+28]
    ciphertext = encrypted_data[9+hash_length+2+key_len+28:]

    try:
        # Decrypt private key using PBKDF2 (OpenSSL standard)
        if private_key_password:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                private_key_password.encode('utf-8')
            )
        else:
            # No password: try to load unprotected key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                None
            )
        
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {str(e)}")

    cipher = AESGCM(aes_key)
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"AES decryption failed: {str(e)}")

    return plaintext, hash_hex


def generate_rsa_keypair(password: Optional[str] = None, key_identifier: str = "") -> Tuple[str, str, None]:
    """Generate RSA-4096 keypair. Returns (private_pem, public_pem, None)
    Uses OpenSSL standard PBKDF2 encryption when password is provided"""
    print("\n🔄 Generating RSA-4096 key pair...")
    print("   This may take 1-2 minutes. Please wait...\n")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )

    public_key = private_key.public_key()

    # Use PBKDF2 (OpenSSL standard) for RSA key encryption
    if password:
        encryption_algo = serialization.BestAvailableEncryption(password.encode('utf-8'))
    else:
        encryption_algo = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    ).decode('utf-8')

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem, None


def validate_rsa_key(key_pem: str, is_public: bool = True, key_password: Optional[str] = None) -> bool:
    try:
        if is_public:
            serialization.load_pem_public_key(key_pem.encode())
        else:
            pw_bytes = key_password.encode() if key_password else None
            serialization.load_pem_private_key(key_pem.encode(), pw_bytes)
        return True
    except Exception:
        return False


def calculate_key_fingerprint(key_pem: str, is_public: bool = True) -> str:
    """
    Calculate SHA256 fingerprint of RSA key for verification.
    This allows users to verify they're using the correct key.
    
    Args:
        key_pem: Key in PEM format (public or private)
        is_public: True for public key, False for private key
    
    Returns:
        SHA256 fingerprint as hex string (shortened to 32 chars for readability)
    """
    try:
        key_hash = hashlib.sha256(key_pem.encode('utf-8')).hexdigest()
        return key_hash[:32]
    except Exception as e:
        print(color_warning(f"⚠️  Fingerprint error: {e}"))
        return "UNKNOWN"


def prompt_generate_keypair():
    try:
        display_header()
        print("\n🔑 RSA-4096 KEY PAIR GENERATION\n")

        keyname = safe_input("Enter key pair name (e.g., 'mykey'): ")
        if not keyname:
            return

        keyname = sanitize_filename(keyname)
        
        ensure_keys_dir()

        protect = safe_input("\nProtect private key with password? (y/n): ")
        password = None

        if protect and protect.lower() == 'y':
            max_attempts = 3
            print(f"\n{color_warning('Key Password Requirements:')}")
            print(f"  • Minimum 12 characters")
            print(f"  • At least 1 UPPERCASE letter (A-Z)")
            print(f"  • At least 1 lowercase letter (a-z)")
            print(f"  • At least 1 digit (0-9)")
            print(f"  • At least 1 special character (!@#$%^&*...)\n")
            
            for attempt in range(max_attempts):
                password = safe_input("🔑 Enter password: ", password=True)
                if not password:
                    print("⚠️  No password entered. Generating unprotected keys.")
                    break
                
                is_valid, msg = validate_password_strength_key(password)
                print(color_info(msg) if is_valid else color_error(msg))
                if not is_valid:
                    if attempt < max_attempts - 1:
                        print(color_warning(f"⚠️  {max_attempts - attempt - 1} attempt(s) remaining"))
                    continue
                
                # Confirm password
                password_confirm = safe_input("🔑 Confirm password: ", password=True)
                if password != password_confirm:
                    log_operation("VALIDATE", "key_generation", "PASSWORD", "FAILED", 
                                 error="Password confirmation mismatch")
                    print(color_error("❌ Passwords do not match. Try again."))
                    if attempt < max_attempts - 1:
                        print(color_warning(f"⚠️  {max_attempts - attempt - 1} attempt(s) remaining"))
                    continue
                
                break

        print("\n🔄 Generating key pair...")
        private_pem, public_pem, _ = generate_rsa_keypair(password, key_identifier=keyname)

        # Calculate public key fingerprint once (used for both private and public key filenames)
        public_fingerprint = calculate_key_fingerprint(public_pem, is_public=True)

        # Save keys to KEYS_DIR with same public fingerprint for both files
        private_file = os.path.join(KEYS_DIR, get_key_filename(keyname, is_public=False, public_fingerprint=public_fingerprint))
        public_file = os.path.join(KEYS_DIR, get_key_filename(keyname, is_public=True, public_fingerprint=public_fingerprint))

        if not write_file_atomic(private_file, private_pem.encode('utf-8')):
            log_operation("KEYGEN", private_file, "RSA4096", "FAILED", 
                         keyname=keyname, key_protected=(password is not None),
                         error="Could not write private key file")
            safe_input("\n👉 Press Enter to continue...")
            return
        os.chmod(private_file, 0o600)

        if not write_file_atomic(public_file, public_pem.encode('utf-8')):
            log_operation("KEYGEN", public_file, "RSA4096", "FAILED",
                         keyname=keyname, key_protected=(password is not None),
                         error="Could not write public key file")
            safe_input("\n👉 Press Enter to continue...")
            return

        log_operation("KEYGEN", private_file, "RSA4096", "SUCCESS",
                     keyname=keyname, key_protected=(password is not None),
                     key_fingerprint=public_fingerprint,
                     additional=f"Key pair: {keyname} | Key size: {RSA_KEY_SIZE} | Location: {KEYS_DIR}")

        print(f"\n{color_success('✅ Keys generated successfully!')}")
        print(f"  Key name:    {color_bright(keyname)}")
        print(f"  Private key: {color_bright(private_file)}")
        print(f"  Public key:  {color_bright(public_file)}")
        
        print(f"\n{color_info('🔑 KEY FINGERPRINT (for verification):')}")
        print(f"  Public: {color_bright(public_fingerprint)}")
        
        if password:
            print(f"\n  🔐 Private key is PASSWORD PROTECTED")
        print("\n⚠️  IMPORTANT: Keep private key secure!")
        print(f"📁 All keys saved in: {color_bright(KEYS_DIR)}")

        safe_input("\n👉 Press Enter to continue...")

    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled")
    except Exception as e:
        log_exception("KEYGEN", "key_generation", "RSA4096", e)
        print(color_error(f"❌ Error: {e}"))
        safe_input("\n👉 Press Enter to continue...")


def prompt_encrypt(data_type=None):
    try:
        display_header()
        print("\n🔐 ENCRYPTION MODE\n")

        print(f"{color_info('─' * 60)}")
        print(f"{color_warning('⚠️  FILE SIZE LIMIT')}")
        print(f"{color_info('─' * 60)}")
        print(f"  📁 Maximum file size: {color_bright('1 GB')}")
        print(f"{color_info('─' * 60)}\n")

        if data_type is None:
            while True:
                data_type = safe_input("Encrypt [t]ext or [f]ile? (t/f): ")
                if data_type and data_type in ['t', 'f']:
                    break
                log_operation("VALIDATE", "user_input", "MENU", "FAILED", 
                             error=f"Invalid choice for data type: {data_type}")
                print(color_error("❌ Invalid choice. Please enter 't' or 'f'"))
                retry = safe_input("Try again? (y/n): ")
                if not retry or retry.lower() != 'y':
                    safe_input("\n👉 Press Enter to continue...")
                    return

        # Encryption method selection menu
        while True:
            print("\n" + "=" * 60)
            print(color_bright("          ENCRYPTION METHOD"))
            print("=" * 60)
            print("\n[1] 🔐 AES-256-GCM (Password-based)")
            print("[2] 🔑 RSA-4096 (Public Key) - Hybrid Encryption")
            print("[3] ↩️  Back to Encrypt Menu\n")
            
            method = safe_input("Select option (1-3): ")
            
            if method == '1':
                method = 'a'  # Convert to AES
                break
            elif method == '2':
                method = 'r'  # Convert to RSA
                print(f"\n{color_info('ℹ️  HYBRID ENCRYPTION')}")
                print(color_info("─" * 60))
                print(color_info("FileSecureSuite uses hybrid encryption for RSA:"))
                print(color_info("• Generates random AES-256 key for each file"))
                print(color_info("• Encrypts file with AES-256-GCM"))
                print(color_info("• Encrypts AES key with RSA-4096 (public key)"))
                print(color_info("─" * 60))
                break
            elif method == '3':
                return
            else:
                log_operation("VALIDATE", "user_input", "MENU", "FAILED", 
                             error=f"Invalid encryption method choice: {method}")
                print(color_error("❌ Invalid choice. Please enter 1, 2, or 3"))
                safe_input("👉 Press Enter to continue...")

        if data_type == 't':
            text = safe_input("\nEnter text to encrypt: ")
            if not text:
                print(color_warning("⚠️  No text provided"))
                safe_input("\n👉 Press Enter to continue...")
                return
            data = text.encode('utf-8')
            file_hash = hashlib.sha256(data).hexdigest()
        else:
            filepath = safe_input("\nEnter file path: ")
            if not filepath:
                log_operation("VALIDATE", "user_input", "FILE_PATH", "FAILED", 
                             error="No file path provided")
                print(color_error("❌ No file path provided"))
                safe_input("\n👉 Press Enter to continue...")
                return
            filepath = clean_path(filepath)
            if not validate_file_size(filepath):
                safe_input("\n👉 Press Enter to continue...")
                return
            with open(filepath, 'rb') as f:
                data = f.read()
            original_filename = sanitize_filename(os.path.basename(filepath))
            # Prepend filename to data for recovery during decryption
            filename_with_separator = original_filename.encode('utf-8') + b'\x00'
            data = filename_with_separator + data
            # Calculate hash on complete payload (filename + separator + file data)
            file_hash = hashlib.sha256(data).hexdigest()

        if method == 'a':
            max_attempts = 3
            password = None
            
            print(f"\n{color_info('Password Requirements:')}")
            print(f"  • Minimum 8 characters")
            print(f"  • At least 2 of: uppercase, lowercase, digit, special char\n")
            
            for attempt in range(max_attempts):
                password = safe_input(f"🔐 Enter password (attempt {attempt + 1}/{max_attempts}): ", password=True)
                if not password:
                    if attempt < max_attempts - 1:
                        print(color_warning(f"⚠️  {max_attempts - attempt - 1} attempt(s) remaining"))
                    continue
                is_valid, msg = validate_password_strength(password)
                if not is_valid:
                    log_operation("VALIDATE", "encrypt_input", "PASSWORD", "FAILED", 
                                 error=f"Password strength: {msg}")
                    print(color_error(f"❌ {msg}"))
                    if attempt < max_attempts - 1:
                        print(color_warning(f"⚠️  {max_attempts - attempt - 1} attempt(s) remaining"))
                    continue
                
                # Confirm password
                password_confirm = safe_input("🔐 Confirm password: ", password=True)
                if password != password_confirm:
                    log_operation("VALIDATE", "encrypt_input", "PASSWORD", "FAILED", 
                                 error="Password confirmation mismatch")
                    print(color_error("❌ Passwords do not match. Try again."))
                    if attempt < max_attempts - 1:
                        print(color_warning(f"⚠️  {max_attempts - attempt - 1} attempt(s) remaining"))
                    password = None
                    continue
                
                # Password accepted - show character count
                print(f"{color_success(f'✅ Password accepted ({len(password)} characters)')}")
                break
            
            if not password:
                log_operation("VALIDATE", "encrypt_input", "PASSWORD", "FAILED", 
                             error="No valid password provided after max attempts")
                print(color_error("❌ No valid password provided"))
                safe_input("\n👉 Press Enter to continue...")
                return

            encrypted_data = aes_encrypt_with_hash(data, password, file_hash)
            if data_type == 't':
                output_base = "encrypted"
            else:
                output_base = f"encrypted_{original_filename}"
            output_file = get_unique_filename(output_base, "aes")

            if not write_file_atomic(output_file, encrypted_data):
                safe_input("\n👉 Press Enter to continue...")
                return

            print(f"\n{color_success('✅ Encryption successful!')}")
            print(f"  Output:     {color_bright(output_file)}")
            
            if data_type == 't':
                output_b64_file = output_file + ".b64"
                b64_data = base64.b64encode(encrypted_data).decode('ascii')
                if write_file_atomic(output_b64_file, b64_data.encode('ascii')):
                    print(f"  Base64:     {color_bright(output_b64_file)}")
            
            log_operation("ENCRYPT", output_file, "AES-256", "SUCCESS", file_hash,
                         additional=f"{'encrypt_text' if data_type == 't' else 'encrypt_file'}")

        elif method == 'r':
            pubkey_path = safe_input("\nEnter public key file path: ")
            if not pubkey_path:
                return
            pubkey_path = clean_path(pubkey_path)
            
            try:
                with open(pubkey_path, 'r') as f:
                    public_key_pem = f.read()
            except FileNotFoundError:
                log_operation("VALIDATE", pubkey_path, "RSA_KEY", "FAILED", 
                             error="Public key file not found")
                print(color_error("❌ Public key file not found"))
                safe_input("\n👉 Press Enter to continue...")
                return
            except Exception as e:
                log_exception("ENCRYPT", pubkey_path, "RSA", e)
                print(color_error(f"❌ Could not read public key: {e}"))
                safe_input("\n👉 Press Enter to continue...")
                return

            if not validate_rsa_key(public_key_pem, is_public=True):
                log_operation("VALIDATE", pubkey_path, "RSA_KEY", "FAILED", 
                             error="Invalid public key format")
                print(color_error("❌ Invalid public key"))
                safe_input("\n👉 Press Enter to continue...")
                return
            
            public_fingerprint = calculate_key_fingerprint(public_key_pem, is_public=True)
            print(f"\n{color_info('✅ Public key loaded successfully')}")
            print(f"  Fingerprint: {color_bright(public_fingerprint)}")
            print(f"  Path: {pubkey_path}\n")

            encrypted_data = rsa_encrypt_hybrid_with_hash(data, public_key_pem, file_hash)
            if data_type == 't':
                output_base = "encrypted"
            else:
                output_base = f"encrypted_{original_filename}"
            output_file = get_unique_filename(output_base, "rsa")

            if not write_file_atomic(output_file, encrypted_data):
                safe_input("\n👉 Press Enter to continue...")
                return

            print(f"\n{color_success('✅ Encryption successful!')}")
            print(f"  Output:     {color_bright(output_file)}")
            
            if data_type == 't':
                output_b64_file = output_file + ".b64"
                b64_data = base64.b64encode(encrypted_data).decode('ascii')
                if write_file_atomic(output_b64_file, b64_data.encode('ascii')):
                    print(f"  Base64:     {color_bright(output_b64_file)}")
            
            log_operation("ENCRYPT", output_file, "RSA", "SUCCESS", file_hash,
                         key_fingerprint=public_fingerprint,
                         additional=f"{'encrypt_text' if data_type == 't' else 'encrypt_file'} | Public key: {os.path.basename(pubkey_path)}")

        print("\n" + "=" * 60)
        data_type_label = "text" if data_type == 't' else "file"
        continue_choice = safe_input(color_info(f"Encrypt another {data_type_label}? (y/n): "))
        if continue_choice and continue_choice.lower() == 'y':
            prompt_encrypt(data_type=data_type)  # Recursive call with same data_type
            return
        
        safe_input("\n👉 Press Enter to continue...")

    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled")
    except Exception as e:
        log_exception("ENCRYPT", "user_input", "UNKNOWN", e)
        print(color_error(f"❌ Error: {e}"))
        safe_input("\n👉 Press Enter to continue...")


def prompt_decrypt():
    try:
        display_header()
        print("\n🔓 DECRYPTION MODE\n")

        print(f"\n{color_info('─' * 60)}")
        print(color_info("ℹ️  FILE FORMAT INFORMATION"))
        print(f"{color_info('─' * 60)}")
        print(f"  ✅ Can decrypt: ANY encrypted file")
        print(f"  ℹ️  Recommended extensions: .aes, .aes.b64, .rsa, .rsa.b64")
        print(f"  ℹ️  Auto-detects format from file content if needed")
        print(color_info('─' * 60))

        filepath = safe_input("\nEnter encrypted file path: ")
        if not filepath:
            return

        filepath = clean_path(filepath)

        if not os.path.exists(filepath):
            print(color_error("❌ File not found"))
            safe_input("\n👉 Press Enter to continue...")
            return

        try:
            with open(filepath, 'rb') as f:
                raw_data = f.read()
            
            filepath_lower = filepath.lower()
            encrypted_data = None
            
            if filepath_lower.endswith('.b64'):
                try:
                    encrypted_data = base64.b64decode(raw_data, validate=True)
                    # Verify decoded content looks like FSS1 payload
                    if not (encrypted_data.startswith(b"FSS1") and len(encrypted_data) >= MIN_ENCRYPTED_SIZE):
                        raise ValueError("Decoded base64 does not look like FSS1 payload")
                    print("ℹ️  Detected base64 format (.b64)")
                except Exception as e:
                    log_exception("DECRYPT", filepath, "BASE64", e)
                    print(color_error(f"❌ Invalid base64 file: {e}"))
                    safe_input("\n👉 Press Enter to continue...")
                    return
            else:
                try:
                    maybe = base64.b64decode(raw_data, validate=True)
                    # Verify decoded content looks like FSS1 payload before accepting
                    if maybe.startswith(b"FSS1") and len(maybe) >= MIN_ENCRYPTED_SIZE:
                        encrypted_data = maybe
                        print("ℹ️  Detected base64 format (content)")
                    else:
                        encrypted_data = raw_data
                        print("ℹ️  Detected binary format")
                except Exception:
                    encrypted_data = raw_data
                    print("ℹ️  Detected binary format")
        except Exception as e:
            log_exception("DECRYPT", filepath, "FILE_READ", e)
            print(color_error(f"❌ Read error: {e}"))
            safe_input("\n👉 Press Enter to continue...")
            return

        detected_format = detect_encryption_format(filepath)
        if not detected_format:
            detected_format = prompt_format_selection()

        if not detected_format:
            safe_input("\n👉 Press Enter to continue...")
            return

        if detected_format == 'aes':
            max_attempts = 3
            for attempt in range(1, max_attempts + 1):
                password = safe_input(f"🔐 Enter password (attempt {attempt}/{max_attempts}): ", password=True)
                
                if not password:
                    print(color_warning(f"⚠️  Password cannot be empty"))
                    if attempt < max_attempts:
                        print(color_warning(f"⚠️  {max_attempts - attempt} attempt(s) remaining"))
                    else:
                        print(color_error("❌ Maximum attempts reached."))
                    continue

                try:
                    plaintext, stored_hash = aes_decrypt_with_hash(encrypted_data, password)
                    
                    # Verify SHA-256 hash
                    computed_hash = hashlib.sha256(plaintext).hexdigest()
                    if not verify_hash_constant_time(stored_hash, computed_hash):
                        print(color_error(f"❌ Hash verification FAILED!"))
                        print(color_error(f"   Expected: {stored_hash}"))
                        print(color_error(f"   Got:      {computed_hash}"))
                        log_operation("DECRYPT", filepath, "AES-256", "FAILED",
                                     error=f"Hash mismatch: expected {stored_hash}, got {computed_hash}",
                                     additional="decrypt_file | KDF: PBKDF2")
                        plaintext = b""  # Clear corrupted plaintext
                        print(color_warning("⚠️  File may be corrupted"))
                        if attempt < max_attempts:
                            print(color_warning(f"⚠️  {max_attempts - attempt} attempt(s) remaining"))
                        continue
                    
                    original_name = None
                    try:
                        parts = plaintext.split(b'\x00', 1)
                        if len(parts) == 2 and len(parts[0]) < 256:
                            original_name = parts[0].decode('utf-8', errors='ignore')
                            plaintext = parts[1]
                    except:
                        pass
                    
                    if not original_name:
                        base_name = os.path.splitext(os.path.basename(filepath))[0]
                        if filepath.endswith('.aes'):
                            base_name = base_name.replace('.aes', '')
                        elif filepath.endswith('.aes.b64'):
                            base_name = base_name.replace('.aes.b64', '')
                        original_name = base_name if base_name else "file"
                    
                    output_file = get_unique_filename("decrypted", original_name)
                    
                    if not write_file_atomic(output_file, plaintext):
                        plaintext = b""  # Clear from memory
                        safe_input("\n👉 Press Enter to continue...")
                        return
                    print(f"\n{color_success('✅ Decryption successful!')}")
                    print(f"  Output file: {color_bright(output_file)}")
                    print(f"  ✅ Integrity verified (SHA-256)")
                    log_operation("DECRYPT", filepath, "AES-256", "SUCCESS", stored_hash,
                                 additional="decrypt_file | KDF: PBKDF2")
                    
                    print("\n" + "=" * 60)
                    continue_choice = safe_input(color_info("Decrypt another file? (y/n): "))
                    if continue_choice and continue_choice.lower() == 'y':
                        prompt_decrypt()  # Recursive call to continue
                        return
                    
                    safe_input("\n👉 Press Enter to continue...")
                    return
                except ValueError as e:
                    if attempt < max_attempts:
                        print(color_error(f"❌ {e}"))
                        sleep_time = 2 ** attempt
                        print(color_warning(f"⏳ Waiting {sleep_time}s before next attempt..."))
                        print(color_warning(f"⚠️  {max_attempts - attempt} attempt(s) remaining"))
                        time.sleep(sleep_time)
                    else:
                        print(color_error(f"❌ {e}"))
                        print(color_error("❌ Maximum attempts reached."))

        else:
            while True:
                priv_path = safe_input("Enter private key file path: ")
                if not priv_path:
                    return
                priv_path = clean_path(priv_path)
                
                try:
                    with open(priv_path, 'r') as f:
                        priv_key = f.read()
                except FileNotFoundError:
                    log_operation("VALIDATE", priv_path, "RSA_KEY", "FAILED", 
                                 error="Private key file not found")
                    print(color_error("❌ Private key file not found"))
                    retry = safe_input("Try another key? (y/n): ")
                    if not retry or retry.lower() != 'y':
                        safe_input("\n👉 Press Enter to continue...")
                        return
                    continue
                except Exception as e:
                    log_exception("DECRYPT", priv_path, "RSA_KEY_READ", e)
                    print(color_error(f"❌ Could not read private key: {e}"))
                    retry = safe_input("Try another key? (y/n): ")
                    if not retry or retry.lower() != 'y':
                        safe_input("\n👉 Press Enter to continue...")
                        return
                    continue
                
                print(f"\n{color_info('🔑 Private key loaded successfully')}")
                print(f"  Path: {priv_path}\n")
                
                try:
                    max_password_attempts = 3
                    password_success = False
                    
                    for pwd_attempt in range(1, max_password_attempts + 1):
                        priv_password = safe_input(f"🔐 Private key password (attempt {pwd_attempt}/{max_password_attempts}, press Enter if none): ", password=True)
                        priv_password = priv_password if priv_password else None
                        
                        # If no password entered, try once with None and exit loop
                        if priv_password is None:
                            try:
                                plaintext, stored_hash = rsa_decrypt_hybrid_with_hash(encrypted_data, priv_key, None, priv_path)
                                password_success = True
                                break
                            except ValueError as e:
                                print(color_error(f"❌ {e}"))
                                print(color_error("❌ Key is password-protected. Try again with password."))
                                continue  # Ask for password again
                        
                        # If password entered, try decryption
                        try:
                            plaintext, stored_hash = rsa_decrypt_hybrid_with_hash(encrypted_data, priv_key, priv_password, priv_path)
                            password_success = True
                            break
                        except ValueError as e:
                            if pwd_attempt < max_password_attempts:
                                log_exception("DECRYPT", priv_path, "RSA_PASSWORD", e)
                                print(color_error(f"❌ {e}"))
                                sleep_time = 2 ** pwd_attempt
                                print(color_warning(f"⏳ Waiting {sleep_time}s before next attempt..."))
                                print(color_warning(f"⚠️  {max_password_attempts - pwd_attempt} attempt(s) remaining"))
                                time.sleep(sleep_time)
                            else:
                                log_operation("DECRYPT", priv_path, "RSA", "FAILED",
                                             error=f"Maximum password attempts reached: {str(e)}",
                                             additional=f"Private key: {os.path.basename(priv_path)}")
                                print(color_error("❌ Maximum password attempts reached."))
                    
                    if not password_success:
                        retry_key = safe_input("Try another key? (y/n): ")
                        if not retry_key or retry_key.lower() != 'y':
                            safe_input("\n👉 Press Enter to continue...")
                            return
                        break  # Esce dal loop password, torna a chiedere chiave
                    
                    # Verify SHA-256 hash
                    computed_hash = hashlib.sha256(plaintext).hexdigest()
                    if not verify_hash_constant_time(stored_hash, computed_hash):
                        print(color_error(f"❌ Hash verification FAILED!"))
                        print(color_error(f"   Expected: {stored_hash}"))
                        print(color_error(f"   Got:      {computed_hash}"))
                        log_operation("DECRYPT", filepath, "RSA", "FAILED",
                                     error=f"Hash mismatch: expected {stored_hash}, got {computed_hash}",
                                     additional=f"decrypt_file | Private key: {os.path.basename(priv_path)}")
                        plaintext = b""  # Clear corrupted plaintext
                        print(color_warning("⚠️  File may be corrupted"))
                        retry_key = safe_input("Try another key? (y/n): ")
                        if not retry_key or retry_key.lower() != 'y':
                            safe_input("\n👉 Press Enter to continue...")
                            return
                        break  # Torna a chiedere la chiave
                    
                    original_name = None
                    try:
                        parts = plaintext.split(b'\x00', 1)
                        if len(parts) == 2 and len(parts[0]) < 256:
                            original_name = parts[0].decode('utf-8', errors='ignore')
                            plaintext = parts[1]
                    except:
                        pass
                    
                    if not original_name:
                        base_name = os.path.splitext(os.path.basename(filepath))[0]
                        if filepath.endswith('.rsa'):
                            base_name = base_name.replace('.rsa', '')
                        elif filepath.endswith('.rsa.b64'):
                            base_name = base_name.replace('.rsa.b64', '')
                        original_name = base_name if base_name else "file"
                    
                    output_file = get_unique_filename("decrypted", original_name)
                    
                    if not write_file_atomic(output_file, plaintext):
                        plaintext = b""  # Clear from memory
                        continue
                    plaintext = b""  # Clear from memory after writing
                    print(f"\n{color_success('✅ Decryption successful!')}")
                    print(f"  Output file: {color_bright(output_file)}")
                    print(f"  ✅ Integrity verified (SHA-256)")
                    log_operation("DECRYPT", filepath, "RSA", "SUCCESS", stored_hash,
                                 additional=f"decrypt_file | Private key: {os.path.basename(priv_path)}")
                    
                    print("\n" + "=" * 60)
                    continue_choice = safe_input(color_info("Decrypt another file? (y/n): "))
                    if continue_choice and continue_choice.lower() == 'y':
                        prompt_decrypt()  # Recursive call to continue
                        return
                    
                    safe_input("\n👉 Press Enter to continue...")
                    return
                except Exception as e:
                    log_exception("DECRYPT", priv_path, "RSA", e)
                    print(color_error(f"❌ Error: {e}"))
                    retry = safe_input("Try another key? (y/n): ")
                    if not retry or retry.lower() != 'y':
                        safe_input("\n👉 Press Enter to continue...")
                        return
                    continue

    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled")
    except Exception as e:
        log_exception("DECRYPT", "user_file", "UNKNOWN", e)
        print(color_error(f"❌ Error: {e}"))
        safe_input("\n👉 Press Enter to continue...")


def prompt_view_audit_log():
    try:
        display_header()
        print("\n📊 AUDIT LOG\n")
        
        log_content = get_audit_log()
        if not log_content:
            print(color_warning("⚠️  No audit logs found"))
        else:
            print(log_content)
        
        safe_input("\n👉 Press Enter to continue...")

    except Exception as e:
        log_exception("AUDIT_LOG", "audit.log", "READ", e)
        print(color_error(f"❌ Error: {e}"))
        safe_input("\n👉 Press Enter to continue...")


def prompt_decrypt_from_clipboard():
    try:
        display_header()
        print("\n📋 DECRYPT TEXT (Base64 Only)\n")
        print("=" * 60)
        print(color_info("Paste your Base64 encrypted text below"))
        print(color_info("(Press Enter twice to finish)"))
        print("=" * 60)
        print()
        
        lines = []
        empty_lines = 0
        
        while True:
            try:
                line = input()
                if line == "":
                    empty_lines += 1
                    if empty_lines >= 2:
                        break
                    lines.append(line)
                else:
                    empty_lines = 0
                    lines.append(line)
            except KeyboardInterrupt:
                print("\n⚠️  Operation cancelled")
                safe_input("\n👉 Press Enter to continue...")
                return
            except EOFError:
                break
        
        text_input = '\n'.join(lines).strip()
        
        if not text_input:
            log_operation("VALIDATE", "clipboard_input", "INPUT", "FAILED", 
                         error="No text provided")
            print(color_error("❌ No text provided"))
            safe_input("\n👉 Press Enter to continue...")
            return

        # Decode Base64 only
        try:
            encrypted_bytes = base64.b64decode(text_input, validate=True)
            # Verify decoded content looks like FSS1 payload
            if not (encrypted_bytes.startswith(b"FSS1") and len(encrypted_bytes) >= MIN_ENCRYPTED_SIZE):
                raise ValueError("Decoded base64 does not look like FSS1 encrypted payload")
            print(f"\n✅ Base64 decoded ({len(encrypted_bytes)} bytes)")
        except Exception as e:
            log_operation("VALIDATE", "clipboard_input", "BASE64", "FAILED", 
                         error=str(e))
            print(color_error(f"❌ Invalid Base64 format: {e}"))
            print(color_warning("\n⚠️  For encrypted files, use: [3] 🔓 Decrypt File"))
            safe_input("\n👉 Press Enter to continue...")
            return

        if len(encrypted_bytes) < 50:
            print(color_warning(f"⚠️  Size: {len(encrypted_bytes)} bytes"))

        detected_format = None
        if len(encrypted_bytes) < 400:
            detected_format = 'aes'
            print(color_success("✅ Detected: 🔐 AES-256-GCM"))
        elif len(encrypted_bytes) > 400:
            detected_format = 'rsa'
            print(color_success("✅ Detected: 🔒 RSA-4096"))
        else:
            print(color_warning(f"⚠️  Size: {len(encrypted_bytes)} bytes"))
            detected_format = prompt_format_selection()

        if not detected_format:
            safe_input("\n👉 Press Enter to continue...")
            return

        if detected_format == 'aes':
            max_attempts = 3
            for attempt in range(1, max_attempts + 1):
                password = safe_input(f"🔐 Enter password (attempt {attempt}/{max_attempts}): ", password=True)
                if not password:
                    if attempt < max_attempts:
                        print(color_warning(f"⚠️  {max_attempts - attempt} attempt(s) remaining"))
                    else:
                        print(color_error("❌ Maximum attempts reached."))
                    continue

                try:
                    plaintext, stored_hash = aes_decrypt_with_hash(encrypted_bytes, password)
                    
                    # Verify SHA-256 hash
                    computed_hash = hashlib.sha256(plaintext).hexdigest()
                    if not verify_hash_constant_time(stored_hash, computed_hash):
                        print(color_error(f"❌ Hash verification FAILED!"))
                        print(color_error(f"   Expected: {stored_hash}"))
                        print(color_error(f"   Got:      {computed_hash}"))
                        log_operation("DECRYPT", "clipboard_input", "AES-256", "FAILED",
                                     error=f"Hash mismatch: expected {stored_hash}, got {computed_hash}",
                                     additional="decrypt_text_from_clipboard | KDF: PBKDF2")
                        plaintext = b""  # Clear corrupted plaintext
                        print(color_warning("⚠️  Data may be corrupted"))
                        if attempt < max_attempts:
                            print(color_warning(f"⚠️  {max_attempts - attempt} attempt(s) remaining"))
                        continue
                    
                    text = plaintext.decode('utf-8')
                    plaintext = b""  # Clear from memory
                    print()
                    print(color_success("✅ Decryption successful!"))
                    print("─" * 60)
                    print(text)
                    print("─" * 60)
                    
                    # Log decrypt from clipboard
                    log_operation("DECRYPT", "clipboard_input", "AES-256", "SUCCESS", stored_hash,
                                 additional="decrypt_text_from_clipboard | KDF: PBKDF2")
                    
                    # Menu for output options
                    print("\n" + color_info("Save/Copy options:"))
                    print("[1] 📋 Copy to clipboard")
                    print("[2] 💾 Save to text file")
                    print("[3] ⏭️  Skip\n")
                    
                    choice = safe_input("Select option (1-3): ")
                    
                    if choice == '1':
                        if HAS_PYPERCLIP:
                            pyperclip.copy(text)
                            threading.Thread(target=clear_clipboard_after, args=(CLIPBOARD_CLEAR_TIMEOUT,), daemon=True).start()
                            print(color_success("✅ Copied to clipboard"))
                        else:
                            print(color_warning("⚠️  Clipboard not available"))
                    elif choice == '2':
                        output_file = get_unique_filename("decrypted", "txt")
                        if write_file_atomic(output_file, text.encode('utf-8')):
                            print(color_success(f"✅ Saved to file: {color_bright(output_file)}"))
                        else:
                            print(color_error("❌ Failed to save file"))
                    elif choice == '3':
                        print(color_info("⏭️  Skipped"))
                    else:
                        print(color_warning("⚠️  Invalid option"))
                    
                    text = ""  # Clear from memory
                    safe_input("\n👉 Press Enter to continue...")
                    return
                except ValueError as e:
                    if attempt < max_attempts:
                        print(color_error(f"❌ {e}"))
                        log_exception("DECRYPT", "clipboard_input", "AES", e)
                        sleep_time = 2 ** attempt
                        print(color_warning(f"⏳ Waiting {sleep_time}s before next attempt..."))
                        print(color_warning(f"⚠️  {max_attempts - attempt} attempt(s) remaining"))
                        time.sleep(sleep_time)
                    else:
                        print(color_error(f"❌ {e}"))
                        log_operation("DECRYPT", "clipboard_input", "AES", "FAILED",
                                     error=f"Maximum attempts reached: {str(e)}")
                        print(color_error("❌ Maximum attempts reached."))

        else:
            print()
            print(color_info(f"📊 Encrypted data size: {len(encrypted_bytes)} bytes"))
            max_key_attempts = 3
            for key_attempt in range(1, max_key_attempts + 1):
                priv_path = safe_input(f"Enter private key file path (attempt {key_attempt}/{max_key_attempts}): ")
                if not priv_path:
                    if key_attempt < max_key_attempts:
                        print(color_warning(f"⚠️  {max_key_attempts - key_attempt} attempt(s) remaining"))
                    continue

                priv_path = clean_path(priv_path)
                if not os.path.exists(priv_path):
                    print(color_error("❌ Private key file not found"))
                    continue

                try:
                    with open(priv_path, 'r') as f:
                        priv_key = f.read()
                    
                    print(f"\n{color_info('🔑 Private key loaded successfully')}\n")
                    
                    max_password_attempts = 3
                    for pwd_attempt in range(1, max_password_attempts + 1):
                        priv_password = safe_input(f"🔐 Private key password (attempt {pwd_attempt}/{max_password_attempts}, Enter if none): ", password=True)
                        priv_password = priv_password if priv_password else None
                        try:
                            plaintext, stored_hash = rsa_decrypt_hybrid_with_hash(encrypted_bytes, priv_key, priv_password)
                            
                            # Verify SHA-256 hash
                            computed_hash = hashlib.sha256(plaintext).hexdigest()
                            if not verify_hash_constant_time(stored_hash, computed_hash):
                                print(color_error(f"❌ Hash verification FAILED!"))
                                print(color_error(f"   Expected: {stored_hash}"))
                                print(color_error(f"   Got:      {computed_hash}"))
                                log_operation("DECRYPT", "clipboard_input", "RSA", "FAILED",
                                             error=f"Hash mismatch: expected {stored_hash}, got {computed_hash}",
                                             additional=f"decrypt_text_from_clipboard | Private key: {os.path.basename(priv_path)}")
                                plaintext = b""  # Clear corrupted plaintext
                                print(color_warning("⚠️  Data may be corrupted"))
                                if pwd_attempt < max_password_attempts:
                                    print(color_warning(f"⚠️  {max_password_attempts - pwd_attempt} attempt(s) remaining"))
                                continue
                            
                            text = plaintext.decode('utf-8')
                            plaintext = b""  # Clear from memory
                            print()
                            print(color_success("✅ Decryption successful!"))
                            print("─" * 60)
                            print(text)
                            print("─" * 60)
                            
                            # Log decrypt from clipboard RSA
                            log_operation("DECRYPT", "clipboard_input", "RSA", "SUCCESS", stored_hash,
                                         additional=f"decrypt_text_from_clipboard | Private key: {os.path.basename(priv_path)}")
                            
                            # Menu for output options
                            print("\n" + color_info("Save/Copy options:"))
                            print("[1] 📋 Copy to clipboard")
                            print("[2] 💾 Save to text file")
                            print("[3] ⏭️  Skip\n")
                            
                            choice = safe_input("Select option (1-3): ")
                            
                            if choice == '1':
                                if HAS_PYPERCLIP:
                                    pyperclip.copy(text)
                                    threading.Thread(target=clear_clipboard_after, args=(CLIPBOARD_CLEAR_TIMEOUT,), daemon=True).start()
                                    print(color_success("✅ Copied to clipboard"))
                                else:
                                    print(color_warning("⚠️  Clipboard not available"))
                            elif choice == '2':
                                output_file = get_unique_filename("decrypted", "txt")
                                if write_file_atomic(output_file, text.encode('utf-8')):
                                    print(color_success(f"✅ Saved to file: {color_bright(output_file)}"))
                                else:
                                    print(color_error("❌ Failed to save file"))
                            elif choice == '3':
                                print(color_info("⏭️  Skipped"))
                            else:
                                print(color_warning("⚠️  Invalid option"))
                            
                            text = ""  # Clear from memory
                            
                            print("\n" + "=" * 60)
                            continue_choice = safe_input(color_info("Decrypt another text? (y/n): "))
                            if continue_choice and continue_choice.lower() == 'y':
                                prompt_decrypt_from_clipboard()  # Recursive call to continue
                                return
                            
                            safe_input("\n👉 Press Enter to continue...")
                            return
                        except ValueError as e:
                            if pwd_attempt < max_password_attempts:
                                print(color_error(f"❌ {e}"))
                                log_exception("DECRYPT", "clipboard_input", "RSA", e)
                                sleep_time = 2 ** pwd_attempt
                                print(color_warning(f"⏳ Waiting {sleep_time}s before next attempt..."))
                                print(color_warning(f"⚠️  {max_password_attempts - pwd_attempt} attempt(s) remaining"))
                                time.sleep(sleep_time)
                            else:
                                print(color_error("❌ Maximum attempts reached."))
                                log_operation("DECRYPT", "clipboard_input", "RSA", "FAILED",
                                             error=f"Maximum attempts reached: {str(e)}",
                                             additional=f"Private key: {os.path.basename(priv_path)}")
                except Exception as e:
                    log_exception("DECRYPT", "clipboard_input", "RSA", e)
                    print(color_error(f"❌ Error: {e}"))

        safe_input("\n👉 Press Enter to continue...")

    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled")
    except Exception as e:
        log_exception("DECRYPT", "clipboard_input", "UNKNOWN", e)
        print(color_error(f"❌ Error: {e}"))
        safe_input("\n👉 Press Enter to continue...")


def generate_and_display_lightning_qr(lnurl: str):
    """
    Generate and display Lightning Network QR code in terminal using ASCII art
    
    CRITICAL SECURITY NOTES:
    - Uses qrcode library with print_ascii() for terminal display
    - High error correction ensures payment accuracy
    - lnurl is NOT modified or altered
    - Prints QR code directly to terminal as ASCII characters (¦ and spaces)
    - No file is created, QR is ephemeral (printed to stdout)
    - invert=True improves terminal readability
    
    Args:
        lnurl: Lightning payment address (must be 104 characters)
    
    Returns:
        None (prints to terminal)
    """
    if not HAS_QRCODE:
        print("\n" + "=" * 60)
        print("⚠️  OPTIONAL: QR Code library not installed")
        print("=" * 60)
        print("\nQR codes are optional. To enable them, install:")
        print("  pip install qrcode[pil]")
        print("\nOr with system package manager:")
        print("  apt install python3-qrcode (Debian/Ubuntu)")
        print("  brew install qrcode (macOS)")
        print("\nFor now, Lightning address displayed as text.")
        print("=" * 60 + "\n")
        print(f"Lightning Address:\n{lnurl}\n")
        return
    
    try:
        # Validate lnurl format
        if not lnurl or len(lnurl) < 50:
            raise ValueError(f"Invalid lnurl: {lnurl}")
        
        # Create QR code with HIGH error correction (critical for payments)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(lnurl)
        qr.make(fit=True)
        
        # Print QR code as ASCII art directly in terminal
        qr.print_ascii(invert=True)
        
    except Exception as e:
        print(color_error(f"❌ Error generating QR code: {e}"))


def prompt_credits():
    try:
        while True:
            display_header()
            print("\n" + "=" * 60)
            print(color_bright("                     CREDITS"))
            print("=" * 60)
            
            print(f"\n{color_info('📋 PROJECT DESCRIPTION:')}\n")
            print("""File Secure Suite - Encryption Tool

FileSecureSuite is a lightweight utility for RSA-4096 key generation and secure file encryption.
It combines AES-256-GCM (symmetric) and RSA-4096 (asymmetric) encryption with 
industry-standard cryptography and full OpenSSL compatibility.
You maintain complete control of your encryption keys.

TECHNOLOGY STACK:
• Python 3.x with cryptography library
• AES-256-GCM encryption (NIST FIPS 197)
• RSA-4096 with OAEP padding (PKCS#1 v2.1)
• PBKDF2 key derivation (OpenSSL 3.0 standard - 600,000 iterations)
• SHA-256 integrity verification
• OpenSSL-compatible key formats (PKCS#8)

HYBRID ENCRYPTION:
• Generates random AES-256 key for each encrypted file
• Encrypts file data with AES-256-GCM (supports unlimited file size)
• Encrypts AES key with RSA-4096 public key (asymmetric security)
• Combines benefits: RSA security + AES performance + unlimited scalability
• File format: Magic + Version + Hash + EncryptedAESKey + Nonce + Ciphertext
• Text uses direct AES-256-GCM with PBKDF2 (password-based)

KEY FEATURES:
• ✅ RSA-4096 key pair generation and management
• ✅ Hybrid encryption (AES-256-GCM + RSA-4096)
• ✅ Support for files of any size
• ✅ Secure key backup and export functionality
• ✅ Public key fingerprint verification
• ✅ Comprehensive audit logging
• ✅ Full OpenSSL compatibility
• ✅ Strong password protection for keys and files

OPEN SOURCE:
FileSecureSuite is open source software. The encryption format is fully
documented and future-proof - your encrypted files remain decryptable
indefinitely, independent of this application.""")

            
            print(f"\n{color_warning('─' * 60)}")
            print(f"\n{color_info('💰 SUPPORT & DONATIONS:')}\n")
            print("If you find FileSecureSuite useful, please consider supporting")
            print("the project with a Lightning Network donation.\n")
            
            lnurl_address = "lnurl1dp68gurn8ghj7ampd3kx2ar0veekzar0wd5xjtnrdakj7tnhv4kxctttdehhwm30d3h82unvwqhk6ctjd9skummcxu6qs3rtcq"
            
            print(f"{color_bright('Lightning Address:')}")
            print(f"\n{color_info(lnurl_address)}\n")
            
            # Menu options
            print(color_bright("Options:"))
            print("[1] View QR Code")
            print("[2] Return to Main Menu\n")
            
            menu_choice = safe_input(color_info("Select option (1-2): "))
            
            if menu_choice == '1':
                while True:
                    clear_screen()
                    display_header()
                    print("\n" + "=" * 60)
                    print(color_bright("           📱 LIGHTNING NETWORK QR CODE"))
                    print("=" * 60 + "\n")
                    
                    # Generate and display QR code as ASCII art
                    generate_and_display_lightning_qr(lnurl_address)
                    
                    print(f"\n{color_bright('Lightning Address:')}")
                    print(f"\n{color_info(lnurl_address)}\n")
                    
                    # QR Code display menu
                    print(color_bright("Options:"))
                    print("[1] View QR Code")
                    print("[2] Return to Main Menu\n")
                    
                    qr_choice = safe_input(color_info("Select option (1-2): "))
                    
                    if qr_choice == '1':
                        continue  # Refresh QR code
                    elif qr_choice == '2' or qr_choice == '':
                        return  # Exit to main menu
                    else:
                        print(color_warning("❌ Invalid option. Press Enter to continue..."))
                        safe_input("")
                        
            elif menu_choice == '2' or menu_choice == '':
                return
            else:
                print(color_warning("❌ Invalid option. Please try again."))
                safe_input(color_info("👉 Press Enter to continue..."))
            
    except Exception as e:
        print(color_error(f"❌ Error: {e}"))
        safe_input("\n👉 Press Enter to continue...")


def backup_keys():
    """Backup selected keys from keys/ to backup/"""
    try:
        ensure_backup_dir()
        
        display_header()
        print("\n" + "=" * 60)
        print(color_bright("              BACKUP KEYS"))
        print("=" * 60)
        
        if not os.path.exists(KEYS_DIR) or not os.listdir(KEYS_DIR):
            print(color_warning("\n⚠️  No keys found in ./keys/"))
            safe_input("\n👉 Press Enter to continue...")
            return
        
        # List all keys
        keys = [f for f in os.listdir(KEYS_DIR) if f.endswith('.pem')]
        if not keys:
            print(color_warning("\n⚠️  No RSA keys found in ./keys/"))
            safe_input("\n👉 Press Enter to continue...")
            return
        
        print(f"\n{color_info('Available keys:')}")
        for i, key in enumerate(keys, 1):
            print(f"  [{i}] {key}")
        
        # Menu for backup options
        while True:
            print(f"\n{color_info('Backup options:')}")
            print("[1] Backup all keys")
            print("[2] Backup selected keys by number")
            print("[3] Cancel\n")
            
            option = safe_input("Select option (1-3): ")
            
            if option == '1':
                # Backup all keys
                backup_count = 0
                for key in keys:
                    try:
                        src = os.path.join(KEYS_DIR, key)
                        dst = os.path.join(BACKUP_DIR, key)
                        with open(src, 'r') as f:
                            content = f.read()
                        with open(dst, 'w') as f:
                            f.write(content)
                        os.chmod(dst, 0o600)
                        backup_count += 1
                    except Exception as e:
                        log_exception("BACKUP", os.path.join(BACKUP_DIR, key), "RSA", e)
                        print(color_error(f"❌ Error backing up {key}: {e}"))
                
                print(f"\n{color_success(f'✅ Backed up {backup_count} key(s) to ./backup/')}")
                log_operation("BACKUP", f"backup_keys", "RSA", "SUCCESS", "", additional=f"Backed up {backup_count} keys (all)")
                safe_input("\n👉 Press Enter to continue...")
                return
            
            elif option == '2':
                # Backup selected keys
                while True:
                    selected_input = safe_input("\nEnter key numbers to backup (comma-separated, e.g. 1,3,5): ")
                    
                    if not selected_input.strip():
                        print(color_warning("⚠️  No keys selected"))
                        retry = safe_input("Try again? (y/n): ")
                        if not retry or retry.lower() != 'y':
                            break
                        continue
                    
                    try:
                        selected_indices = [int(x.strip()) for x in selected_input.split(',')]
                        
                        invalid = [idx for idx in selected_indices if idx < 1 or idx > len(keys)]
                        if invalid:
                            print(color_error(f"❌ Invalid numbers: {invalid}. Valid range: 1-{len(keys)}"))
                            retry = safe_input("Try again? (y/n): ")
                            if not retry or retry.lower() != 'y':
                                break
                            continue
                        
                        if len(selected_indices) != len(set(selected_indices)):
                            print(color_warning("⚠️  Duplicate numbers found, removing..."))
                            selected_indices = list(set(selected_indices))
                            selected_indices.sort()
                        
                        # Backup selected keys
                        backup_count = 0
                        for idx in selected_indices:
                            key = keys[idx - 1]
                            try:
                                src = os.path.join(KEYS_DIR, key)
                                dst = os.path.join(BACKUP_DIR, key)
                                with open(src, 'r') as f:
                                    content = f.read()
                                with open(dst, 'w') as f:
                                    f.write(content)
                                os.chmod(dst, 0o600)
                                backup_count += 1
                                print(f"  ✅ Backed up: {key}")
                            except Exception as e:
                                log_exception("BACKUP", os.path.join(BACKUP_DIR, key), "RSA", e)
                                print(color_error(f"  ❌ Error backing up {key}: {e}"))
                        
                        print(f"\n{color_success(f'✅ Backed up {backup_count} key(s) to ./backup/')}")
                        log_operation("BACKUP", f"backup_keys", "RSA", "SUCCESS", "", additional=f"Backed up {backup_count} keys (selected: {selected_indices})")
                        safe_input("\n👉 Press Enter to continue...")
                        return
                    
                    except ValueError:
                        print(color_error("❌ Invalid input. Use comma-separated numbers (e.g. 1,3,5)"))
                        retry = safe_input("Try again? (y/n): ")
                        if not retry or retry.lower() != 'y':
                            break
            
            elif option == '3':
                print(color_info("Backup cancelled"))
                safe_input("\n👉 Press Enter to continue...")
                return
            
            else:
                print(color_error("❌ Invalid option. Please enter 1, 2, or 3"))
        
    except Exception as e:
        log_exception("BACKUP", "backup_keys", "RSA", e)
        print(color_error(f"❌ Backup error: {e}"))
        safe_input("\n👉 Press Enter to continue...")


def export_public_key():
    """Extract and export public key from private key"""
    try:
        ensure_backup_dir()
        
        display_header()
        print("\n" + "=" * 60)
        print(color_bright("           EXPORT PUBLIC KEY"))
        print("=" * 60)
        
        priv_path = safe_input("\nEnter private key file path: ")
        if not priv_path:
            return
        
        priv_path = clean_path(priv_path)
        
        try:
            with open(priv_path, 'r') as f:
                priv_key_pem = f.read()
        except FileNotFoundError:
            print(color_error("❌ Private key file not found"))
            safe_input("\n👉 Press Enter to continue...")
            return
        except Exception as e:
            print(color_error(f"❌ Could not read private key: {e}"))
            safe_input("\n👉 Press Enter to continue...")
            return
        
        # Try to load private key - first without password, then with if needed
        private_key = None
        
        try:
            private_key = serialization.load_pem_private_key(
                priv_key_pem.encode(),
                password=None
            )
        except Exception:
            # Key is password-protected, ask for password
            max_password_attempts = 3
            password_success = False
            
            for pwd_attempt in range(1, max_password_attempts + 1):
                password = safe_input(f"🔐 Private key password (attempt {pwd_attempt}/{max_password_attempts}, press Enter if none): ", password=True)
                password = password if password else None
                
                # If no password entered, try once with None
                if password is None:
                    try:
                        private_key = serialization.load_pem_private_key(
                            priv_key_pem.encode(),
                            password=None
                        )
                        password_success = True
                        break
                    except Exception as e:
                        print(color_error(f"❌ Key is password-protected"))
                        continue  # Ask for password again
                
                # Decrypt private key with password (PBKDF2 - OpenSSL standard)
                try:
                    private_key = serialization.load_pem_private_key(
                        priv_key_pem.encode(),
                        password.encode('utf-8')
                    )
                    password_success = True
                    break
                except Exception as e:
                    if pwd_attempt < max_password_attempts:
                        print(color_error(f"❌ {e}"))
                        sleep_time = 2 ** pwd_attempt
                        print(color_warning(f"⏳ Waiting {sleep_time}s before next attempt..."))
                        print(color_warning(f"⚠️  {max_password_attempts - pwd_attempt} attempt(s) remaining"))
                        time.sleep(sleep_time)
                    else:
                            print(color_error("❌ Maximum password attempts reached."))
            
            if not password_success:
                print(color_error("❌ Could not decrypt private key"))
                safe_input("\n👉 Press Enter to continue...")
                return
        
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Generate filename for exported public key
        keyname = os.path.splitext(os.path.basename(priv_path))[0]
        keyname = keyname.replace('_private', '')
        public_export_file = os.path.join(BACKUP_DIR, f"{keyname}_public_exported_{get_unique_filename('', 'pem').split('_')[-1]}")
        
        with open(public_export_file, 'w') as f:
            f.write(public_key_pem)
        os.chmod(public_export_file, 0o644)
        
        # Calculate fingerprint
        public_fingerprint = calculate_key_fingerprint(public_key_pem, is_public=True)
        
        print(f"\n{color_success('✅ Public key exported successfully!')}")
        print(f"  File: {color_bright(public_export_file)}")
        print(f"  Fingerprint: {color_bright(public_fingerprint)}")
        
        log_operation("EXPORT", public_export_file, "RSA", "SUCCESS", "", 
                     additional=f"export_public_key | key_fingerprint: {public_fingerprint}")
        
        safe_input("\n👉 Press Enter to continue...")
        
    except Exception as e:
        log_exception("EXPORT", "export_public_key", "RSA", e)
        print(color_error(f"❌ Export error: {e}"))
        safe_input("\n👉 Press Enter to continue...")


def prompt_encrypt_menu():
    """Menu for choosing encrypt text or file"""
    while True:
        display_header()
        print("\n" + "=" * 60)
        print(color_bright("                  ENCRYPT MENU"))
        print("=" * 60)
        print("\n[1] 📝 Encrypt Text")
        print("[2] 📁 Encrypt File")
        print("[3] ↩️  Back to Main Menu\n")
        
        choice = safe_input("Select option (1-3): ")
        
        if choice == '1':
            prompt_encrypt('t')
        elif choice == '2':
            prompt_encrypt('f')
        elif choice == '3':
            return
        else:
            print(color_error("❌ Invalid choice. Please enter 1, 2, or 3"))
            safe_input("👉 Press Enter to continue...")


def prompt_decrypt_menu():
    """Menu for choosing decrypt text or file"""
    while True:
        display_header()
        print("\n" + "=" * 60)
        print(color_bright("                  DECRYPT MENU"))
        print("=" * 60)
        print("\n[1] 📋 Decrypt Text (B64 only)")
        print("[2] 📁 Decrypt File")
        print("[3] ↩️  Back to Main Menu\n")
        
        choice = safe_input("Select option (1-3): ")
        
        if choice == '1':
            prompt_decrypt_from_clipboard()
        elif choice == '2':
            prompt_decrypt()
        elif choice == '3':
            return
        else:
            print(color_error("❌ Invalid choice. Please enter 1, 2, or 3"))
            safe_input("👉 Press Enter to continue...")


def prompt_key_management():
    """Menu for key management options"""
    while True:
        display_header()
        print("\n" + "=" * 60)
        print(color_bright("              KEY MANAGEMENT"))
        print("=" * 60)
        print("\n[1] 💾 Backup Keys")
        print("[2] 📤 Export Public Key from Private")
        print("[3] ↩️  Back to Main Menu\n")
        
        choice = safe_input("Select option (1-3): ")
        
        if choice == '1':
            backup_keys()
        elif choice == '2':
            export_public_key()
        elif choice == '3':
            return
        else:
            print(color_error("❌ Invalid choice. Please enter 1, 2, or 3"))
            safe_input("👉 Press Enter to continue...")


def main():
    while True:
        try:
            display_header()
            display_menu()

            choice = safe_input("Select option (1-7): ")

            if choice == '1':
                prompt_generate_keypair()
            elif choice == '2':
                prompt_encrypt_menu()
            elif choice == '3':
                prompt_decrypt_menu()
            elif choice == '4':
                prompt_key_management()
            elif choice == '5':
                prompt_view_audit_log()
            elif choice == '6':
                prompt_credits()
            elif choice == '7':
                print("\n👋 File Secure Suite v1.0.5 closed. Stay secure!\n")
                sys.exit(0)
            else:
                print("❌ Invalid choice. Please try again.")
                safe_input("👉 Press Enter to continue...")

        except KeyboardInterrupt:
            print("\n\n👋 File Secure Suite v1.0.5 closed.")
            sys.exit(0)
        except Exception as e:
            print(color_error(f"❌ Unexpected error: {e}"))
            safe_input("👉 Press Enter to continue...")


if __name__ == "__main__":
    try:
        if '--genkeys' in sys.argv or '-g' in sys.argv:
            display_header()
            prompt_generate_keypair()
        elif '--help' in sys.argv or '-h' in sys.argv:
            print("""
File Secure Suite v1.0 - Enterprise Encryption Tool

USAGE:
  python3 FileSecureSuite_1_0.py              Interactive mode
  python3 FileSecureSuite_1_0.py --genkeys    Generate RSA keys
  python3 FileSecureSuite_1_0.py --help       Show this help

FEATURES:
  • AES-256-GCM: Password-based symmetric encryption
  • RSA-4096: Public-key hybrid encryption
  • Hash embedded inside encrypted files
  • Automatic integrity verification on decryption
  • Password strength validation
  • Rate limiting with exponential backoff
  • Auto-detection of encryption format
  • Unified decryption: reads .aes, .aes.b64, .rsa, .rsa.b64
  • Audit logging for compliance
  • Clipboard operations with auto-clear
  • Cross-platform support (Windows/Linux/macOS)

SECURITY FEATURES:
  ✅ Buffer overflow protection
  ✅ Base64 strict validation
  ✅ Path traversal protection
  ✅ Maximum password attempts
  ✅ File size validation
  ✅ Post-decrypt verification
  ✅ Comprehensive audit logging

IMPORTANT:
  ⚠️  Keep file extensions (.aes/.rsa or .aes.b64/.rsa.b64)
  ⚠️  They are used for format detection
  ⚠️  Audit logs saved to: ./logs/encryption_audit.log
            """)
        else:
            main()

    except KeyboardInterrupt:
        print("\n\n👋 File Secure Suite v1.0 closed.")
        sys.exit(0)
    except Exception as e:
        print(color_error(f"\n❌ Fatal error: {e}"))
        sys.exit(1)
