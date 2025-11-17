#!/usr/bin/env python3
"""
File Secure Suite v1.0 - Enterprise Encryption Suite
Secure file and text encryption with AES-256-GCM and RSA-4096
"""

import os
import sys
import getpass
import time
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

# Ensure qrcode is installed for QR code generation
try:
    import qrcode
    from PIL import Image
except ImportError:
    print("Installing required QR code libraries...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "qrcode[pil]"])
    import qrcode
    from PIL import Image

# Set restrictive umask to prevent file permission issues
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
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False


def verify_hash_constant_time(stored_hash_hex: str, computed_hash_hex: str) -> bool:
    stored_bytes = bytes.fromhex(stored_hash_hex)
    computed_bytes = bytes.fromhex(computed_hash_hex)
    return hmac.compare_digest(stored_bytes, computed_bytes)


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


# Detect operating system
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'encryption_audit.log')
PBKDF2_ITERATIONS = 480000
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


def log_operation(operation: str, filepath: str, method: str, status: str, 
                  file_hash: str = "", error: str = "", additional: str = "", traceback_str: str = ""):
    ensure_log_dir()
    try:
        timestamp = datetime.datetime.now().isoformat()
        basename = os.path.basename(filepath)
        log_entry = f"[{timestamp}] {operation:12} | file: {basename:40} | method: {method:5} | status: {status:15}"
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
        # Ensure log file has restrictive permissions
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
        
        # Debug: log che abbiamo ricevuto input
        if password and result:
            # Non stampare la password, solo la conferma
            import sys
            sys.stderr.write("[DEBUG] Password received (length: {})\n".format(len(result)))
        
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
            print(color_error("❌ File not found"))
            return False
        size = os.path.getsize(filepath)
        if size == 0:
            print(color_error("❌ File is empty"))
            return False
        if size > MAX_FILE_SIZE:
            print(color_error(f"❌ File too large (max {format_size(MAX_FILE_SIZE)})"))
            return False
        return True
    except Exception as e:
        print(color_error(f"❌ Size check failed: {e}"))
        return False


def write_file_atomic(filepath: str, data: bytes) -> bool:
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
        try:
            if os.path.exists(temp_filepath):
                os.remove(temp_filepath)
        except:
            pass
        print(color_error(f"❌ Write error: {e}"))
        return False


def get_unique_filename(base_name: str, extension: str = "") -> str:
    timestamp = int(time.time() * 1000)
    random_suffix = random.randint(10000, 99999)
    if extension and not extension.startswith('.'):
        extension = '.' + extension
    return f"{base_name}_{timestamp}_{random_suffix}{extension}"


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

        if file_size < 100:
            return 'aes'
        elif file_size > 600:
            return 'rsa'
        else:
            with open(file_path, 'rb') as f:
                header = f.read(min(512, file_size))
            byte_counts = {}
            for byte in header[:100]:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            entropy = len(byte_counts) / 256.0
            return 'rsa' if entropy > 0.8 else 'aes'

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
    print(color_bright("      File Secure Suite v1.0 - Encryption Tool"))
    print("=" * 60)


def display_menu():
    print("\n" + "=" * 60)
    print(color_bright("                    MAIN MENU"))
    print("=" * 60)
    print("\n[1] 🔑  Generate RSA-4096 Key Pair")
    print("[2] 🔐  Encrypt Text or File")
    print("[3] 🔓  Decrypt Files")
    print("[4] 📋  Decrypt Text")
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
    key, salt = derive_key_from_password(password)
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, data, None)
    hash_bytes = bytes.fromhex(file_hash)
    
    magic = b"FSS1"
    version = struct.pack('>B', 1)
    result = magic + version + struct.pack('>I', len(hash_bytes)) + hash_bytes + salt + nonce + ciphertext
    return result


def aes_decrypt_with_hash(encrypted_data: bytes, password: str) -> Tuple[bytes, str]:
    """
    Decrypt AES-256-GCM encrypted data with hash verification.
    
    NOTE: Returned plaintext should be handled carefully and cleared from memory
    after use. Caller is responsible for: del plaintext or plaintext = b""
    """
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
    
    min_required = 5 + 4 + hash_length + 16 + 12 + 1
    if len(encrypted_data) < min_required:
        raise ValueError(f"Invalid format (got {len(encrypted_data)} bytes, need {min_required})")
    
    hash_bytes = encrypted_data[9:9+hash_length]
    hash_hex = hash_bytes.hex()
    salt = encrypted_data[9+hash_length:9+hash_length+16]
    nonce = encrypted_data[9+hash_length+16:9+hash_length+28]
    ciphertext = encrypted_data[9+hash_length+28:]

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
                                 private_key_password: Optional[str] = None) -> Tuple[bytes, str]:
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
        pw_bytes = private_key_password.encode() if private_key_password else None
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            pw_bytes
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


def generate_rsa_keypair(password: Optional[str] = None) -> Tuple[str, str]:
    print("\n🔄 Generating RSA-4096 key pair...")
    print("   This may take 1-2 minutes. Please wait...\n")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )

    public_key = private_key.public_key()

    encryption_algo = (
        serialization.BestAvailableEncryption(password.encode()) 
        if password 
        else serialization.NoEncryption()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    ).decode('utf-8')

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem


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


def prompt_generate_keypair():
    try:
        display_header()
        print("\n🔑 RSA-4096 KEY PAIR GENERATION\n")

        keyname = safe_input("Enter key pair name (e.g., 'mykey'): ")
        if not keyname:
            return

        keyname = sanitize_filename(keyname)

        protect = safe_input("\nProtect private key with password? (y/n): ")
        password = None

        if protect and protect.lower() == 'y':
            max_attempts = 3
            for attempt in range(max_attempts):
                password = safe_input("🔑 Enter password: ", password=True)
                if not password:
                    print("⚠️  No password entered. Generating unprotected keys.")
                    break
                
                is_valid, msg = validate_password_strength(password)
                print(color_info(msg))
                if not is_valid:
                    if attempt < max_attempts - 1:
                        print(color_warning(f"⚠️  {max_attempts - attempt - 1} attempt(s) remaining"))
                    continue
                
                # Confirm password
                password_confirm = safe_input("🔑 Confirm password: ", password=True)
                if password != password_confirm:
                    print(color_error("❌ Passwords do not match. Try again."))
                    if attempt < max_attempts - 1:
                        print(color_warning(f"⚠️  {max_attempts - attempt - 1} attempt(s) remaining"))
                    continue
                
                break

        print("\n🔄 Generating key pair...")
        private_pem, public_pem = generate_rsa_keypair(password)

        private_file = get_unique_filename(f"{keyname}_private", "pem")
        public_file = get_unique_filename(f"{keyname}_public", "pem")

        if not write_file_atomic(private_file, private_pem.encode('utf-8')):
            safe_input("\n👉 Press Enter to continue...")
            return
        os.chmod(private_file, 0o600)

        if not write_file_atomic(public_file, public_pem.encode('utf-8')):
            safe_input("\n👉 Press Enter to continue...")
            return

        print(f"\n{color_success('✅ Keys generated successfully!')}")
        print(f"  Private key: {color_bright(private_file)}")
        print(f"  Public key:  {color_bright(public_file)}")
        if password:
            print(f"  🔐 Private key is PASSWORD PROTECTED")
        print("\n⚠️  IMPORTANT: Keep private key secure!")

        safe_input("\n👉 Press Enter to continue...")

    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled")
    except Exception as e:
        print(color_error(f"❌ Error: {e}"))
        safe_input("\n👉 Press Enter to continue...")


def prompt_encrypt():
    try:
        display_header()
        print("\n🔐 ENCRYPTION MODE\n")

        print(f"{color_info('─' * 60)}")
        print(f"{color_warning('⚠️  FILE SIZE LIMIT')}")
        print(f"{color_info('─' * 60)}")
        print(f"  📁 Maximum file size: {color_bright('1 GB')}")
        print(f"{color_info('─' * 60)}\n")

        data_type = safe_input("Encrypt [t]ext or [f]ile? (t/f): ")
        if not data_type or data_type not in ['t', 'f']:
            print(color_error("❌ Invalid choice. Please enter 't' or 'f'"))
            safe_input("\n👉 Press Enter to continue...")
            return

        method = safe_input("\nEncryption method: [a]ES-256 or [r]SA-4096? (a/r): ")
        if not method or method not in ['a', 'r']:
            print(color_error("❌ Invalid choice. Please enter 'a' or 'r'"))
            safe_input("\n👉 Press Enter to continue...")
            return

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
                print(color_error("❌ No file path provided"))
                safe_input("\n👉 Press Enter to continue...")
                return
            filepath = clean_path(filepath)
            if not validate_file_size(filepath):
                safe_input("\n👉 Press Enter to continue...")
                return
            with open(filepath, 'rb') as f:
                data = f.read()
            file_hash = calculate_file_hash(filepath)
            # Get original filename for encrypted filename
            original_filename = sanitize_filename(os.path.basename(filepath))

        if method == 'a':
            max_attempts = 3
            password = None
            for attempt in range(max_attempts):
                password = safe_input(f"🔐 Enter password (attempt {attempt + 1}/{max_attempts}): ", password=True)
                if not password:
                    if attempt < max_attempts - 1:
                        print(color_warning(f"⚠️  {max_attempts - attempt - 1} attempt(s) remaining"))
                    continue
                is_valid, msg = validate_password_strength(password)
                if not is_valid:
                    print(color_error(f"❌ {msg}"))
                    if attempt < max_attempts - 1:
                        print(color_warning(f"⚠️  {max_attempts - attempt - 1} attempt(s) remaining"))
                    continue
                
                # Confirm password
                password_confirm = safe_input("🔐 Confirm password: ", password=True)
                if password != password_confirm:
                    print(color_error("❌ Passwords do not match. Try again."))
                    if attempt < max_attempts - 1:
                        print(color_warning(f"⚠️  {max_attempts - attempt - 1} attempt(s) remaining"))
                    password = None
                    continue
                
                break
            
            if not password:
                print(color_error("❌ No valid password provided"))
                safe_input("\n👉 Press Enter to continue...")
                return

            encrypted_data = aes_encrypt_with_hash(data, password, file_hash)
            # For text: use generic name, for files: include original filename
            if data_type == 't':
                output_base = "encrypted"
            else:
                # Include full original filename in encrypted filename
                output_base = f"encrypted_{original_filename}"
            output_file = get_unique_filename(output_base, "aes")

            if not write_file_atomic(output_file, encrypted_data):
                safe_input("\n👉 Press Enter to continue...")
                return

            print(f"\n{color_success('✅ Encryption successful!')}")
            print(f"  Output:     {color_bright(output_file)}")
            
            # For text only: also create base64 version
            if data_type == 't':
                output_b64_file = output_file + ".b64"
                b64_data = base64.b64encode(encrypted_data).decode('ascii')
                if write_file_atomic(output_b64_file, b64_data.encode('ascii')):
                    print(f"  Base64:     {color_bright(output_b64_file)}")
            
            log_operation("ENCRYPT", output_file, "AES", "SUCCESS", file_hash)

        else:
            pubkey_path = safe_input("\nEnter public key file path: ")
            if not pubkey_path:
                return
            pubkey_path = clean_path(pubkey_path)
            
            try:
                with open(pubkey_path, 'r') as f:
                    public_key_pem = f.read()
            except FileNotFoundError:
                print(color_error("❌ Public key file not found"))
                safe_input("\n👉 Press Enter to continue...")
                return
            except Exception as e:
                print(color_error(f"❌ Could not read public key: {e}"))
                safe_input("\n👉 Press Enter to continue...")
                return

            if not validate_rsa_key(public_key_pem, is_public=True):
                print(color_error("❌ Invalid public key"))
                safe_input("\n👉 Press Enter to continue...")
                return

            encrypted_data = rsa_encrypt_hybrid_with_hash(data, public_key_pem, file_hash)
            # For text: use generic name, for files: include original filename
            if data_type == 't':
                output_base = "encrypted"
            else:
                # Include full original filename in encrypted filename
                output_base = f"encrypted_{original_filename}"
            output_file = get_unique_filename(output_base, "rsa")

            if not write_file_atomic(output_file, encrypted_data):
                safe_input("\n👉 Press Enter to continue...")
                return

            print(f"\n{color_success('✅ Encryption successful!')}")
            print(f"  Output:     {color_bright(output_file)}")
            
            # For text only: also create base64 version
            if data_type == 't':
                output_b64_file = output_file + ".b64"
                b64_data = base64.b64encode(encrypted_data).decode('ascii')
                if write_file_atomic(output_b64_file, b64_data.encode('ascii')):
                    print(f"  Base64:     {color_bright(output_b64_file)}")
            
            log_operation("ENCRYPT", output_file, "RSA", "SUCCESS", file_hash)

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
                    print("ℹ️  Detected base64 format (.b64)")
                except Exception as e:
                    print(color_error(f"❌ Invalid base64 file: {e}"))
                    safe_input("\n👉 Press Enter to continue...")
                    return
            else:
                try:
                    encrypted_data = base64.b64decode(raw_data, validate=True)
                    print("ℹ️  Detected base64 format (content)")
                except Exception:
                    encrypted_data = raw_data
                    print("ℹ️  Detected binary format")
        except Exception as e:
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
                    
                    # Preserve original filename from the beginning of plaintext
                    original_name = None
                    try:
                        # Try to extract original filename if stored
                        parts = plaintext.split(b'\x00', 1)
                        if len(parts) == 2 and len(parts[0]) < 256:
                            original_name = parts[0].decode('utf-8', errors='ignore')
                            plaintext = parts[1]
                    except:
                        pass
                    
                    # If no original name found, extract from encrypted file
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
                    plaintext = b""  # Clear from memory after writing
                    print(f"\n{color_success('✅ Decryption successful!')}")
                    print(f"  Output file: {color_bright(output_file)}")
                    print(f"  ✅ Integrity verified (SHA-256)")
                    log_operation("DECRYPT", filepath, "AES", "SUCCESS", stored_hash)
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
                    print(color_error("❌ Private key file not found"))
                    retry = safe_input("Try another key? (y/n): ")
                    if not retry or retry.lower() != 'y':
                        safe_input("\n👉 Press Enter to continue...")
                        return
                    continue
                except Exception as e:
                    print(color_error(f"❌ Could not read private key: {e}"))
                    retry = safe_input("Try another key? (y/n): ")
                    if not retry or retry.lower() != 'y':
                        safe_input("\n👉 Press Enter to continue...")
                        return
                    continue
                
                try:
                    max_password_attempts = 3
                    for pwd_attempt in range(1, max_password_attempts + 1):
                        priv_password = safe_input(f"🔐 Private key password (attempt {pwd_attempt}/{max_password_attempts}, press Enter if none): ", password=True)
                        priv_password = priv_password if priv_password else None
                        try:
                            plaintext, stored_hash = rsa_decrypt_hybrid_with_hash(encrypted_data, priv_key, priv_password)
                            
                            # Preserve original filename from the beginning of plaintext
                            original_name = None
                            try:
                                # Try to extract original filename if stored
                                parts = plaintext.split(b'\x00', 1)
                                if len(parts) == 2 and len(parts[0]) < 256:
                                    original_name = parts[0].decode('utf-8', errors='ignore')
                                    plaintext = parts[1]
                            except:
                                pass
                            
                            # If no original name found, extract from encrypted file
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
                            log_operation("DECRYPT", filepath, "RSA", "SUCCESS", stored_hash)
                            safe_input("\n👉 Press Enter to continue...")
                            return
                        except ValueError as e:
                            if pwd_attempt < max_password_attempts:
                                print(color_error(f"❌ {e}"))
                                sleep_time = 2 ** pwd_attempt
                                print(color_warning(f"⏳ Waiting {sleep_time}s before next attempt..."))
                                print(color_warning(f"⚠️  {max_password_attempts - pwd_attempt} attempt(s) remaining"))
                                time.sleep(sleep_time)
                            else:
                                print(color_error("❌ Maximum password attempts reached."))
                                retry_key = safe_input("Try another key? (y/n): ")
                                if not retry_key or retry_key.lower() != 'y':
                                    safe_input("\n👉 Press Enter to continue...")
                                    return
                                break  # Esce dal loop password, torna a chiedere chiave
                except Exception as e:
                    print(color_error(f"❌ Error: {e}"))
                    retry = safe_input("Try another key? (y/n): ")
                    if not retry or retry.lower() != 'y':
                        safe_input("\n👉 Press Enter to continue...")
                        return
                    continue

        safe_input("\n👉 Press Enter to continue...")

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
        print(color_error(f"❌ Error: {e}"))
        safe_input("\n👉 Press Enter to continue...")


def prompt_decrypt_from_clipboard():
    try:
        display_header()
        print("\n📋 DECRYPT TEXT\n")

        print(color_info("Paste your encrypted text (base64 or binary encoded)"))
        print("Paste your encrypted text below (press Enter twice to finish):\n")
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
            print(color_error("❌ No text provided"))
            safe_input("\n👉 Press Enter to continue...")
            return

        try:
            encrypted_bytes = base64.b64decode(text_input, validate=True)
        except Exception:
            encrypted_bytes = text_input.encode('utf-8')

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
                    text = plaintext.decode('utf-8')
                    plaintext = b""  # Clear from memory
                    print()
                    print(color_success("✅ Decryption successful!"))
                    print("─" * 60)
                    print(text)
                    print("─" * 60)
                    
                    # Menu for output options
                    print("\n" + color_info("Save/Copy options:"))
                    print("[1] 📋 Copy to clipboard")
                    print("[2] 💾 Save to text file")
                    print("[3] ⏭️  Skip\n")
                    
                    choice = safe_input("Select option (1-3): ")
                    
                    if choice == '1':
                        if HAS_PYPERCLIP:
                            pyperclip.copy(text)
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
                        sleep_time = 2 ** attempt
                        print(color_warning(f"⏳ Waiting {sleep_time}s before next attempt..."))
                        print(color_warning(f"⚠️  {max_attempts - attempt} attempt(s) remaining"))
                        time.sleep(sleep_time)
                    else:
                        print(color_error(f"❌ {e}"))
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
                    max_password_attempts = 3
                    for pwd_attempt in range(1, max_password_attempts + 1):
                        priv_password = safe_input(f"🔐 Private key password (attempt {pwd_attempt}/{max_password_attempts}, Enter if none): ", password=True)
                        priv_password = priv_password if priv_password else None
                        try:
                            plaintext, stored_hash = rsa_decrypt_hybrid_with_hash(encrypted_bytes, priv_key, priv_password)
                            text = plaintext.decode('utf-8')
                            plaintext = b""  # Clear from memory
                            print()
                            print(color_success("✅ Decryption successful!"))
                            print("─" * 60)
                            print(text)
                            print("─" * 60)
                            
                            # Menu for output options
                            print("\n" + color_info("Save/Copy options:"))
                            print("[1] 📋 Copy to clipboard")
                            print("[2] 💾 Save to text file")
                            print("[3] ⏭️  Skip\n")
                            
                            choice = safe_input("Select option (1-3): ")
                            
                            if choice == '1':
                                if HAS_PYPERCLIP:
                                    pyperclip.copy(text)
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
                            if pwd_attempt < max_password_attempts:
                                print(color_error(f"❌ {e}"))
                                sleep_time = 2 ** pwd_attempt
                                print(color_warning(f"⏳ Waiting {sleep_time}s before next attempt..."))
                                print(color_warning(f"⚠️  {max_password_attempts - pwd_attempt} attempt(s) remaining"))
                                time.sleep(sleep_time)
                            else:
                                print(color_error("❌ Maximum attempts reached."))
                except Exception as e:
                    print(color_error(f"❌ Error: {e}"))

        safe_input("\n👉 Press Enter to continue...")

    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled")
    except Exception as e:
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
            print("""File Secure Suite v1.0 - Encryption Tool

FileSecureSuite is lightweight encryption utility that lets you generate RSA keys,
encrypt and decrypt text or files using AES and RSA.
Built with cryptographic best practices, it combines AES-256-GCM for
symmetric encryption and RSA-4096 for hybrid encryption scenarios.
You stay in full control of your encryption keys.

TECHNOLOGY STACK:
• Python 3.x with cryptography library
• PBKDF2 key derivation (480,000 iterations)
• SHA-256 hashing for integrity
• OpenSSL-compatible formats""")
            
            print(f"\n{color_warning('─' * 60)}")
            print(f"\n{color_info('💰 SUPPORT & DONATIONS:')}\n")
            print("If you find FileSecureSuite useful, please consider supporting")
            print("the project with a Lightning Network donation.\n")
            
            # Show Lightning Address
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


def main():
    while True:
        try:
            display_header()
            display_menu()

            choice = safe_input("Select option (1-7): ")

            if choice == '1':
                prompt_generate_keypair()
            elif choice == '2':
                prompt_encrypt()
            elif choice == '3':
                prompt_decrypt()
            elif choice == '4':
                prompt_decrypt_from_clipboard()
            elif choice == '5':
                prompt_view_audit_log()
            elif choice == '6':
                prompt_credits()
            elif choice == '7':
                print("\n👋 File Secure Suite v1.0 closed. Stay secure!\n")
                sys.exit(0)
            else:
                print("❌ Invalid choice. Please try again.")
                safe_input("👉 Press Enter to continue...")

        except KeyboardInterrupt:
            print("\n\n👋 File Secure Suite v1.0 closed.")
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
