"""
Application configuration for SecureCrypt Steganography System.

Payload Version 2 — Two-Key Architecture with Password Ciphertext Storage
=========================================================================
The password-derived key protects a random AES session key (key wrapping).
The user's password is converted into a ciphertext/numerical representation.
This password ciphertext is stored directly in the stego image payload header.
The receiver uses the password ciphertext/numbers to decrypt the message.
"""
import os

# ─── Cryptography ─────────────────────────────────────────────────────────────
PBKDF2_ITERATIONS = 600_000      # NIST SP 800-132 recommended minimum
PBKDF2_HASH       = "sha256"
KEY_SIZE          = 32           # 256-bit AES key
SALT_SIZE         = 16           # 128-bit random salt
NONCE_SIZE        = 12           # 96-bit GCM nonce (standard)
GCM_TAG_SIZE      = 16           # 128-bit authentication tag

# Password Ciphertext constants
PASSWORD_CIPHERTEXT_SIZE = 32    # 256-bit password ciphertext stored in payload header

# Key-wrapping constants
KEY_WRAP_NONCE_SIZE   = 12       # 96-bit GCM nonce for key wrapping
PROTECTED_KEY_SIZE    = KEY_SIZE + GCM_TAG_SIZE   # 48 bytes (32-byte key + 16-byte tag)

# ─── File Handling ─────────────────────────────────────────────────────────────
BASE_DIR           = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER      = os.path.join(BASE_DIR, "uploads")
OUTPUT_FOLDER      = os.path.join(BASE_DIR, "outputs")
KEYS_FOLDER        = os.path.join(BASE_DIR, "keys")
PRIVATE_KEY_PATH   = os.path.join(KEYS_FOLDER, "private_key.pem")
PUBLIC_KEY_PATH    = os.path.join(KEYS_FOLDER, "public_key.pem")

MAX_CONTENT_LENGTH = 30 * 1024 * 1024   # 30 MB upload limit
ALLOWED_EXTENSIONS = {"png", "bmp", "tiff", "tif"}

# Watermarking extension sets
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpeg", "jpg", "bmp", "webp"}
ALLOWED_PDF_EXTENSIONS   = {"pdf"}
ALLOWED_CODE_EXTENSIONS  = {
    "py", "java", "c", "cpp", "h", "hpp", "js", "ts", "jsx", "tsx", "html", "htm",
    "css", "sh", "bash", "sql", "json", "yaml", "yml", "txt", "md", "rb", "php",
    "go", "rs", "cs", "swift", "kt"
}

# ─── Flask ─────────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32))

# ─── Payload ──────────────────────────────────────────────────────────────────
# Binary payload layout v2 (Two-Key Architecture with Password Ciphertext):
#   MAGIC              4 bytes   "SCST"
#   VERSION            1 byte    0x02
#   FLAGS              1 byte    reserved = 0x00
#   SALT              16 bytes   PBKDF2 random salt
#   PASS_CIPHERTEXT   32 bytes   Password converted ciphertext bytes
#   KEY_NONCE         12 bytes   Key-wrapping AES-GCM nonce
#   PROTECTED_KEY     48 bytes   AES-GCM(session_key) = 32-byte encrypted key + 16-byte GCM tag
#   MSG_NONCE         12 bytes   Message encryption AES-GCM nonce
#   CT_LEN             4 bytes   big-endian uint32 (ciphertext + 16-byte GCM tag)
#   CIPHERTEXT        variable   AES-GCM ciphertext + 16-byte GCM tag
PAYLOAD_MAGIC        = b"SCST"
PAYLOAD_VERSION      = 0x02
PAYLOAD_FLAGS        = 0x00
PAYLOAD_FIXED_HEADER = (
    4                         # MAGIC
    + 1                       # VERSION
    + 1                       # FLAGS
    + SALT_SIZE               # 16 — PBKDF2 salt
    + PASSWORD_CIPHERTEXT_SIZE # 32 — password ciphertext bytes
    + KEY_WRAP_NONCE_SIZE     # 12 — key-wrapping nonce
    + PROTECTED_KEY_SIZE      # 48 — protected session key (encrypted + tag)
    + NONCE_SIZE              # 12 — message encryption nonce
    + 4                       # CT_LEN
)   # Total: 130 bytes

# Number of LSB positions reserved for the fixed header (1 bit per position across RGB)
# 130 bytes × 8 bits = 1040 bit-slots → stored sequentially before ASEE
HEADER_BIT_SLOTS = PAYLOAD_FIXED_HEADER * 8
