"""
Configuration for Digital Watermarking and Content Authenticity Verification System.
Module 2 Only.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Folder settings
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")
KEYS_FOLDER   = os.path.join(BASE_DIR, "keys")

# Ed25519 Key file paths
PRIVATE_KEY_PATH = os.path.join(KEYS_FOLDER, "private_key.pem")
PUBLIC_KEY_PATH  = os.path.join(KEYS_FOLDER, "public_key.pem")

# Ensure required directories exist
for folder in [UPLOAD_FOLDER, OUTPUT_FOLDER, KEYS_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Security limits & file handling
MAX_CONTENT_LENGTH = 30 * 1024 * 1024  # 30 MB upload limit
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32))

# Supported File Extensions by Category
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpeg", "jpg", "bmp", "webp"}
ALLOWED_PDF_EXTENSIONS   = {"pdf"}
ALLOWED_CODE_EXTENSIONS  = {"py", "java", "c", "cpp", "js", "ts", "html", "css", "sh", "sql", "txt", "md"}

ALLOWED_EXTENSIONS = (
    ALLOWED_IMAGE_EXTENSIONS | ALLOWED_PDF_EXTENSIONS | ALLOWED_CODE_EXTENSIONS
)
