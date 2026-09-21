"""
File Upload Validation & Security Checks.
Path traversal protection, MIME validation, extension checks, and file size limits.
Never executes or evaluates uploaded files as commands.
"""
import os
import re
import io
from PIL import Image
import fitz

from config import (
    ALLOWED_IMAGE_EXTENSIONS,
    ALLOWED_PDF_EXTENSIONS,
    ALLOWED_CODE_EXTENSIONS,
    MAX_CONTENT_LENGTH,
)


class ValidationError(Exception):
    """Raised when file validation fails."""


def sanitize_filename(filename: str) -> str:
    """Sanitize filename against path traversal attacks."""
    if not filename:
        return "unnamed_file"
    filename = os.path.basename(filename)
    filename = re.sub(r"[^\w\.-]", "_", filename)
    return filename or "unnamed_file"


def get_extension(filename: str) -> str:
    """Extract lowercase extension without leading dot."""
    return os.path.splitext(filename)[1].lower().lstrip(".")


def validate_file_size(file_bytes: bytes, max_bytes: int = MAX_CONTENT_LENGTH):
    """Check file byte size limits."""
    if not file_bytes:
        raise ValidationError("File is empty (0 bytes).")
    if len(file_bytes) > max_bytes:
        limit_mb = max_bytes // (1024 * 1024)
        raise ValidationError(f"File size exceeds maximum allowed limit of {limit_mb} MB.")


def validate_image_file(file_bytes: bytes, filename: str) -> Image.Image:
    """Validate that upload is a genuine image."""
    validate_file_size(file_bytes)
    ext = get_extension(filename)
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValidationError(f"Unsupported image format '.{ext}'. Allowed: {', '.join(sorted(ALLOWED_IMAGE_EXTENSIONS))}")

    try:
        img = Image.open(io.BytesIO(file_bytes))
        img.verify()
        # Re-open after verify()
        img = Image.open(io.BytesIO(file_bytes))
        return img
    except Exception as e:
        raise ValidationError(f"Corrupted or invalid image file: {e}")


def validate_pdf_file(file_bytes: bytes, filename: str):
    """Validate that upload is a genuine PDF file."""
    validate_file_size(file_bytes)
    ext = get_extension(filename)
    if ext not in ALLOWED_PDF_EXTENSIONS:
        raise ValidationError("File must be a .pdf document.")

    try:
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        if len(doc) == 0:
            doc.close()
            raise ValidationError("PDF file contains zero pages.")
        doc.close()
    except Exception as e:
        raise ValidationError(f"Corrupted or invalid PDF file: {e}")


def validate_source_code_file(file_bytes: bytes, filename: str):
    """Validate source code file format and encoding."""
    validate_file_size(file_bytes)
    ext = get_extension(filename)
    if ext not in ALLOWED_CODE_EXTENSIONS:
        raise ValidationError(f"Unsupported source code extension '.{ext}'. Allowed: {', '.join(sorted(ALLOWED_CODE_EXTENSIONS))}")
