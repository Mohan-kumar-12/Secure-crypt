"""
Input validation utilities for SecureCrypt.
"""
import io
from PIL import Image
from config import ALLOWED_EXTENSIONS

# Minimum password length
MIN_PASSWORD_LENGTH = 8

# Minimum image dimensions to be useful
MIN_IMAGE_DIMENSION = 32


class ValidationError(Exception):
    """Raised when validation fails."""


def allowed_extension(filename: str) -> bool:
    """Return True if the filename has an allowed extension."""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def validate_image_file(file_bytes: bytes) -> Image.Image:
    """
    Validate that the bytes represent a real, supported image.

    Args:
        file_bytes: Raw bytes from the uploaded file.

    Returns:
        Opened PIL Image object.

    Raises:
        ValidationError: If the file is not a valid supported image.
    """
    try:
        img = Image.open(io.BytesIO(file_bytes))
        img.verify()           # checks header integrity
    except Exception:
        raise ValidationError("The uploaded file is not a valid image.")

    # Re-open after verify (verify() closes the internal stream)
    img = Image.open(io.BytesIO(file_bytes))

    fmt = (img.format or "").upper()
    allowed_formats = {"PNG", "BMP", "TIFF"}
    if fmt not in allowed_formats:
        raise ValidationError(
            f"Unsupported image format: {fmt}. "
            "Please upload a PNG, BMP, or TIFF image."
        )

    if img.width < MIN_IMAGE_DIMENSION or img.height < MIN_IMAGE_DIMENSION:
        raise ValidationError(
            f"Image is too small ({img.width}×{img.height}). "
            f"Minimum dimension: {MIN_IMAGE_DIMENSION}×{MIN_IMAGE_DIMENSION}."
        )

    return img


def validate_password(password: str, confirm: str = None) -> None:
    """
    Validate password requirements.

    Args:
        password: The password string.
        confirm:  Optional confirmation string (must match password).

    Raises:
        ValidationError: If validation fails.
    """
    if not password:
        raise ValidationError("Password must not be empty.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    if confirm is not None and password != confirm:
        raise ValidationError("Passwords do not match.")


def validate_message(message: str) -> None:
    """
    Validate that the secret message is non-empty.

    Raises:
        ValidationError: If validation fails.
    """
    if not message or not message.strip():
        raise ValidationError("Secret message must not be empty.")
