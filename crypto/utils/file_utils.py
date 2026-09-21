"""
Secure file utilities for SecureCrypt.

Handles safe temporary file creation, cleanup, and path management.
"""
import os
import uuid
from config import UPLOAD_FOLDER, OUTPUT_FOLDER


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def save_upload(file_bytes: bytes, suffix: str = ".png") -> str:
    """
    Save uploaded bytes to a randomly-named file in the uploads directory.

    Args:
        file_bytes: Raw file bytes.
        suffix:     File extension including leading dot.

    Returns:
        Absolute path to the saved file.
    """
    _ensure_dir(UPLOAD_FOLDER)
    filename = uuid.uuid4().hex + suffix
    path = os.path.join(UPLOAD_FOLDER, filename)
    with open(path, "wb") as f:
        f.write(file_bytes)
    return path


def save_output(file_bytes: bytes, suffix: str = ".png") -> tuple[str, str]:
    """
    Save output bytes to a randomly-named file in the outputs directory.

    Returns:
        (token, absolute_path) — token is used as the download key.
    """
    _ensure_dir(OUTPUT_FOLDER)
    token    = uuid.uuid4().hex
    filename = token + suffix
    path     = os.path.join(OUTPUT_FOLDER, filename)
    with open(path, "wb") as f:
        f.write(file_bytes)
    return token, path


def get_output_path(token: str, suffix: str = ".png") -> str | None:
    """Return the output file path for a token, or None if it doesn't exist."""
    _ensure_dir(OUTPUT_FOLDER)
    path = os.path.join(OUTPUT_FOLDER, token + suffix)
    return path if os.path.isfile(path) else None


def cleanup_file(path: str) -> None:
    """Silently delete a file if it exists."""
    try:
        if path and os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def safe_filename(original: str) -> str:
    """Return a safe random filename with the same extension."""
    ext = ""
    if "." in original:
        ext = "." + original.rsplit(".", 1)[1].lower()
    return uuid.uuid4().hex + ext


# ── Watermark download registry ────────────────────────────────────────────────
_WATERMARK_DOWNLOAD_REGISTRY = {}


def save_watermark_output(file_bytes: bytes, filename: str) -> tuple[str, str]:
    """Save watermarked output bytes and return (download_token, file_path)."""
    _ensure_dir(OUTPUT_FOLDER)
    token = uuid.uuid4().hex
    safe_path = os.path.join(OUTPUT_FOLDER, f"wm_{token}_{filename}")
    with open(safe_path, "wb") as f:
        f.write(file_bytes)
    _WATERMARK_DOWNLOAD_REGISTRY[token] = (safe_path, filename)
    return token, safe_path


def get_watermark_download(token: str) -> tuple[str, str] | None:
    """Retrieve (file_path, filename) for a watermark download token."""
    entry = _WATERMARK_DOWNLOAD_REGISTRY.get(token)
    if entry and os.path.isfile(entry[0]):
        return entry
    return None
