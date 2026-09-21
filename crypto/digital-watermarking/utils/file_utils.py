"""
Temporary file storage management, download token tracking, and cleanup.
Uses secure random tokens — avoids exposing internal directory structures.
"""
import os
import uuid
import time
from typing import Tuple, Optional

from config import OUTPUT_FOLDER, UPLOAD_FOLDER

# Token registry mapping download_token -> (file_path, filename)
_DOWNLOAD_REGISTRY = {}


def save_output(file_bytes: bytes, filename: str) -> Tuple[str, str]:
    """
    Save generated protected output bytes to temp storage and return download token.

    Args:
        file_bytes: Protected file data bytes.
        filename:   Suggested filename (e.g. 'watermarked_image.png').

    Returns:
        Tuple of (download_token, file_path)
    """
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    token = uuid.uuid4().hex
    safe_path = os.path.join(OUTPUT_FOLDER, f"{token}_{filename}")

    with open(safe_path, "wb") as f:
        f.write(file_bytes)

    _DOWNLOAD_REGISTRY[token] = {
        "path": safe_path,
        "filename": filename,
        "created_at": time.time(),
    }

    return token, safe_path


def get_download_file(token: str) -> Optional[Tuple[str, str]]:
    """
    Retrieve file path and filename for a valid download token.

    Returns:
        Tuple of (file_path, filename) or None.
    """
    entry = _DOWNLOAD_REGISTRY.get(token)
    if entry and os.path.exists(entry["path"]):
        return entry["path"], entry["filename"]
    return None


def cleanup_temp_files(max_age_seconds: int = 3600):
    """Clean up files older than max_age_seconds."""
    now = time.time()
    for folder in [OUTPUT_FOLDER, UPLOAD_FOLDER]:
        if not os.path.exists(folder):
            continue
        for fname in os.listdir(folder):
            fpath = os.path.join(folder, fname)
            try:
                if os.path.isfile(fpath) and (now - os.path.getmtime(fpath) > max_age_seconds):
                    os.remove(fpath)
            except Exception:
                pass
