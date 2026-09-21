"""
Image analysis utilities — metadata extraction.
"""
import io
from PIL import Image
from steganography.capacity import calculate_capacity


def analyze_image(img: Image.Image, file_size_bytes: int = 0) -> dict:
    """
    Extract metadata and capacity info from a PIL Image.

    Args:
        img:             PIL Image object.
        file_size_bytes: Original uploaded file size in bytes (optional).

    Returns:
        dict with image metadata and embedding capacity information.
    """
    cap = calculate_capacity(img)

    return {
        "width":         img.width,
        "height":        img.height,
        "mode":          img.mode,
        "channels":      cap["channels"],
        "raw_bytes":     cap["raw_bytes"],
        "usable_bytes":  cap["usable_bytes"],
        "usable_kb":     cap["usable_kb"],
        "file_size_kb":  round(file_size_bytes / 1024, 2) if file_size_bytes else None,
    }
