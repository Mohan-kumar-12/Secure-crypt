"""
Image capacity calculation for LSB steganography.

For 1-bit-per-channel LSB embedding:
  raw_bits   = width × height × channels
  raw_bytes  = raw_bits // 8
  usable_bytes = raw_bytes - PAYLOAD_FIXED_HEADER

The fixed header is always stored sequentially before ASEE-selected pixels.
"""
from PIL import Image
from config import PAYLOAD_FIXED_HEADER


class InsufficientCapacityError(Exception):
    """Raised when the payload is too large for the cover image."""


def get_channels(img: Image.Image) -> int:
    """Return the number of channels used for embedding (RGB only, no alpha)."""
    mode = img.mode
    if mode in ("RGB", "RGBA"):
        return 3   # use only R, G, B — preserve alpha
    if mode in ("L",):
        return 1   # grayscale
    if mode in ("P",):
        return 3   # palette → will be converted to RGB
    return len(img.getbands())


def calculate_capacity(img: Image.Image) -> dict:
    """
    Calculate the LSB embedding capacity of an image.

    Args:
        img: PIL Image object.

    Returns:
        dict with:
            width          (int)   — image width in pixels
            height         (int)   — image height in pixels
            channels       (int)   — number of channels used for embedding
            mode           (str)   — PIL image mode
            raw_bits       (int)   — total embeddable bits
            raw_bytes      (int)   — raw bytes capacity
            usable_bytes   (int)   — bytes available for payload (after header)
            usable_kb      (float) — KB available for payload
    """
    channels   = get_channels(img)
    raw_bits   = img.width * img.height * channels
    raw_bytes  = raw_bits // 8
    usable     = max(0, raw_bytes - PAYLOAD_FIXED_HEADER)

    return {
        "width":        img.width,
        "height":       img.height,
        "channels":     channels,
        "mode":         img.mode,
        "raw_bits":     raw_bits,
        "raw_bytes":    raw_bytes,
        "usable_bytes": usable,
        "usable_kb":    round(usable / 1024, 2),
    }


def check_capacity(img: Image.Image, payload_bytes: int) -> None:
    """
    Raise InsufficientCapacityError if the payload won't fit.

    Args:
        img:           Cover image.
        payload_bytes: Total payload size in bytes (including header).
    """
    cap = calculate_capacity(img)
    if payload_bytes > cap["raw_bytes"]:
        raise InsufficientCapacityError(
            f"Payload ({payload_bytes:,} bytes) exceeds image capacity "
            f"({cap['raw_bytes']:,} bytes). "
            "Use a larger image or a shorter message."
        )
