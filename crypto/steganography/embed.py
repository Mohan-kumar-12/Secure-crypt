"""
LSB payload embedding into cover images.

Embedding strategy:
  ALL payload bits (header + ciphertext) are embedded sequentially in
  row-major, channel-major order:
    slot 0  → pixel(0,   0,   R)
    slot 1  → pixel(0,   0,   G)
    slot 2  → pixel(0,   0,   B)
    slot 3  → pixel(0,   1,   R)
    ...

  This guarantees bit-perfect extraction: the receiver reads the same
  sequential positions without needing to reconstruct any ranking.

  The Adaptive Secure Embedding Engine (ASEE) is used for ANALYSIS and
  REPORTING purposes — it computes which regions of the image are most
  suitable for hiding data (high-texture areas). The sequential embedding
  order ensures correctness; ASEE informs the security analysis displayed
  in the UI.

  Only the least significant bit of each embedding channel is modified.
  The result is always saved as lossless PNG.
"""
import io
import numpy as np
from PIL import Image

from steganography.capacity import get_channels, check_capacity


def _bytes_to_bits(data: bytes) -> list[int]:
    """Convert bytes to a flat list of bits (MSB first per byte)."""
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def embed_payload(cover_img: Image.Image, payload: bytes) -> Image.Image:
    """
    Embed a binary payload into a cover image using sequential LSB steganography.

    Args:
        cover_img: PIL Image (cover image — RGB, RGBA, BMP, etc.).
        payload:   Packed binary payload bytes from utils.payload.build_payload().

    Returns:
        New PIL Image with the payload embedded (lossless PNG-safe).

    Raises:
        InsufficientCapacityError: If payload is too large.
    """
    # ── Capacity check ────────────────────────────────────────────────────────
    check_capacity(cover_img, len(payload))

    # ── Normalise image ───────────────────────────────────────────────────────
    original_mode = cover_img.mode
    has_alpha = original_mode in ("RGBA", "LA", "PA")

    if original_mode in ("P", "L", "LA"):
        work_img = cover_img.convert("RGB")
    else:
        work_img = cover_img.convert("RGBA" if has_alpha else "RGB")

    n_channels = get_channels(work_img)   # 3 for RGB/RGBA (alpha excluded)
    arr = np.array(work_img, dtype=np.uint8).copy()
    H, W = arr.shape[:2]

    # ── Convert payload to bits ───────────────────────────────────────────────
    payload_bits = _bytes_to_bits(payload)
    total_bits   = len(payload_bits)
    total_slots  = H * W * n_channels

    if total_bits > total_slots:
        raise ValueError("Payload exceeds image bit-slot count — capacity check missed this.")

    # ── Embed all bits sequentially ───────────────────────────────────────────
    # Sequential order: pixel (r, c), channels 0..n_channels-1
    # Slot formula:
    #   slot = r * (W * n_channels) + c * n_channels + ch
    for slot, bit in enumerate(payload_bits):
        r  = slot // (W * n_channels)
        rr = slot  % (W * n_channels)
        c  = rr    // n_channels
        ch = rr    %  n_channels
        arr[r, c, ch] = (arr[r, c, ch] & 0xFE) | bit

    # ── Reconstruct image ─────────────────────────────────────────────────────
    stego = Image.fromarray(arr, mode=work_img.mode)
    return stego


def image_to_png_bytes(img: Image.Image) -> bytes:
    """Encode a PIL Image as PNG bytes (lossless)."""
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=False, compress_level=1)
    return buf.getvalue()
