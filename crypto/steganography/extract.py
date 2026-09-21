"""
LSB payload extraction from stego images.

Extraction exactly mirrors sequential embedding:
  1. Read ALL payload bits sequentially in row-major, channel-major order.
  2. First PAYLOAD_FIXED_HEADER * 8 bits → fixed header bytes.
  3. Parse header to get: magic, version, salt, nonce, ciphertext length.
  4. Read the next (ciphertext_length * 8) bits → ciphertext bytes.
  5. Assemble and validate the full payload.

The receiver needs only:
  - The stego image (contains everything except the password).
  - The user's password (used for PBKDF2 key derivation).
"""
import numpy as np
from PIL import Image

from config import PAYLOAD_FIXED_HEADER
from steganography.capacity import get_channels
from utils.payload import parse_payload, PayloadError


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Convert a flat list of bits (MSB first) back to bytes."""
    remainder = len(bits) % 8
    if remainder:
        bits = bits + [0] * (8 - remainder)
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def _read_bits_sequential(arr: np.ndarray, n_channels: int, start_slot: int, count: int) -> list[int]:
    """Read `count` LSBs sequentially starting from `start_slot`."""
    H, W = arr.shape[:2]
    bits = []
    for i in range(count):
        slot = start_slot + i
        r  = slot // (W * n_channels)
        rr = slot  % (W * n_channels)
        c  = rr    // n_channels
        ch = rr    %  n_channels
        if r >= H:
            raise PayloadError("Image too small — ran out of pixels during extraction.")
        bits.append(int(arr[r, c, ch] & 1))
    return bits


def extract_payload(stego_img: Image.Image) -> bytes:
    """
    Extract the hidden binary payload from a stego image.

    Args:
        stego_img: PIL Image loaded from the stego PNG.

    Returns:
        Raw payload bytes (header + ciphertext).

    Raises:
        PayloadError: If no valid SecureCrypt payload is found.
    """
    # ── Normalise ──────────────────────────────────────────────────────────────
    original_mode = stego_img.mode
    has_alpha     = original_mode in ("RGBA", "LA", "PA")

    if original_mode in ("P", "L", "LA"):
        work_img = stego_img.convert("RGB")
    else:
        work_img = stego_img.convert("RGBA" if has_alpha else "RGB")

    n_channels = get_channels(work_img)
    arr        = np.array(work_img, dtype=np.uint8)
    H, W       = arr.shape[:2]

    header_bits_needed = PAYLOAD_FIXED_HEADER * 8
    total_slots = H * W * n_channels
    if total_slots < header_bits_needed:
        raise PayloadError("Image too small to contain a SecureCrypt payload.")

    # ── Step 1: Extract HEADER bytes sequentially ──────────────────────────────
    header_bits  = _read_bits_sequential(arr, n_channels, 0, header_bits_needed)
    header_bytes = _bits_to_bytes(header_bits)

    # ── Step 2: Validate magic and parse ciphertext length ─────────────────────
    import struct
    from config import (
        PAYLOAD_MAGIC, PAYLOAD_VERSION,
        SALT_SIZE, PASSWORD_CIPHERTEXT_SIZE, KEY_WRAP_NONCE_SIZE, PROTECTED_KEY_SIZE, NONCE_SIZE,
    )

    magic = header_bytes[0:4]
    if magic != PAYLOAD_MAGIC:
        raise PayloadError(
            "No valid SecureCrypt payload detected in this image."
        )

    version = header_bytes[4]
    if version != PAYLOAD_VERSION:
        raise PayloadError(f"Unsupported payload version: {version}")

    # v2 layout: FLAGS(1) + SALT(16) + PASS_CIPHERTEXT(32) + KEY_NONCE(12) + PROTECTED_KEY(48) + MSG_NONCE(12) + CT_LEN(4)
    offset = 6 + SALT_SIZE + PASSWORD_CIPHERTEXT_SIZE + KEY_WRAP_NONCE_SIZE + PROTECTED_KEY_SIZE + NONCE_SIZE
    try:
        (ct_len,) = struct.unpack(">I", header_bytes[offset : offset + 4])
    except struct.error:
        raise PayloadError("Malformed payload header.")

    if ct_len == 0:
        raise PayloadError("Payload declares zero ciphertext length.")

    ct_bits_needed = ct_len * 8

    if header_bits_needed + ct_bits_needed > total_slots:
        raise PayloadError(
            f"Image does not have enough pixels to hold the declared payload ({ct_len} bytes)."
        )

    # ── Step 3: Extract CIPHERTEXT bytes sequentially ─────────────────────────
    ct_bits  = _read_bits_sequential(arr, n_channels, header_bits_needed, ct_bits_needed)
    ct_bytes = _bits_to_bytes(ct_bits)

    # ── Step 4: Assemble and validate full payload ─────────────────────────────
    full_payload = header_bytes[:PAYLOAD_FIXED_HEADER] + ct_bytes

    # Final structural validation
    parse_payload(full_payload)   # raises PayloadError on any issue

    return full_payload
