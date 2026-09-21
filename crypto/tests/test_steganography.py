"""
Steganography tests for SecureCrypt (Payload v2 with Password Ciphertext).
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import io
import pytest
import numpy as np
from PIL import Image

from steganography.embed import embed_payload, image_to_png_bytes
from steganography.extract import extract_payload
from steganography.capacity import calculate_capacity, check_capacity, InsufficientCapacityError
from utils.payload import build_payload, parse_payload
from config import SALT_SIZE, PASSWORD_CIPHERTEXT_SIZE, NONCE_SIZE, KEY_WRAP_NONCE_SIZE, PROTECTED_KEY_SIZE


def make_test_image(width=200, height=200, mode="RGB", seed=42) -> Image.Image:
    """Create a deterministic test image with texture (not solid color)."""
    rng = np.random.default_rng(seed)
    arr = rng.integers(0, 256, (height, width, 3), dtype=np.uint8)
    return Image.fromarray(arr, mode="RGB")


def make_test_payload(msg_size: int = 32) -> bytes:
    """Build a minimal valid test payload with exactly msg_size bytes of ciphertext."""
    salt          = bytes(range(SALT_SIZE))
    pass_cipher   = bytes(range(PASSWORD_CIPHERTEXT_SIZE))
    key_nonce     = bytes(range(KEY_WRAP_NONCE_SIZE))
    protected_key = b"protected_session_key_32_bytes!!" + b"\x00" * 16   # 48 bytes
    msg_nonce     = bytes(range(NONCE_SIZE))
    pattern       = bytes([i % 256 for i in range(max(msg_size, 1))])
    ciphertext    = (pattern * ((msg_size // len(pattern)) + 1))[:msg_size]
    return build_payload(salt, pass_cipher, key_nonce, protected_key, msg_nonce, ciphertext)


class TestCapacity:
    def test_rgb_capacity(self):
        img = make_test_image(100, 100, "RGB")
        cap = calculate_capacity(img)
        assert cap["raw_bytes"] == 100 * 100 * 3 // 8

    def test_usable_less_than_raw(self):
        img = make_test_image(100, 100)
        cap = calculate_capacity(img)
        assert cap["usable_bytes"] < cap["raw_bytes"]

    def test_check_capacity_ok(self):
        img = make_test_image(500, 500)
        check_capacity(img, 100)   # should not raise

    def test_check_capacity_too_large(self):
        img = make_test_image(10, 10)
        with pytest.raises(InsufficientCapacityError):
            check_capacity(img, 10_000_000)


class TestEmbedExtract:
    def test_small_payload_roundtrip(self):
        img     = make_test_image(200, 200)
        payload = make_test_payload(32)

        stego = embed_payload(img, payload)
        extracted = extract_payload(stego)

        assert extracted == payload, "Extracted payload must equal embedded payload byte for byte."

    def test_stego_is_same_size(self):
        img   = make_test_image(200, 200)
        stego = embed_payload(img, make_test_payload(32))
        assert stego.size == img.size

    def test_stego_png_roundtrip(self):
        """Saving stego image as PNG bytes and re-opening must not lose payload data."""
        img       = make_test_image(200, 200)
        payload   = make_test_payload(64)
        stego     = embed_payload(img, payload)
        png_bytes = image_to_png_bytes(stego)

        reloaded  = Image.open(io.BytesIO(png_bytes))
        extracted = extract_payload(reloaded)

        assert extracted == payload

    def test_larger_payload(self):
        img     = make_test_image(500, 500)
        payload = make_test_payload(1024)

        stego     = embed_payload(img, payload)
        extracted = extract_payload(stego)
        assert extracted == payload

    def test_rgba_image_alpha_preserved(self):
        """RGBA images: alpha channel must not be modified."""
        arr  = np.random.randint(0, 256, (200, 200, 4), dtype=np.uint8)
        arr[:, :, 3] = 255   # opaque alpha
        img  = Image.fromarray(arr, mode="RGBA")
        payload = make_test_payload(32)

        stego     = embed_payload(img, payload)
        stego_arr = np.array(stego)

        assert np.array_equal(stego_arr[:, :, 3], arr[:, :, 3]), "Alpha channel must be completely untouched."

    def test_capacity_exceeded_raises(self):
        img = make_test_image(10, 10)   # tiny image
        payload = make_test_payload(10_000)
        with pytest.raises(InsufficientCapacityError):
            embed_payload(img, payload)

    def test_image_not_modified_in_non_embedded_pixels(self):
        """Pixels beyond the embedding region should be unchanged."""
        img     = make_test_image(500, 500)
        payload = make_test_payload(32)   # small — uses very few pixels

        stego     = embed_payload(img, payload)
        orig_arr  = np.array(img)
        stego_arr = np.array(stego)

        # Payload is (130 + 32) = 162 bytes = 1296 bits → 432 pixels (3 channels/pixel)
        # Check pixels well beyond pixel 432 (e.g. pixel 1000 onwards)
        flat_orig  = orig_arr.reshape(-1, 3)
        flat_stego = stego_arr.reshape(-1, 3)

        assert np.array_equal(flat_orig[1000:], flat_stego[1000:]), "Non-embedded pixels must remain bit-identical."
