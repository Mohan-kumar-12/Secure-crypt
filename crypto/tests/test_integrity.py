"""
Integration tests for SecureCrypt (Two-Key Architecture v2 with Password Ciphertext).

Tests the complete round-trip:
  message → encrypt → build v2 payload → embed → save PNG → load PNG → extract → parse → decrypt → message

Also tests wrong-password and tamper-detection scenarios.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import io
import pytest
import numpy as np
from PIL import Image
from cryptography.exceptions import InvalidTag

from crypto.encryption import encrypt_message, decrypt_message
from steganography.embed import embed_payload, image_to_png_bytes
from steganography.extract import extract_payload
from utils.payload import build_payload, parse_payload, PayloadError


def make_textured_image(width=400, height=400, seed=7) -> Image.Image:
    rng = np.random.default_rng(seed)
    arr = rng.integers(0, 256, (height, width, 3), dtype=np.uint8)
    return Image.fromarray(arr, mode="RGB")


class TestFullRoundTrip:
    def _roundtrip(self, message: str, password: str, img_seed: int = 7):
        img = make_textured_image(seed=img_seed)

        # Encrypt
        enc     = encrypt_message(message, password)
        payload = build_payload(
            enc["salt"], enc["password_ciphertext_bytes"], enc["key_nonce"],
            enc["protected_key"], enc["msg_nonce"], enc["ciphertext"]
        )

        # Embed
        stego = embed_payload(img, payload)

        # Save as PNG → reload (simulates download + re-upload)
        png_bytes = image_to_png_bytes(stego)
        reloaded  = Image.open(io.BytesIO(png_bytes))

        # Extract
        raw = extract_payload(reloaded)

        # Parse
        parsed = parse_payload(raw)

        # Decrypt
        result = decrypt_message(
            parsed["salt"], parsed["password_ciphertext_bytes"], parsed["key_nonce"],
            parsed["protected_key"], parsed["msg_nonce"], parsed["ciphertext"], password
        )

        return result

    def test_basic_roundtrip(self):
        msg = "Hello, this is a secret message!"
        assert self._roundtrip(msg, "TestPass123!") == msg

    def test_unicode_roundtrip(self):
        msg = "Secret: गोपनीय सन्देश 🔐 Ñoño"
        assert self._roundtrip(msg, "UniPass99@") == msg

    def test_multiline_roundtrip(self):
        msg = "Line 1\nLine 2\nLine 3\nSpecial chars: <>&\"'"
        assert self._roundtrip(msg, "MultiPass1!") == msg

    def test_medium_message(self):
        msg = "M" * 5000
        assert self._roundtrip(msg, "MediumPass1!", img_seed=42) == msg

    def test_short_message(self):
        msg = "Hi"
        assert self._roundtrip(msg, "ShortPass1!") == msg


class TestWrongPassword:
    def test_wrong_password_fails(self):
        img     = make_textured_image()
        enc     = encrypt_message("top secret", "CorrectPass1!")
        payload = build_payload(
            enc["salt"], enc["password_ciphertext_bytes"], enc["key_nonce"],
            enc["protected_key"], enc["msg_nonce"], enc["ciphertext"]
        )
        stego   = embed_payload(img, payload)
        raw     = extract_payload(stego)
        parsed  = parse_payload(raw)

        with pytest.raises(InvalidTag):
            decrypt_message(
                parsed["salt"], parsed["password_ciphertext_bytes"], parsed["key_nonce"],
                parsed["protected_key"], parsed["msg_nonce"], parsed["ciphertext"], "WrongPass1!"
            )

    def test_similar_password_fails(self):
        img     = make_textured_image(seed=11)
        enc     = encrypt_message("confidential", "Password123!")
        payload = build_payload(
            enc["salt"], enc["password_ciphertext_bytes"], enc["key_nonce"],
            enc["protected_key"], enc["msg_nonce"], enc["ciphertext"]
        )
        stego   = embed_payload(img, payload)
        raw     = extract_payload(stego)
        parsed  = parse_payload(raw)

        with pytest.raises(InvalidTag):
            decrypt_message(
                parsed["salt"], parsed["password_ciphertext_bytes"], parsed["key_nonce"],
                parsed["protected_key"], parsed["msg_nonce"], parsed["ciphertext"], "Password123 "
            )


class TestTamperDetection:
    def test_modified_stego_pixel_auth_fails(self):
        """Flipping a pixel bit in the stego image corrupts the payload → GCM auth fails."""
        img     = make_textured_image(seed=13)
        enc     = encrypt_message("tamper me", "TamperPass1!")
        payload = build_payload(
            enc["salt"], enc["password_ciphertext_bytes"], enc["key_nonce"],
            enc["protected_key"], enc["msg_nonce"], enc["ciphertext"]
        )
        stego   = embed_payload(img, payload)

        png_bytes = image_to_png_bytes(stego)
        reloaded  = Image.open(io.BytesIO(png_bytes))
        arr       = np.array(reloaded)

        from config import PAYLOAD_FIXED_HEADER
        W = reloaded.width
        n_ch = 3
        ct_start_slot = PAYLOAD_FIXED_HEADER * 8
        for i in range(80):
            slot = ct_start_slot + i
            r  = slot // (W * n_ch)
            rr = slot  % (W * n_ch)
            c  = rr    // n_ch
            ch = rr    %  n_ch
            arr[r, c, ch] ^= 1   # flip LSB

        tampered_img = Image.fromarray(arr, mode="RGB")

        tamper_detected = False
        try:
            raw    = extract_payload(tampered_img)
            parsed = parse_payload(raw)
            try:
                decrypt_message(
                    parsed["salt"], parsed["password_ciphertext_bytes"], parsed["key_nonce"],
                    parsed["protected_key"], parsed["msg_nonce"], parsed["ciphertext"], "TamperPass1!"
                )
            except InvalidTag:
                tamper_detected = True
        except Exception:
            tamper_detected = True   # extraction failure = tamper detected

        assert tamper_detected, "Tampering should have been detected by GCM auth tag"

    def test_payload_magic_tamper_raises_payload_error(self):
        """If we corrupt the magic bytes, extraction must fail with PayloadError."""
        enc     = encrypt_message("secret", "TestPass1!")
        payload = build_payload(
            enc["salt"], enc["password_ciphertext_bytes"], enc["key_nonce"],
            enc["protected_key"], enc["msg_nonce"], enc["ciphertext"]
        )

        bad_payload = b"XXXX" + payload[4:]
        with pytest.raises(PayloadError):
            parse_payload(bad_payload)


class TestCapacityValidation:
    def test_oversized_message_rejected(self):
        from steganography.capacity import InsufficientCapacityError

        small_img = make_textured_image(10, 10)
        payload = b"X" * 10_000
        with pytest.raises(InsufficientCapacityError):
            embed_payload(small_img, payload)
