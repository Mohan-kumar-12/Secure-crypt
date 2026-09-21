"""
Tests for Ed25519 Digital Signatures (test_signatures.py).
"""
import pytest
from watermarking.signatures import ensure_key_pair, sign_file, verify_signature


class TestEd25519Signatures:
    def test_ensure_key_pair(self):
        priv, pub = ensure_key_pair()
        assert priv is not None
        assert pub is not None

    def test_sign_and_verify_valid(self):
        data = b"print('Authentic Python Source Code')"
        sig_bytes, sig_hex = sign_file(data)

        assert len(sig_bytes) == 64
        assert len(sig_hex) == 128

        assert verify_signature(data, sig_bytes) is True
        assert verify_signature(data, sig_hex) is True

    def test_tampered_content_fails_verification(self):
        original = b"print('Original Code')"
        tampered = b"print('Tampered Code')"

        sig_bytes, _ = sign_file(original)

        assert verify_signature(original, sig_bytes) is True
        assert verify_signature(tampered, sig_bytes) is False
