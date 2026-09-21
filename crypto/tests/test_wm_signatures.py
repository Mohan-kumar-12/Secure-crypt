"""
Tests for SHA-256 Hashing and Ed25519 Signatures (test_wm_hashing.py & test_wm_signatures.py).
"""
import pytest
from watermarking.hashing import calculate_sha256
from watermarking.signatures import ensure_key_pair, sign_file, verify_signature


class TestWatermarkHashingAndSignatures:
    def test_sha256_deterministic(self):
        data = b"Unified Platform Hashing Test"
        h1 = calculate_sha256(data)
        h2 = calculate_sha256(data)
        assert h1 == h2
        assert len(h1) == 64

    def test_ed25519_sign_verify(self):
        data = b"Unified Platform Ed25519 Test"
        sig_bytes, sig_hex = sign_file(data)

        assert len(sig_bytes) == 64
        assert verify_signature(data, sig_bytes) is True
        assert verify_signature(data, sig_hex) is True
        assert verify_signature(b"altered data", sig_bytes) is False
