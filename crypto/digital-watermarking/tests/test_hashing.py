"""
Tests for SHA-256 File Fingerprinting (test_hashing.py).
"""
import pytest
from watermarking.hashing import calculate_sha256


class TestSHA256Hashing:
    def test_sha256_bytes_deterministic(self):
        data = b"Hello SecureCrypt Module 2 World"
        hash1 = calculate_sha256(data)
        hash2 = calculate_sha256(data)
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_sha256_different_inputs(self):
        data1 = b"Content 1"
        data2 = b"Content 2"
        hash1 = calculate_sha256(data1)
        hash2 = calculate_sha256(data2)
        assert hash1 != hash2

    def test_modified_file_changes_hash(self):
        original = b"function test() { return 1; }"
        modified = b"function test() { return 2; }"
        h_orig = calculate_sha256(original)
        h_mod  = calculate_sha256(modified)
        assert h_orig != h_mod
