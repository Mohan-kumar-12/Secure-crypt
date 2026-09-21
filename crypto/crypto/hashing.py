"""
SHA-256 fingerprinting for payload analysis and display.

NOTE: SHA-256 alone does NOT authenticate an attacker-controlled payload.
Authentication is provided by AES-GCM. This module is for informational
display only.
"""
import hashlib


def sha256_fingerprint(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of data."""
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """Return raw SHA-256 bytes."""
    return hashlib.sha256(data).digest()
