"""
Key derivation using PBKDF2-HMAC-SHA256.

Uses the `cryptography` library — no manual PBKDF2 implementation.
Never use the password directly as the AES key.
"""
import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from config import PBKDF2_ITERATIONS, KEY_SIZE, SALT_SIZE


def generate_salt() -> bytes:
    """Return a cryptographically random salt."""
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a password and salt using PBKDF2-HMAC-SHA256.

    Args:
        password: User-supplied password string.
        salt:     Random bytes (SALT_SIZE).

    Returns:
        32-byte AES key.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a str")
    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
        raise ValueError(f"salt must be {SALT_SIZE} bytes")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))
