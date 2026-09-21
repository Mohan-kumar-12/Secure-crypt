"""
Cryptographic SHA-256 File Fingerprinting.
"""
import hashlib
from typing import Union


def calculate_sha256(target: Union[str, bytes]) -> str:
    """
    Calculate the SHA-256 hash fingerprint of a file or raw bytes.

    Args:
        target: Absolute file path (str) or raw byte data (bytes).

    Returns:
        Hexadecimal SHA-256 digest string.
    """
    hasher = hashlib.sha256()

    if isinstance(target, bytes):
        hasher.update(target)
    elif isinstance(target, str):
        with open(target, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    else:
        raise TypeError("Target must be a file path string or bytes object")

    return hasher.hexdigest().upper()
