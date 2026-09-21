"""
Ed25519 Digital Signatures using Python Cryptography Library.

The private key is stored securely server-side in `keys/private_key.pem`.
The public key is available for verification in `keys/public_key.pem`.
The private key is NEVER sent to the frontend or browser.
"""
import os
from typing import Union, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from config import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH, KEYS_FOLDER


def ensure_key_pair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """
    Ensure an Ed25519 key pair exists. Generates a new pair if missing.

    Returns:
        Tuple of (private_key, public_key)
    """
    os.makedirs(KEYS_FOLDER, exist_ok=True)

    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key

    # Generate new Ed25519 key pair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()

    # Save private key PEM
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(pem_private)

    # Save public key PEM
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(pem_public)

    return private_key, public_key


def get_public_key_pem() -> bytes:
    """Return the Ed25519 public key as PEM bytes."""
    _, public_key = ensure_key_pair()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def sign_file(file_path_or_bytes: Union[str, bytes]) -> Tuple[bytes, str]:
    """
    Cryptographically sign content using the server's Ed25519 private key.

    Returns:
        Tuple of (raw_signature_bytes, hex_signature_str).
    """
    if isinstance(file_path_or_bytes, str):
        with open(file_path_or_bytes, "rb") as f:
            data = f.read()
    elif isinstance(file_path_or_bytes, bytes):
        data = file_path_or_bytes
    else:
        raise TypeError("Input must be str file path or bytes")

    private_key, _ = ensure_key_pair()
    signature_bytes = private_key.sign(data)
    signature_hex   = signature_bytes.hex().upper()

    return signature_bytes, signature_hex


def verify_signature(
    file_path_or_bytes: Union[str, bytes],
    signature_input: Union[bytes, str],
) -> bool:
    """
    Verify an Ed25519 digital signature against content.

    Returns:
        True if signature is VALID (content is authentic and untampered),
        False if INVALID.
    """
    try:
        if isinstance(file_path_or_bytes, str):
            with open(file_path_or_bytes, "rb") as f:
                data = f.read()
        elif isinstance(file_path_or_bytes, bytes):
            data = file_path_or_bytes
        else:
            return False

        if isinstance(signature_input, str):
            sig_bytes = bytes.fromhex(signature_input.strip())
        elif isinstance(signature_input, bytes):
            sig_bytes = signature_input
        else:
            return False

        _, public_key = ensure_key_pair()
        public_key.verify(sig_bytes, data)
        return True
    except Exception:
        return False
