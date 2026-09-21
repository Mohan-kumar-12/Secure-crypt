"""
AES-256-GCM encryption and decryption — Two-Key Architecture with Password Ciphertext.

Uses the two-key password protection system:
  - Password converted into Ciphertext / Numbers and stored in image payload.
  - A random session key encrypts the message (AES-256-GCM).
  - The password-derived key protects the session key (AES-256-GCM).

All cryptographic operations use the Python `cryptography` library.
"""
from cryptography.exceptions import InvalidTag

from crypto.password_protection import secure_encrypt, secure_decrypt


def encrypt_message(message: str, password: str) -> dict:
    """
    Encrypt a plaintext message using the two-key architecture with password ciphertext conversion.

    Returns:
        dict with keys:
            salt                          (bytes) — 16-byte PBKDF2 random salt
            password_ciphertext_bytes     (bytes) — 32-byte password ciphertext stored in payload
            password_ciphertext_formatted (str)   — Formatted ciphertext/numbers password string
            key_nonce                     (bytes) — 12-byte key-wrapping nonce
            protected_key                 (bytes) — 48-byte protected session key
            msg_nonce                     (bytes) — 12-byte message encryption nonce
            ciphertext                    (bytes) — encrypted data + 16-byte GCM tag
    """
    return secure_encrypt(message, password)


def decrypt_message(
    salt: bytes,
    password_ciphertext_bytes: bytes,
    key_nonce: bytes,
    protected_key: bytes,
    msg_nonce: bytes,
    ciphertext: bytes,
    password: str,
) -> str:
    """
    Decrypt and authenticate using stored payload password ciphertext.

    Args:
        salt:                      16-byte salt from payload.
        password_ciphertext_bytes: 32-byte password ciphertext from payload.
        key_nonce:                 12-byte key-wrapping nonce from payload.
        protected_key:             48-byte protected session key from payload.
        msg_nonce:                 12-byte message encryption nonce from payload.
        ciphertext:                Encrypted data + GCM tag.
        password:                  Receiver input (ciphertext/numbers or original password).

    Returns:
        Decrypted plaintext string.
    """
    return secure_decrypt(
        salt,
        password_ciphertext_bytes,
        key_nonce,
        protected_key,
        msg_nonce,
        ciphertext,
        password,
    )
