"""
Password Protection Module — Two-Key Architecture with Password Ciphertext Storage
===================================================================================

CONCEPT
-------
The password supplied by the user is converted into a formatted Ciphertext /
Numerical representation. This password ciphertext is stored directly inside
the stego image binary payload header.

During decryption, the user enters either the generated Password Ciphertext
(numbers/hex string) or the original password. The system verifies the entry
against the stored payload ciphertext, recovers the random AES session key,
and decrypts the message.

Architecture:
    Password → Password Ciphertext (Numbers / Hex)
    Password Ciphertext → PBKDF2-HMAC-SHA256 → Password-Derived Key (PDK)
    PDK → AES-256-GCM → protects Random Session Key
    Random Session Key → AES-256-GCM → encrypts Secret Message
"""
import os
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from config import (
    KEY_SIZE,
    SALT_SIZE,
    NONCE_SIZE,
    KEY_WRAP_NONCE_SIZE,
    PASSWORD_CIPHERTEXT_SIZE,
    PBKDF2_ITERATIONS,
)


# ─── Password to Ciphertext Conversion ────────────────────────────────────────

def compute_password_ciphertext(password: str, salt: bytes) -> Tuple[str, bytes]:
    """
    Convert a password and salt into a formatted ciphertext/numerical string
    and its raw 32-byte binary representation for payload storage.

    Format example: "8F2A-41C9-7B03-9E4D-5A81-2B03-4C9E-6F12-..."

    Args:
        password: User input password string.
        salt:     16-byte random salt.

    Returns:
        Tuple of (formatted_ciphertext_str, raw_32_bytes)
    """
    if not isinstance(password, str):
        raise TypeError("password must be a str")
    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
        raise ValueError(f"salt must be {SALT_SIZE} bytes")

    # Clean input: remove whitespace and hyphens
    clean_pw = password.replace("-", "").replace(" ", "").strip()

    # Create deterministic 32-byte ciphertext digest of the password + salt
    digest = hashlib.sha256(clean_pw.encode("utf-8") + salt).digest()

    # Format into uppercase 4-character blocks (64 hex chars = 16 blocks)
    hex_str = digest.hex().upper()
    formatted = "-".join([hex_str[i:i+4] for i in range(0, 64, 4)])

    return formatted, digest


# ─── Password Key Derivation ─────────────────────────────────────────────────

def derive_password_key(password_ciphertext: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from the password ciphertext string and salt using PBKDF2.

    Args:
        password_ciphertext: Formatted ciphertext/numerical password string.
        salt:                Random salt bytes.

    Returns:
        32-byte password-derived key (PDK).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    clean_key_input = password_ciphertext.replace("-", "").replace(" ", "").strip().upper()
    return kdf.derive(clean_key_input.encode("utf-8"))


# ─── Random Session Key ─────────────────────────────────────────────────────

def generate_session_key() -> bytes:
    """Generate a cryptographically random 256-bit AES session key."""
    return os.urandom(KEY_SIZE)


# ─── Session Key Protection (Key Wrapping) ───────────────────────────────────

def protect_session_key(
    session_key: bytes,
    password_derived_key: bytes,
) -> Tuple[bytes, bytes]:
    """Protect the random session key using AES-256-GCM with the password-derived key."""
    if len(session_key) != KEY_SIZE:
        raise ValueError(f"session_key must be {KEY_SIZE} bytes")
    if len(password_derived_key) != KEY_SIZE:
        raise ValueError(f"password_derived_key must be {KEY_SIZE} bytes")

    key_nonce = os.urandom(KEY_WRAP_NONCE_SIZE)
    aesgcm = AESGCM(password_derived_key)
    protected_key = aesgcm.encrypt(key_nonce, session_key, None)

    return protected_key, key_nonce


def recover_session_key(
    protected_key: bytes,
    password_derived_key: bytes,
    key_nonce: bytes,
) -> bytes:
    """Recover the random session key by decrypting with the password-derived key."""
    if len(key_nonce) != KEY_WRAP_NONCE_SIZE:
        raise ValueError(f"key_nonce must be {KEY_WRAP_NONCE_SIZE} bytes")

    aesgcm = AESGCM(password_derived_key)
    session_key = aesgcm.decrypt(key_nonce, protected_key, None)
    return session_key


# ─── Message Encryption ─────────────────────────────────────────────────────

def encrypt_message(
    message: str,
    session_key: bytes,
) -> Tuple[bytes, bytes]:
    """Encrypt message using AES-256-GCM with random session key."""
    if not message:
        raise ValueError("Message must not be empty")
    if len(session_key) != KEY_SIZE:
        raise ValueError(f"session_key must be {KEY_SIZE} bytes")

    msg_nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(msg_nonce, message.encode("utf-8"), None)

    return ciphertext, msg_nonce


def decrypt_message(
    ciphertext: bytes,
    session_key: bytes,
    msg_nonce: bytes,
) -> str:
    """Decrypt ciphertext using session key."""
    if len(session_key) != KEY_SIZE:
        raise ValueError(f"session_key must be {KEY_SIZE} bytes")
    if len(msg_nonce) != NONCE_SIZE:
        raise ValueError(f"msg_nonce must be {NONCE_SIZE} bytes")

    aesgcm = AESGCM(session_key)
    plaintext_bytes = aesgcm.decrypt(msg_nonce, ciphertext, None)
    return plaintext_bytes.decode("utf-8")


# ─── High-Level Pipelines ───────────────────────────────────────────────────

def secure_encrypt(message: str, password: str) -> dict:
    """
    Complete encryption pipeline with Password Ciphertext generation and storage.

    Workflow:
        1. Generate random salt.
        2. Convert password → Password Ciphertext (formatted string + 32-byte digest).
        3. Derive PDK from Password Ciphertext via PBKDF2-HMAC-SHA256.
        4. Generate random AES session key.
        5. Encrypt message with session key (AES-256-GCM).
        6. Protect session key with PDK (AES-256-GCM).
        7. Return all payload components including stored password ciphertext.
    """
    if not message:
        raise ValueError("Message must not be empty")
    if not password:
        raise ValueError("Password must not be empty")

    salt = os.urandom(SALT_SIZE)

    # Convert password into ciphertext / numerical format
    formatted_pw_ciphertext, pw_ciphertext_bytes = compute_password_ciphertext(password, salt)

    # Derive PDK from the ciphertext password string
    pdk = derive_password_key(formatted_pw_ciphertext, salt)

    # Generate random session key
    session_key = generate_session_key()

    # Encrypt message with session key
    ciphertext, msg_nonce = encrypt_message(message, session_key)

    # Protect session key with PDK
    protected_key, key_nonce = protect_session_key(session_key, pdk)

    del pdk
    del session_key

    return {
        "salt":                        salt,
        "password_ciphertext_bytes":   pw_ciphertext_bytes,
        "password_ciphertext_formatted": formatted_pw_ciphertext,
        "key_nonce":                   key_nonce,
        "protected_key":               protected_key,
        "msg_nonce":                   msg_nonce,
        "ciphertext":                  ciphertext,
    }


def secure_decrypt(
    salt: bytes,
    password_ciphertext_bytes: bytes,
    key_nonce: bytes,
    protected_key: bytes,
    msg_nonce: bytes,
    ciphertext: bytes,
    password: str,
) -> str:
    """
    Complete decryption pipeline validating input password against stored payload password ciphertext.

    Accepts password supplied either as:
      - The generated Password Ciphertext (numerical/hex string, e.g. "8F2A-41C9-...")
      - The original plaintext password (e.g. "MySecretPass123!")

    Raises:
        InvalidTag: If password check or payload authentication fails.
    """
    if not password:
        raise ValueError("Password must not be empty")
    if len(password_ciphertext_bytes) != PASSWORD_CIPHERTEXT_SIZE:
        raise ValueError(f"stored password_ciphertext must be {PASSWORD_CIPHERTEXT_SIZE} bytes")

    clean_input = password.replace("-", "").replace(" ", "").strip().upper()
    stored_hex  = password_ciphertext_bytes.hex().upper()

    # Determine if input matches stored password ciphertext directly (entered as ciphertext/numbers)
    if clean_input == stored_hex:
        calc_formatted = "-".join([stored_hex[i:i+4] for i in range(0, 64, 4)])
    else:
        # User entered original plaintext password -> compute ciphertext
        calc_formatted, calc_bytes = compute_password_ciphertext(password, salt)
        if calc_bytes != password_ciphertext_bytes:
            # Password ciphertext does not match payload header
            raise InvalidTag()

    # Derive PDK and decrypt
    pdk = derive_password_key(calc_formatted, salt)

    try:
        session_key = recover_session_key(protected_key, pdk, key_nonce)
    finally:
        del pdk

    try:
        plaintext = decrypt_message(ciphertext, session_key, msg_nonce)
    finally:
        del session_key

    return plaintext
