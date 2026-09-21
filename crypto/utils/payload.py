"""
Binary payload builder and parser for the SecureCrypt steganography system.

Payload binary format v2 — Two-Key Architecture with Password Ciphertext:
┌──────────────────┬──────────┬─────────────────────────────────────────────────────┐
│ Field            │ Size     │ Description                                         │
├──────────────────┼──────────┼─────────────────────────────────────────────────────┤
│ MAGIC            │  4 bytes │ ASCII "SCST" — identifies a SecureCrypt image       │
│ VERSION          │  1 byte  │ 0x02 (Two-Key Architecture)                         │
│ FLAGS            │  1 byte  │ Reserved, currently 0x00                             │
│ SALT             │ 16 bytes │ PBKDF2 random salt                                  │
│ PASS_CIPHERTEXT  │ 32 bytes │ Password converted ciphertext/numerical bytes       │
│ KEY_NONCE        │ 12 bytes │ Key-wrapping AES-GCM nonce                          │
│ PROTECTED_KEY    │ 48 bytes │ AES-GCM(session_key) = 32-byte key + 16-byte tag    │
│ MSG_NONCE        │ 12 bytes │ Message encryption AES-GCM nonce                    │
│ CT_LEN           │  4 bytes │ uint32 — byte length of CIPHERTEXT field             │
│ CIPHERTEXT       │ variable │ AES-GCM ciphertext + 16-byte GCM tag                │
└──────────────────┴──────────┴─────────────────────────────────────────────────────┘
Total fixed header: 130 bytes
"""
import struct
from config import (
    PAYLOAD_MAGIC,
    PAYLOAD_VERSION,
    PAYLOAD_FLAGS,
    SALT_SIZE,
    PASSWORD_CIPHERTEXT_SIZE,
    NONCE_SIZE,
    KEY_WRAP_NONCE_SIZE,
    PROTECTED_KEY_SIZE,
    PAYLOAD_FIXED_HEADER,
)


class PayloadError(Exception):
    """Raised when a payload cannot be parsed or is invalid."""


def build_payload(
    salt: bytes,
    password_ciphertext_bytes: bytes,
    key_nonce: bytes,
    protected_key: bytes,
    msg_nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    """
    Pack encryption components into the structured binary payload.

    Args:
        salt:                      16-byte PBKDF2 random salt.
        password_ciphertext_bytes: 32-byte password ciphertext bytes.
        key_nonce:                 12-byte key-wrapping AES-GCM nonce.
        protected_key:             48-byte protected session key.
        msg_nonce:                 12-byte message encryption AES-GCM nonce.
        ciphertext:                AES-GCM ciphertext + tag (variable length).

    Returns:
        Packed bytes ready for LSB embedding.
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(f"salt must be {SALT_SIZE} bytes, got {len(salt)}")
    if len(password_ciphertext_bytes) != PASSWORD_CIPHERTEXT_SIZE:
        raise ValueError(f"password_ciphertext_bytes must be {PASSWORD_CIPHERTEXT_SIZE} bytes, got {len(password_ciphertext_bytes)}")
    if len(key_nonce) != KEY_WRAP_NONCE_SIZE:
        raise ValueError(f"key_nonce must be {KEY_WRAP_NONCE_SIZE} bytes, got {len(key_nonce)}")
    if len(protected_key) != PROTECTED_KEY_SIZE:
        raise ValueError(f"protected_key must be {PROTECTED_KEY_SIZE} bytes, got {len(protected_key)}")
    if len(msg_nonce) != NONCE_SIZE:
        raise ValueError(f"msg_nonce must be {NONCE_SIZE} bytes, got {len(msg_nonce)}")

    ct_len = len(ciphertext)
    header = (
        PAYLOAD_MAGIC
        + bytes([PAYLOAD_VERSION, PAYLOAD_FLAGS])
        + salt
        + password_ciphertext_bytes
        + key_nonce
        + protected_key
        + msg_nonce
        + struct.pack(">I", ct_len)
    )
    return header + ciphertext


def parse_payload(data: bytes) -> dict:
    """
    Unpack and validate a binary payload.

    Returns:
        dict with keys: version, flags, salt, password_ciphertext_bytes,
                        key_nonce, protected_key, msg_nonce, ciphertext
    """
    if len(data) < PAYLOAD_FIXED_HEADER:
        raise PayloadError(
            f"Payload too short: {len(data)} bytes (minimum {PAYLOAD_FIXED_HEADER})"
        )

    magic = data[0:4]
    if magic != PAYLOAD_MAGIC:
        raise PayloadError(
            f"Invalid magic header: {magic!r} — not a SecureCrypt payload"
        )

    version = data[4]
    if version != PAYLOAD_VERSION:
        raise PayloadError(f"Unsupported payload version: {version}")

    flags = data[5]

    offset = 6

    salt = data[offset : offset + SALT_SIZE]
    offset += SALT_SIZE

    password_ciphertext_bytes = data[offset : offset + PASSWORD_CIPHERTEXT_SIZE]
    offset += PASSWORD_CIPHERTEXT_SIZE

    key_nonce = data[offset : offset + KEY_WRAP_NONCE_SIZE]
    offset += KEY_WRAP_NONCE_SIZE

    protected_key = data[offset : offset + PROTECTED_KEY_SIZE]
    offset += PROTECTED_KEY_SIZE

    msg_nonce = data[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE

    (ct_len,) = struct.unpack(">I", data[offset : offset + 4])
    offset += 4

    if ct_len == 0:
        raise PayloadError("Payload ciphertext length is zero")

    if len(data) < offset + ct_len:
        raise PayloadError(
            f"Payload declares {ct_len} ciphertext bytes but only "
            f"{len(data) - offset} bytes available"
        )

    ciphertext = data[offset : offset + ct_len]

    return {
        "version":                   version,
        "flags":                     flags,
        "salt":                      salt,
        "password_ciphertext_bytes": password_ciphertext_bytes,
        "key_nonce":                 key_nonce,
        "protected_key":             protected_key,
        "msg_nonce":                 msg_nonce,
        "ciphertext":                ciphertext,
    }


def total_payload_size(ciphertext_len: int) -> int:
    """Return total byte size of a payload given the ciphertext length."""
    return PAYLOAD_FIXED_HEADER + ciphertext_len
