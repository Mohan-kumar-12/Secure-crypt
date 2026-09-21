"""
Payload format tests for SecureCrypt (Two-Key Architecture v2 with Password Ciphertext).
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import struct
from utils.payload import build_payload, parse_payload, PayloadError, total_payload_size
from config import SALT_SIZE, PASSWORD_CIPHERTEXT_SIZE, NONCE_SIZE, KEY_WRAP_NONCE_SIZE, PROTECTED_KEY_SIZE, PAYLOAD_FIXED_HEADER


DUMMY_SALT           = bytes(range(SALT_SIZE))
DUMMY_PASS_CIPHER    = bytes(range(PASSWORD_CIPHERTEXT_SIZE))
DUMMY_KEY_NONCE      = bytes(range(KEY_WRAP_NONCE_SIZE))
DUMMY_PROTECTED_KEY  = b"protected_session_key_32_bytes!!" + b"\x00" * 16  # 48 bytes
DUMMY_MSG_NONCE      = bytes(range(NONCE_SIZE))
DUMMY_CIPHERTEXT     = b"encrypted_data_here_with_tag" + b"\x00" * 16


class TestBuildPayload:
    def test_builds_without_error(self):
        p = build_payload(
            DUMMY_SALT, DUMMY_PASS_CIPHER, DUMMY_KEY_NONCE, DUMMY_PROTECTED_KEY,
            DUMMY_MSG_NONCE, DUMMY_CIPHERTEXT
        )
        assert isinstance(p, bytes)

    def test_magic_header_present(self):
        p = build_payload(
            DUMMY_SALT, DUMMY_PASS_CIPHER, DUMMY_KEY_NONCE, DUMMY_PROTECTED_KEY,
            DUMMY_MSG_NONCE, DUMMY_CIPHERTEXT
        )
        assert p[:4] == b"SCST"

    def test_version_byte(self):
        p = build_payload(
            DUMMY_SALT, DUMMY_PASS_CIPHER, DUMMY_KEY_NONCE, DUMMY_PROTECTED_KEY,
            DUMMY_MSG_NONCE, DUMMY_CIPHERTEXT
        )
        assert p[4] == 0x02

    def test_flags_byte(self):
        p = build_payload(
            DUMMY_SALT, DUMMY_PASS_CIPHER, DUMMY_KEY_NONCE, DUMMY_PROTECTED_KEY,
            DUMMY_MSG_NONCE, DUMMY_CIPHERTEXT
        )
        assert p[5] == 0x00

    def test_correct_total_length(self):
        p = build_payload(
            DUMMY_SALT, DUMMY_PASS_CIPHER, DUMMY_KEY_NONCE, DUMMY_PROTECTED_KEY,
            DUMMY_MSG_NONCE, DUMMY_CIPHERTEXT
        )
        expected = PAYLOAD_FIXED_HEADER + len(DUMMY_CIPHERTEXT)
        assert len(p) == expected
        assert PAYLOAD_FIXED_HEADER == 130

    def test_wrong_salt_length_raises(self):
        with pytest.raises(ValueError):
            build_payload(b"short", DUMMY_PASS_CIPHER, DUMMY_KEY_NONCE, DUMMY_PROTECTED_KEY, DUMMY_MSG_NONCE, DUMMY_CIPHERTEXT)

    def test_wrong_pass_cipher_length_raises(self):
        with pytest.raises(ValueError):
            build_payload(DUMMY_SALT, b"short", DUMMY_KEY_NONCE, DUMMY_PROTECTED_KEY, DUMMY_MSG_NONCE, DUMMY_CIPHERTEXT)

    def test_wrong_key_nonce_length_raises(self):
        with pytest.raises(ValueError):
            build_payload(DUMMY_SALT, DUMMY_PASS_CIPHER, b"short", DUMMY_PROTECTED_KEY, DUMMY_MSG_NONCE, DUMMY_CIPHERTEXT)

    def test_wrong_protected_key_length_raises(self):
        with pytest.raises(ValueError):
            build_payload(DUMMY_SALT, DUMMY_PASS_CIPHER, DUMMY_KEY_NONCE, b"short", DUMMY_MSG_NONCE, DUMMY_CIPHERTEXT)

    def test_wrong_msg_nonce_length_raises(self):
        with pytest.raises(ValueError):
            build_payload(DUMMY_SALT, DUMMY_PASS_CIPHER, DUMMY_KEY_NONCE, DUMMY_PROTECTED_KEY, b"shortnonce", DUMMY_CIPHERTEXT)


class TestParsePayload:
    def _make(self, ct=None):
        ct = ct or DUMMY_CIPHERTEXT
        return build_payload(
            DUMMY_SALT, DUMMY_PASS_CIPHER, DUMMY_KEY_NONCE, DUMMY_PROTECTED_KEY,
            DUMMY_MSG_NONCE, ct
        )

    def test_roundtrip(self):
        p = self._make()
        parsed = parse_payload(p)
        assert parsed["salt"]                      == DUMMY_SALT
        assert parsed["password_ciphertext_bytes"] == DUMMY_PASS_CIPHER
        assert parsed["key_nonce"]                 == DUMMY_KEY_NONCE
        assert parsed["protected_key"]             == DUMMY_PROTECTED_KEY
        assert parsed["msg_nonce"]                 == DUMMY_MSG_NONCE
        assert parsed["ciphertext"]                == DUMMY_CIPHERTEXT
        assert parsed["version"]                   == 0x02

    def test_invalid_magic_raises(self):
        p = bytearray(self._make())
        p[0:4] = b"XXXX"
        with pytest.raises(PayloadError, match="magic"):
            parse_payload(bytes(p))

    def test_wrong_version_raises(self):
        p = bytearray(self._make())
        p[4] = 0x01   # v1 no longer supported
        with pytest.raises(PayloadError, match="version"):
            parse_payload(bytes(p))

    def test_too_short_raises(self):
        with pytest.raises(PayloadError):
            parse_payload(b"SCST\x02\x00")

    def test_truncated_ciphertext_raises(self):
        p = self._make()
        truncated = p[:PAYLOAD_FIXED_HEADER] + b"\x00" * 5
        ba = bytearray(truncated)
        offset = 6 + SALT_SIZE + PASSWORD_CIPHERTEXT_SIZE + KEY_WRAP_NONCE_SIZE + PROTECTED_KEY_SIZE + NONCE_SIZE
        struct.pack_into(">I", ba, offset, 9999)
        with pytest.raises(PayloadError):
            parse_payload(bytes(ba))

    def test_zero_ct_len_raises(self):
        p = bytearray(self._make())
        offset = 6 + SALT_SIZE + PASSWORD_CIPHERTEXT_SIZE + KEY_WRAP_NONCE_SIZE + PROTECTED_KEY_SIZE + NONCE_SIZE
        struct.pack_into(">I", p, offset, 0)
        with pytest.raises(PayloadError):
            parse_payload(bytes(p))

    def test_total_payload_size(self):
        assert total_payload_size(100) == PAYLOAD_FIXED_HEADER + 100
