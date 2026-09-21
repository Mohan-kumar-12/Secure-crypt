"""
Cryptography tests for SecureCrypt (Two-Key Architecture with Password Ciphertext).
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from cryptography.exceptions import InvalidTag

from crypto.encryption import encrypt_message, decrypt_message
from crypto.key_derivation import derive_key, generate_salt
from crypto.hashing import sha256_fingerprint


class TestKeyDerivation:
    def test_derive_key_returns_32_bytes(self):
        salt = generate_salt()
        key  = derive_key("testpassword123", salt)
        assert len(key) == 32

    def test_same_password_same_salt_same_key(self):
        salt = generate_salt()
        k1   = derive_key("mypassword", salt)
        k2   = derive_key("mypassword", salt)
        assert k1 == k2

    def test_different_salts_different_keys(self):
        s1, s2 = generate_salt(), generate_salt()
        k1 = derive_key("mypassword", s1)
        k2 = derive_key("mypassword", s2)
        assert k1 != k2

    def test_salt_is_16_bytes(self):
        assert len(generate_salt()) == 16

    def test_different_salts_each_call(self):
        assert generate_salt() != generate_salt()

    def test_invalid_salt_length_raises(self):
        with pytest.raises(ValueError):
            derive_key("password", b"tooshort")

    def test_non_str_password_raises(self):
        salt = generate_salt()
        with pytest.raises(TypeError):
            derive_key(b"not_a_string", salt)


class TestEncryptDecrypt:
    def test_roundtrip_with_original_password(self):
        message = "Hello, SecureCrypt!"
        password = "TestPassword123!"
        enc = encrypt_message(message, password)
        result = decrypt_message(
            enc["salt"], enc["password_ciphertext_bytes"], enc["key_nonce"],
            enc["protected_key"], enc["msg_nonce"], enc["ciphertext"], password
        )
        assert result == message

    def test_roundtrip_with_ciphertext_password(self):
        message = "Hello, SecureCrypt!"
        password = "TestPassword123!"
        enc = encrypt_message(message, password)
        # Decrypt using the converted ciphertext password string
        cipher_pw = enc["password_ciphertext_formatted"]
        result = decrypt_message(
            enc["salt"], enc["password_ciphertext_bytes"], enc["key_nonce"],
            enc["protected_key"], enc["msg_nonce"], enc["ciphertext"], cipher_pw
        )
        assert result == message

    def test_unicode_roundtrip(self):
        message = "मेरा गुप्त संदेश 🔐 Héllo Wörld"
        password = "UnicodePass99!"
        enc = encrypt_message(message, password)
        result = decrypt_message(
            enc["salt"], enc["password_ciphertext_bytes"], enc["key_nonce"],
            enc["protected_key"], enc["msg_nonce"], enc["ciphertext"], password
        )
        assert result == message

    def test_wrong_password_fails(self):
        enc = encrypt_message("secret text", "CorrectPass123!")
        with pytest.raises(InvalidTag):
            decrypt_message(
                enc["salt"], enc["password_ciphertext_bytes"], enc["key_nonce"],
                enc["protected_key"], enc["msg_nonce"], enc["ciphertext"], "WrongPass123!"
            )

    def test_modified_ciphertext_fails(self):
        enc = encrypt_message("important data", "StrongPass99!")
        ct = bytearray(enc["ciphertext"])
        ct[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt_message(
                enc["salt"], enc["password_ciphertext_bytes"], enc["key_nonce"],
                enc["protected_key"], enc["msg_nonce"], bytes(ct), "StrongPass99!"
            )

    def test_modified_protected_key_fails(self):
        enc = encrypt_message("important data", "StrongPass99!")
        pk = bytearray(enc["protected_key"])
        pk[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt_message(
                enc["salt"], enc["password_ciphertext_bytes"], enc["key_nonce"],
                bytes(pk), enc["msg_nonce"], enc["ciphertext"], "StrongPass99!"
            )

    def test_different_encryptions_different_ciphertext(self):
        enc1 = encrypt_message("same message", "samepassword1")
        enc2 = encrypt_message("same message", "samepassword1")
        assert enc1["ciphertext"]                != enc2["ciphertext"]
        assert enc1["salt"]                      != enc2["salt"]
        assert enc1["password_ciphertext_bytes"] != enc2["password_ciphertext_bytes"]
        assert enc1["key_nonce"]                 != enc2["key_nonce"]
        assert enc1["msg_nonce"]                 != enc2["msg_nonce"]
        assert enc1["protected_key"]             != enc2["protected_key"]

    def test_empty_message_raises(self):
        with pytest.raises(ValueError):
            encrypt_message("", "password123!")

    def test_empty_password_raises_encrypt(self):
        with pytest.raises(ValueError):
            encrypt_message("hello", "")

    def test_large_message_roundtrip(self):
        message  = "A" * 50_000
        password = "LargeMessagePass1!"
        enc = encrypt_message(message, password)
        result = decrypt_message(
            enc["salt"], enc["password_ciphertext_bytes"], enc["key_nonce"],
            enc["protected_key"], enc["msg_nonce"], enc["ciphertext"], password
        )
        assert result == message

    def test_ciphertext_longer_than_plaintext(self):
        """AES-GCM adds a 16-byte authentication tag."""
        msg = "test"
        enc = encrypt_message(msg, "pass1234!")
        pt_bytes = len(msg.encode())
        ct_bytes = len(enc["ciphertext"])
        assert ct_bytes == pt_bytes + 16

    def test_nonces_are_12_bytes(self):
        enc = encrypt_message("test", "pass1234!")
        assert len(enc["key_nonce"]) == 12
        assert len(enc["msg_nonce"]) == 12

    def test_protected_key_is_48_bytes(self):
        enc = encrypt_message("test", "pass1234!")
        assert len(enc["protected_key"]) == 48

    def test_password_ciphertext_bytes_is_32_bytes(self):
        enc = encrypt_message("test", "pass1234!")
        assert len(enc["password_ciphertext_bytes"]) == 32


class TestHashing:
    def test_sha256_hex_length(self):
        fp = sha256_fingerprint(b"hello")
        assert len(fp) == 64

    def test_sha256_deterministic(self):
        assert sha256_fingerprint(b"abc") == sha256_fingerprint(b"abc")

    def test_sha256_different_inputs(self):
        assert sha256_fingerprint(b"abc") != sha256_fingerprint(b"xyz")
