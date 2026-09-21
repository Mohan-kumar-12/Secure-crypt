"""
Security tests for Password Protection Module — Two-Key Architecture with Password Ciphertext.

Implements all security test scenarios:
  Test 1 — Correct password roundtrip
  Test 2 — Decryption with converted Ciphertext / Numerical Password
  Test 3 — Wrong password rejection
  Test 4 — Modified protected session key tamper detection
  Test 5 — Modified ciphertext tamper detection
  Test 6 — Different passwords produce different protected payloads
  Test 7 — Same password multiple encryptions produce unique salts, nonces, keys, and ciphertexts
  Test 8 — Complete steganography embedding & extraction roundtrip
  Test 9 — Password Ciphertext is stored in payload header
  Test 10 — Plaintext password is never embedded directly in payload
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from cryptography.exceptions import InvalidTag
from PIL import Image

from crypto.password_protection import (
    derive_password_key,
    generate_session_key,
    protect_session_key,
    recover_session_key,
    compute_password_ciphertext,
    encrypt_message as raw_encrypt_message,
    decrypt_message as raw_decrypt_message,
    secure_encrypt,
    secure_decrypt,
)
from utils.payload import build_payload, parse_payload
from steganography.embed import embed_payload
from steganography.extract import extract_payload


class TestPasswordProtectionSecuritySuite:

    # ── Test 1 — Correct original password ─────────────────────────────────────
    def test_1_correct_password_success(self):
        message  = "Top Secret Project Bluebook Operational Parameters"
        password = "CorrectSuperSecretPassword123!"

        enc = secure_encrypt(message, password)

        decrypted = secure_decrypt(
            salt                      = enc["salt"],
            password_ciphertext_bytes = enc["password_ciphertext_bytes"],
            key_nonce                 = enc["key_nonce"],
            protected_key             = enc["protected_key"],
            msg_nonce                 = enc["msg_nonce"],
            ciphertext                = enc["ciphertext"],
            password                  = password,
        )

        assert decrypted == message, "Correct original password must successfully decrypt plaintext."

    # ── Test 2 — Decrypt using converted Password Ciphertext ──────────────────
    def test_2_decryption_with_converted_ciphertext_password(self):
        """Verify receiver can decrypt using the generated Ciphertext / Numerical Password."""
        message  = "Top Secret Data"
        password = "MyPassword123!"

        enc = secure_encrypt(message, password)
        cipher_pw = enc["password_ciphertext_formatted"]   # e.g. "8F2A-41C9-..."

        decrypted = secure_decrypt(
            salt                      = enc["salt"],
            password_ciphertext_bytes = enc["password_ciphertext_bytes"],
            key_nonce                 = enc["key_nonce"],
            protected_key             = enc["protected_key"],
            msg_nonce                 = enc["msg_nonce"],
            ciphertext                = enc["ciphertext"],
            password                  = cipher_pw,
        )

        assert decrypted == message, "Entering the converted Ciphertext Password must decrypt plaintext."

    # ── Test 3 — Wrong password ───────────────────────────────────────────────
    def test_3_wrong_password_fails(self):
        message  = "Confidential Intelligence Report"
        password = "RightPassword123!"

        enc = secure_encrypt(message, password)

        with pytest.raises(InvalidTag):
            secure_decrypt(
                salt                      = enc["salt"],
                password_ciphertext_bytes = enc["password_ciphertext_bytes"],
                key_nonce                 = enc["key_nonce"],
                protected_key             = enc["protected_key"],
                msg_nonce                 = enc["msg_nonce"],
                ciphertext                = enc["ciphertext"],
                password                  = "WrongPassword456!",
            )

    # ── Test 4 — Modified protected session key ─────────────────────────────
    def test_4_modified_protected_session_key_fails(self):
        message  = "Integrity Sensitive Data"
        password = "SecurePassword999!"

        enc = secure_encrypt(message, password)

        tampered_pk = bytearray(enc["protected_key"])
        tampered_pk[5] ^= 0xFF

        with pytest.raises(InvalidTag):
            secure_decrypt(
                salt                      = enc["salt"],
                password_ciphertext_bytes = enc["password_ciphertext_bytes"],
                key_nonce                 = enc["key_nonce"],
                protected_key             = bytes(tampered_pk),
                msg_nonce                 = enc["msg_nonce"],
                ciphertext                = enc["ciphertext"],
                password                  = password,
            )

    # ── Test 5 — Modified ciphertext ─────────────────────────────────────────
    def test_5_modified_ciphertext_fails(self):
        message  = "Tamper Check Message"
        password = "SecurePassword999!"

        enc = secure_encrypt(message, password)

        tampered_ct = bytearray(enc["ciphertext"])
        tampered_ct[0] ^= 0xFF

        with pytest.raises(InvalidTag):
            secure_decrypt(
                salt                      = enc["salt"],
                password_ciphertext_bytes = enc["password_ciphertext_bytes"],
                key_nonce                 = enc["key_nonce"],
                protected_key             = enc["protected_key"],
                msg_nonce                 = enc["msg_nonce"],
                ciphertext                = bytes(tampered_ct),
                password                  = password,
            )

    # ── Test 6 — Different passwords ──────────────────────────────────────────
    def test_6_different_passwords_produce_different_protected_payloads(self):
        message = "Same Secret Message"

        enc1 = secure_encrypt(message, "PasswordAlpha123!")
        enc2 = secure_encrypt(message, "PasswordBeta456!")

        assert enc1["protected_key"]             != enc2["protected_key"]
        assert enc1["salt"]                      != enc2["salt"]
        assert enc1["password_ciphertext_bytes"] != enc2["password_ciphertext_bytes"]
        assert enc1["ciphertext"]                != enc2["ciphertext"]

    # ── Test 7 — Same password, multiple encryptions ─────────────────────────
    def test_7_same_password_multiple_encryptions_randomness(self):
        message  = "Static Secret Message"
        password = "ReusedPassword123!"

        enc1 = secure_encrypt(message, password)
        enc2 = secure_encrypt(message, password)

        assert enc1["salt"]                      != enc2["salt"]
        assert enc1["password_ciphertext_bytes"] != enc2["password_ciphertext_bytes"]
        assert enc1["key_nonce"]                 != enc2["key_nonce"]
        assert enc1["msg_nonce"]                 != enc2["msg_nonce"]
        assert enc1["protected_key"]             != enc2["protected_key"]
        assert enc1["ciphertext"]                != enc2["ciphertext"]

    # ── Test 8 — End-to-end Steganography Workflow ────────────────────────────
    def test_8_full_steganography_workflow(self):
        message  = "End-To-End Steganographic Cryptography Test"
        password = "E2EPassword2026!"

        # 1. Encrypt message
        enc = secure_encrypt(message, password)

        # 2. Build payload
        payload = build_payload(
            enc["salt"],
            enc["password_ciphertext_bytes"],
            enc["key_nonce"],
            enc["protected_key"],
            enc["msg_nonce"],
            enc["ciphertext"],
        )

        # 3. Create dummy cover image
        cover_img = Image.new("RGB", (250, 250), color=(120, 150, 180))

        # 4. Embed payload
        stego_img = embed_payload(cover_img, payload)

        # 5. Extract payload from stego image
        extracted_bytes = extract_payload(stego_img)

        # 6. Parse extracted payload
        parsed = parse_payload(extracted_bytes)

        # 7. Recover session key & decrypt message using original password
        decrypted_orig = secure_decrypt(
            salt                      = parsed["salt"],
            password_ciphertext_bytes = parsed["password_ciphertext_bytes"],
            key_nonce                 = parsed["key_nonce"],
            protected_key             = parsed["protected_key"],
            msg_nonce                 = parsed["msg_nonce"],
            ciphertext                = parsed["ciphertext"],
            password                  = password,
        )
        assert decrypted_orig == message

        # 8. Recover session key & decrypt message using password ciphertext string
        decrypted_cipher = secure_decrypt(
            salt                      = parsed["salt"],
            password_ciphertext_bytes = parsed["password_ciphertext_bytes"],
            key_nonce                 = parsed["key_nonce"],
            protected_key             = parsed["protected_key"],
            msg_nonce                 = parsed["msg_nonce"],
            ciphertext                = parsed["ciphertext"],
            password                  = enc["password_ciphertext_formatted"],
        )
        assert decrypted_cipher == message

    # ── Test 9 — Password Ciphertext in payload ────────────────────────────────
    def test_9_password_ciphertext_stored_in_payload(self):
        enc = secure_encrypt("Secret message", "MyPassword123!")
        payload = build_payload(
            enc["salt"],
            enc["password_ciphertext_bytes"],
            enc["key_nonce"],
            enc["protected_key"],
            enc["msg_nonce"],
            enc["ciphertext"],
        )

        parsed = parse_payload(payload)
        assert parsed["password_ciphertext_bytes"] == enc["password_ciphertext_bytes"]

    # ── Test 10 — Plaintext password non-storage check ───────────────────────
    def test_10_plaintext_password_never_in_payload(self):
        password = "SuperSecretPassword123!"
        enc = secure_encrypt("Secret message", password)
        payload = build_payload(
            enc["salt"],
            enc["password_ciphertext_bytes"],
            enc["key_nonce"],
            enc["protected_key"],
            enc["msg_nonce"],
            enc["ciphertext"],
        )

        pw_bytes = password.encode("utf-8")
        assert pw_bytes not in payload, "Plaintext password bytes MUST NOT be present anywhere in payload."
