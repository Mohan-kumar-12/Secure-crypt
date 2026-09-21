"""
Decryption route: POST /api/decrypt

Accepts multipart/form-data:
  - image:    stego image file
  - password: user password

Returns JSON:
  success, message, integrity_status, authentication_status

Two-Key Architecture:
  1. Extract payload from stego image
  2. Parse payload → salt, key_nonce, protected_key, msg_nonce, ciphertext
  3. Derive password key from user password + salt
  4. Recover session key (AES-GCM auth check #1)
  5. Decrypt message (AES-GCM auth check #2)
"""
import logging
from flask import Blueprint, request, jsonify
from cryptography.exceptions import InvalidTag

from utils.validation import validate_image_file, validate_password, ValidationError
from steganography.extract import extract_payload
from utils.payload import parse_payload, PayloadError
from crypto.encryption import decrypt_message
from crypto.hashing import sha256_fingerprint
from analysis.image_analysis import analyze_image

logger = logging.getLogger(__name__)

decryption_bp = Blueprint("decryption", __name__)


@decryption_bp.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    """Handle extract & decrypt operation."""
    try:
        # ── Input extraction ───────────────────────────────────────────────────
        image_file = request.files.get("image")
        password   = request.form.get("password", "")

        if not image_file:
            return jsonify({"success": False, "error": "No stego image uploaded."}), 400

        if not password:
            return jsonify({"success": False, "error": "Password is required."}), 400

        file_bytes = image_file.read()

        # ── Validate image ─────────────────────────────────────────────────────
        try:
            stego_img = validate_image_file(file_bytes)
        except ValidationError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        image_info = analyze_image(stego_img, len(file_bytes))

        # ── Extract payload ────────────────────────────────────────────────────
        try:
            raw_payload = extract_payload(stego_img)
        except PayloadError as e:
            return jsonify({
                "success":             False,
                "error":               str(e),
                "authentication_status": "FAILED",
                "integrity_status":      "UNVERIFIED",
                "image_info":            image_info,
            }), 400

        # ── Parse payload (v2: two-key architecture) ───────────────────────────
        try:
            parsed = parse_payload(raw_payload)
        except PayloadError as e:
            return jsonify({
                "success":             False,
                "error":               str(e),
                "authentication_status": "FAILED",
                "integrity_status":      "UNVERIFIED",
                "image_info":            image_info,
            }), 400

        payload_fingerprint = sha256_fingerprint(raw_payload)

        # ── Decrypt (Two-Key Architecture) ─────────────────────────────────────
        # Step 1: Password → PBKDF2 → PDK → Recover Session Key (auth check #1)
        # Step 2: Session Key → Decrypt Message (auth check #2)
        try:
            plaintext = decrypt_message(
                salt                      = parsed["salt"],
                password_ciphertext_bytes = parsed["password_ciphertext_bytes"],
                key_nonce                 = parsed["key_nonce"],
                protected_key             = parsed["protected_key"],
                msg_nonce                 = parsed["msg_nonce"],
                ciphertext                = parsed["ciphertext"],
                password                  = password,
            )
        except InvalidTag:
            # Do not distinguish between wrong password and tampered payload
            # to avoid leaking information to an attacker
            return jsonify({
                "success":               False,
                "error": (
                    "Payload authentication failed. Possible causes: "
                    "incorrect password, modified stego image, or corrupted payload."
                ),
                "authentication_status": "FAILED",
                "integrity_status":      "TAMPERED_OR_WRONG_KEY",
                "sha256_fingerprint":    payload_fingerprint,
                "image_info":            image_info,
            }), 400
        except Exception:
            logger.exception("Unexpected decryption error")
            return jsonify({
                "success": False,
                "error":   "Decryption failed due to an unexpected error.",
            }), 500

        # ── Success ────────────────────────────────────────────────────────────
        return jsonify({
            "success":               True,
            "message":               plaintext,
            "authentication_status": "VERIFIED",
            "integrity_status":      "VERIFIED",
            "password_verified":     True,
            "session_key_recovered": True,
            "message_authenticated": True,
            "sha256_fingerprint":    payload_fingerprint,
            "payload_size":          len(raw_payload),
            "payload_size_kb":       round(len(raw_payload) / 1024, 2),
            "image_info":            image_info,
        })

    except Exception:
        logger.exception("Unexpected error in /api/decrypt")
        return jsonify({
            "success": False,
            "error":   "An internal server error occurred. Please try again.",
        }), 500


@decryption_bp.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Analyze a stego image to check for a SecureCrypt payload.
    Returns metadata without attempting decryption.
    """
    try:
        image_file = request.files.get("image")
        if not image_file:
            return jsonify({"success": False, "error": "No image uploaded."}), 400

        file_bytes = image_file.read()

        try:
            img = validate_image_file(file_bytes)
        except ValidationError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        image_info = analyze_image(img, len(file_bytes))

        # Try to detect if payload exists
        payload_detected = False
        payload_status   = "No SecureCrypt payload detected."
        try:
            raw_payload = extract_payload(img)
            parsed      = parse_payload(raw_payload)
            payload_detected = True
            payload_status   = "SecureCrypt payload detected (awaiting decryption)."
            payload_fp       = sha256_fingerprint(raw_payload)
        except Exception:
            payload_fp = None

        return jsonify({
            "success":          True,
            "image_info":       image_info,
            "payload_detected": payload_detected,
            "payload_status":   payload_status,
            "sha256_fingerprint": payload_fp,
        })

    except Exception:
        logger.exception("Unexpected error in /api/analyze")
        return jsonify({"success": False, "error": "Analysis failed."}), 500
