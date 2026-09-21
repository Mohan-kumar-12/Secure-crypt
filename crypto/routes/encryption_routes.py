"""
Encryption route: POST /api/encrypt

Accepts a multipart/form-data request with:
  - image:    cover image file
  - message:  secret plaintext
  - password: user password
  - confirm:  password confirmation

Returns JSON:
  success, download_token, metrics, payload_size, capacity, security_info
"""
import io
import base64
import logging
from flask import Blueprint, request, jsonify

from crypto.encryption import encrypt_message
from utils.payload import build_payload, total_payload_size
from utils.validation import (
    validate_image_file,
    validate_password,
    validate_message,
    ValidationError,
)
from utils.file_utils import save_output
from steganography.capacity import calculate_capacity
from steganography.embed import embed_payload, image_to_png_bytes
from analysis.image_metrics import compute_metrics
from analysis.image_analysis import analyze_image
from crypto.hashing import sha256_fingerprint

logger = logging.getLogger(__name__)

encryption_bp = Blueprint("encryption", __name__)


@encryption_bp.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    """Handle encrypt & hide operation."""
    try:
        # ── Input extraction ───────────────────────────────────────────────────
        image_file = request.files.get("image")
        message    = request.form.get("message", "").strip()
        password   = request.form.get("password", "")
        confirm    = request.form.get("confirm", "")

        if not image_file:
            return jsonify({"success": False, "error": "No image file uploaded."}), 400

        file_bytes = image_file.read()

        # ── Validation ─────────────────────────────────────────────────────────
        try:
            validate_message(message)
        except ValidationError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        try:
            validate_password(password, confirm)
        except ValidationError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        try:
            cover_img = validate_image_file(file_bytes)
        except ValidationError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        # ── Capacity pre-check (estimate with max overhead) ───────────────────
        cap = calculate_capacity(cover_img)
        msg_bytes    = len(message.encode("utf-8"))
        # AES-GCM adds 16-byte tag; estimate total ciphertext = msg + 16
        est_ct_len   = msg_bytes + 16
        est_payload  = total_payload_size(est_ct_len)

        if est_payload > cap["raw_bytes"]:
            return jsonify({
                "success": False,
                "error": (
                    f"Message too large for this image. "
                    f"Estimated payload: {est_payload:,} bytes, "
                    f"Image capacity: {cap['raw_bytes']:,} bytes."
                ),
            }), 400

        # ── Encrypt (Two-Key Architecture + Password Ciphertext) ─────────────
        enc = encrypt_message(message, password)

        # ── Build structured payload (v2) ─────────────────────────────────────
        payload = build_payload(
            enc["salt"],
            enc["password_ciphertext_bytes"],
            enc["key_nonce"],
            enc["protected_key"],
            enc["msg_nonce"],
            enc["ciphertext"],
        )
        actual_payload_size = len(payload)

        if actual_payload_size > cap["raw_bytes"]:
            return jsonify({
                "success": False,
                "error": "Payload exceeds image capacity after encryption.",
            }), 400

        # ── Embed ──────────────────────────────────────────────────────────────
        stego_img = embed_payload(cover_img, payload)

        # ── Image metrics ─────────────────────────────────────────────────────
        metrics = compute_metrics(cover_img, stego_img)

        # ── Save stego image ──────────────────────────────────────────────────
        stego_bytes = image_to_png_bytes(stego_img)
        token, _    = save_output(stego_bytes, ".png")

        # ── Thumbnail previews (base64) ────────────────────────────────────────
        def img_to_b64_thumb(img, max_size=(400, 400)):
            thumb = img.copy()
            thumb.thumbnail(max_size)
            buf = io.BytesIO()
            thumb.convert("RGB").save(buf, format="JPEG", quality=85)
            return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()

        cover_thumb = img_to_b64_thumb(cover_img)
        stego_thumb = img_to_b64_thumb(stego_img)

        # ── Payload analysis ──────────────────────────────────────────────────
        embedding_pct  = round((actual_payload_size / cap["raw_bytes"]) * 100, 2)
        density_label  = (
            "Low"    if embedding_pct < 5   else
            "Medium" if embedding_pct < 20  else
            "High"
        )

        image_info = analyze_image(cover_img, len(file_bytes))

        # ── SHA-256 fingerprint (display only) ─────────────────────────────────
        payload_fingerprint = sha256_fingerprint(payload)

        return jsonify({
            "success": True,
            "download_token": token,
            "metrics": metrics,
            "payload_size":                 actual_payload_size,
            "payload_size_kb":              round(actual_payload_size / 1024, 2),
            "capacity_bytes":               cap["raw_bytes"],
            "capacity_kb":                  cap["usable_kb"],
            "embedding_pct":                embedding_pct,
            "density_label":                density_label,
            "message_size":                 msg_bytes,
            "message_size_kb":              round(msg_bytes / 1024, 2),
            "image_info":                   image_info,
            "cover_thumb":                  cover_thumb,
            "stego_thumb":                  stego_thumb,
            "sha256_fingerprint":           payload_fingerprint,
            "password_ciphertext_formatted": enc["password_ciphertext_formatted"],
            "security_info": {
                "encryption":          "AES-256-GCM",
                "key_derivation":      "PBKDF2-HMAC-SHA256",
                "key_protection":      "AES-256-GCM (Key Wrapping)",
                "session_key":         "Random 256-bit",
                "steganography":       "Adaptive LSB (ASEE)",
                "authentication":      "GCM Authentication Tag (×2)",
                "integrity":           "Enabled",
                "password_stored":     False,
                "password_storage":    "Never Stored",
                "salt":                "Random",
            },
        })

    except Exception as e:
        logger.exception("Unexpected error in /api/encrypt")
        return jsonify({
            "success": False,
            "error": "An internal server error occurred. Please try again.",
        }), 500
