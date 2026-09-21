"""
API Routes for Content Watermark Verification.

Endpoints:
  POST /api/verify/watermark/image
  POST /api/verify/watermark/pdf
  POST /api/verify/watermark/source-code
"""
import logging
from flask import Blueprint, request, jsonify

from utils.file_validation import (
    validate_image_file,
    validate_pdf_file,
    validate_source_code_file,
    sanitize_filename,
    ValidationError,
)
from watermarking.verification import (
    verify_image,
    verify_pdf,
    verify_source_code,
)

logger = logging.getLogger(__name__)
watermark_verification_bp = Blueprint("watermark_verification", __name__)


@watermark_verification_bp.route("/api/verify/watermark/image", methods=["POST"])
def api_verify_watermark_image():
    """Verify an uploaded watermarked image."""
    try:
        image_file = request.files.get("image")
        if not image_file:
            return jsonify({"success": False, "error": "No image file uploaded."}), 400

        filename       = sanitize_filename(image_file.filename)
        reference_hash = request.form.get("reference_hash", "").strip()
        file_bytes     = image_file.read()

        try:
            validate_image_file(file_bytes, filename)
        except ValidationError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        report = verify_image(file_bytes, reference_hash=reference_hash)
        report["success"] = True
        return jsonify(report)

    except Exception:
        logger.exception("Error in /api/verify/watermark/image")
        return jsonify({"success": False, "error": "Image verification failed."}), 500


@watermark_verification_bp.route("/api/verify/watermark/pdf", methods=["POST"])
def api_verify_watermark_pdf():
    """Verify an uploaded watermarked PDF document."""
    try:
        pdf_file = request.files.get("pdf")
        if not pdf_file:
            return jsonify({"success": False, "error": "No PDF file uploaded."}), 400

        filename       = sanitize_filename(pdf_file.filename)
        reference_hash = request.form.get("reference_hash", "").strip()
        file_bytes     = pdf_file.read()

        try:
            validate_pdf_file(file_bytes, filename)
        except ValidationError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        report = verify_pdf(file_bytes, reference_hash=reference_hash)
        report["success"] = True
        return jsonify(report)

    except Exception:
        logger.exception("Error in /api/verify/watermark/pdf")
        return jsonify({"success": False, "error": "PDF verification failed."}), 500


@watermark_verification_bp.route("/api/verify/watermark/source-code", methods=["POST"])
def api_verify_watermark_source_code():
    """Verify source code file against uploaded Ed25519 signature."""
    try:
        code_file = request.files.get("code_file")
        if not code_file:
            return jsonify({"success": False, "error": "No source code file uploaded."}), 400

        filename   = sanitize_filename(code_file.filename)
        code_bytes = code_file.read()

        try:
            validate_source_code_file(code_bytes, filename)
        except ValidationError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        sig_file = request.files.get("sig_file")
        sig_text = request.form.get("signature_text", "").strip()

        signature_input = None
        if sig_file and getattr(sig_file, "filename", "").strip():
            signature_input = sig_file.read()
        elif sig_text:
            signature_input = sig_text

        if not signature_input:
            return jsonify({
                "success": False,
                "error": "Digital signature (.sig file or signature hex text) is required for source code verification.",
            }), 400

        report = verify_source_code(code_bytes, signature_input, filename=filename)
        report["success"] = True
        return jsonify(report)

    except Exception:
        logger.exception("Error in /api/verify/watermark/source-code")
        return jsonify({"success": False, "error": "Source code verification failed."}), 500
