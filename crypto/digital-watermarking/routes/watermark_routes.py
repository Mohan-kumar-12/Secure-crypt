"""
API Routes for Content Watermarking and Protection.

Endpoints:
  POST /api/watermark/image
  POST /api/watermark/pdf
  POST /api/watermark/source-code
"""
import io
import base64
import logging
from flask import Blueprint, request, jsonify

from utils.file_validation import (
    validate_image_file,
    validate_pdf_file,
    validate_source_code_file,
    sanitize_filename,
    ValidationError,
)
from utils.file_utils import save_output
from watermarking.image_watermark import apply_image_watermark
from watermarking.pdf_watermark import apply_pdf_watermark
from watermarking.source_code import protect_source_code, get_comment_syntax

logger = logging.getLogger(__name__)
watermark_bp = Blueprint("watermark", __name__)


@watermark_bp.route("/api/watermark/image", methods=["POST"])
def api_watermark_image():
    """Handle Image Watermarking request."""
    try:
        image_file = request.files.get("image")
        if not image_file:
            return jsonify({"success": False, "error": "No image file uploaded."}), 400

        filename       = sanitize_filename(image_file.filename)
        watermark_text = request.form.get("watermark_text", "CONFIDENTIAL").strip()
        owner          = request.form.get("owner", "Mohan Kumar J").strip()
        project_id     = request.form.get("project_id", "PROJECT-001").strip()
        position       = request.form.get("position", "center").strip()

        try:
            opacity_pct = float(request.form.get("opacity", 30))
            font_size   = int(request.form.get("font_size", 28))
        except ValueError:
            return jsonify({"success": False, "error": "Invalid opacity or font size parameter."}), 400

        file_bytes = image_file.read()

        # Validate genuine image
        try:
            validate_image_file(file_bytes, filename)
        except ValidationError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        # Apply Real Watermark
        out_bytes, meta = apply_image_watermark(
            file_bytes,
            watermark_text=watermark_text,
            owner=owner,
            project_id=project_id,
            position=position,
            opacity_pct=opacity_pct,
            font_size=font_size,
        )

        # Save output and generate token
        out_filename = f"watermarked_{filename}"
        token, _     = save_output(out_bytes, out_filename)

        # Base64 thumbnail preview
        try:
            from PIL import Image
            thumb = Image.open(io.BytesIO(out_bytes))
            thumb.thumbnail((400, 400))
            buf = io.BytesIO()
            thumb.convert("RGB").save(buf, format="JPEG", quality=85)
            preview_b64 = "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()
        except Exception:
            preview_b64 = None

        return jsonify({
            "success":            True,
            "download_token":     token,
            "filename":           out_filename,
            "watermark_id":       meta["watermark_id"],
            "owner":              meta["owner"],
            "project_id":         meta["project_id"],
            "sha256":             meta["sha256"],
            "created_at":         meta["created_at"],
            "preview_b64":        preview_b64,
            "watermark_details":  meta,
        })

    except Exception:
        logger.exception("Error in /api/watermark/image")
        return jsonify({"success": False, "error": "Image watermarking processing failed."}), 500


@watermark_bp.route("/api/watermark/pdf", methods=["POST"])
def api_watermark_pdf():
    """Handle PDF Watermarking request."""
    try:
        pdf_file = request.files.get("pdf")
        if not pdf_file:
            return jsonify({"success": False, "error": "No PDF file uploaded."}), 400

        filename       = sanitize_filename(pdf_file.filename)
        watermark_text = request.form.get("watermark_text", "CONFIDENTIAL").strip()
        owner          = request.form.get("owner", "Mohan Kumar J").strip()
        project_id     = request.form.get("project_id", "PROJECT-001").strip()
        position       = request.form.get("position", "center").strip()
        pages_option   = request.form.get("pages_option", "all").strip()
        selected_pages = request.form.get("selected_pages", "").strip()

        try:
            opacity_pct = float(request.form.get("opacity", 20))
            font_size   = int(request.form.get("font_size", 28))
        except ValueError:
            return jsonify({"success": False, "error": "Invalid opacity or font size parameter."}), 400

        file_bytes = pdf_file.read()

        # Validate genuine PDF
        try:
            validate_pdf_file(file_bytes, filename)
        except ValidationError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        # Apply PyMuPDF Visible Page Watermark
        out_bytes, meta = apply_pdf_watermark(
            file_bytes,
            watermark_text=watermark_text,
            owner=owner,
            project_id=project_id,
            position=position,
            opacity_pct=opacity_pct,
            font_size=font_size,
            pages_option=pages_option,
            selected_pages=selected_pages,
        )

        out_filename = f"watermarked_{filename}"
        token, _     = save_output(out_bytes, out_filename)

        return jsonify({
            "success":           True,
            "download_token":    token,
            "filename":          out_filename,
            "watermark_id":      meta["watermark_id"],
            "owner":             meta["owner"],
            "project_id":        meta["project_id"],
            "sha256":            meta["sha256"],
            "created_at":        meta["created_at"],
            "watermark_details": meta,
        })

    except Exception:
        logger.exception("Error in /api/watermark/pdf")
        return jsonify({"success": False, "error": "PDF watermarking processing failed."}), 500


@watermark_bp.route("/api/watermark/source-code", methods=["POST"])
def api_watermark_source_code():
    """Handle Source Code Protection & Ed25519 Signing request."""
    try:
        code_file = request.files.get("code_file")
        if not code_file:
            return jsonify({"success": False, "error": "No source code file uploaded."}), 400

        filename   = sanitize_filename(code_file.filename)
        owner      = request.form.get("owner", "Mohan Kumar J").strip()
        project_id = request.form.get("project_id", "PROJECT-001").strip()

        file_bytes = code_file.read()

        try:
            validate_source_code_file(file_bytes, filename)
        except ValidationError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        # Apply Language Comment Header + Ed25519 Signature
        protected_bytes, sig_bytes, sig_hex, meta = protect_source_code(
            file_bytes,
            filename=filename,
            owner=owner,
            project_id=project_id,
        )

        # Save protected source file
        out_filename = f"protected_{filename}"
        code_token, _ = save_output(protected_bytes, out_filename)

        # Save signature file (.sig)
        sig_filename = f"{filename}.sig"
        sig_token, _ = save_output(sig_bytes, sig_filename)

        return jsonify({
            "success":               True,
            "code_download_token":   code_token,
            "code_filename":         out_filename,
            "sig_download_token":    sig_token,
            "sig_filename":          sig_filename,
            "watermark_id":          meta["watermark_id"],
            "owner":                 meta["owner"],
            "project_id":            meta["project_id"],
            "sha256":                meta["sha256"],
            "signature_hex":         sig_hex,
            "created_at":            meta["created_at"],
            "watermark_details":     meta,
        })

    except Exception:
        logger.exception("Error in /api/watermark/source-code")
        return jsonify({"success": False, "error": "Source code protection processing failed."}), 500
