"""
SecureCrypt — Flask Application Entry Point
Unified Steganography & Digital Watermarking Platform (Port 5000)
"""
import os
import io
import logging
from flask import Flask, render_template, send_file, abort, jsonify, Response

from config import (
    SECRET_KEY,
    UPLOAD_FOLDER,
    OUTPUT_FOLDER,
    KEYS_FOLDER,
    MAX_CONTENT_LENGTH,
)
from routes.encryption_routes import encryption_bp
from routes.decryption_routes import decryption_bp
from routes.watermark_routes import watermark_bp
from routes.watermark_verification_routes import watermark_verification_bp

from utils.file_utils import get_output_path, cleanup_file, get_watermark_download
from watermarking.signatures import ensure_key_pair, get_public_key_pem

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

# ── App Factory ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key           = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# ── Blueprints ─────────────────────────────────────────────────────────────────
app.register_blueprint(encryption_bp)
app.register_blueprint(decryption_bp)
app.register_blueprint(watermark_bp)
app.register_blueprint(watermark_verification_bp)

# ── Ensure directories & Ed25519 keys exist ────────────────────────────────────
for folder in [UPLOAD_FOLDER, OUTPUT_FOLDER, KEYS_FOLDER]:
    os.makedirs(folder, exist_ok=True)

ensure_key_pair()


# ── Steganography Page Routes ──────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/encrypt")
def encrypt_page():
    return render_template("encrypt.html")


@app.route("/decrypt")
def decrypt_page():
    return render_template("decrypt.html")


@app.route("/analysis")
def analysis_page():
    return render_template("analysis.html")


@app.route("/about")
def about_page():
    return render_template("about.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/profile")
def profile_page():
    return render_template("profile.html")


# ── Digital Watermarking Page Routes ───────────────────────────────────────────
@app.route("/watermark/image", endpoint="wm_image_page")
def watermark_image_page():
    return render_template("watermark_image.html")


@app.route("/watermark/pdf", endpoint="wm_pdf_page")
def watermark_pdf_page():
    return render_template("watermark_pdf.html")


@app.route("/watermark/source-code", endpoint="wm_code_page")
def watermark_code_page():
    return render_template("watermark_source_code.html")


@app.route("/watermark/verify", endpoint="wm_verify_page")
def watermark_verify_page():
    return render_template("watermark_verify.html")


# ── Download Endpoints ─────────────────────────────────────────────────────────
@app.route("/download/<token>")
def download(token):
    """Serve a generated stego image by token and delete after sending."""
    if not all(c in "0123456789abcdefABCDEF-" for c in token):
        abort(400)

    path = get_output_path(token, ".png")
    if not path:
        abort(404)

    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        abort(404)

    cleanup_file(path)

    return send_file(
        io.BytesIO(data),
        mimetype="image/png",
        as_attachment=True,
        download_name="securecrypt_stego.png",
    )


@app.route("/download/watermark/<token>")
def download_watermark(token):
    """Serve a watermarked file or signature file by token."""
    entry = get_watermark_download(token)
    if not entry:
        abort(404)

    file_path, filename = entry
    return send_file(
        file_path,
        as_attachment=True,
        download_name=filename,
    )


@app.route("/api/public-key")
def download_public_key():
    """Download the server's Ed25519 public key."""
    pem_bytes = get_public_key_pem()
    return Response(
        pem_bytes,
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=ed25519_public_key.pem"},
    )


# ── Error handlers ─────────────────────────────────────────────────────────────
@app.errorhandler(413)
def file_too_large(e):
    return jsonify({
        "success": False,
        "error": f"File too large. Maximum upload size is {MAX_CONTENT_LENGTH // (1024*1024)} MB.",
    }), 413


@app.errorhandler(404)
def not_found(e):
    return render_template("index.html"), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"success": False, "error": "Internal server error."}), 500


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
