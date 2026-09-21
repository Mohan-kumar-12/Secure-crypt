"""
Flask Web Server Entry Point — Module 2: Digital Watermarking & Verification System.
"""
import os
from flask import Flask, render_template, send_file, jsonify, Response

from config import (
    SECRET_KEY,
    MAX_CONTENT_LENGTH,
    UPLOAD_FOLDER,
    OUTPUT_FOLDER,
    KEYS_FOLDER,
)
from routes.watermark_routes import watermark_bp
from routes.verification_routes import verification_bp
from utils.file_utils import get_download_file, cleanup_temp_files
from watermarking.signatures import ensure_key_pair, get_public_key_pem

# Create Flask application
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# Register Blueprints
app.register_blueprint(watermark_bp)
app.register_blueprint(verification_bp)


# Ensure Ed25519 key pair on server startup
ensure_key_pair()


@app.route("/")
def index():
    """Main Dashboard."""
    return render_template("index.html")


@app.route("/image")
def image_page():
    """Image Watermarking page."""
    return render_template("image.html")


@app.route("/pdf")
def pdf_page():
    """PDF Watermarking page."""
    return render_template("pdf.html")


@app.route("/source-code")
def source_code_page():
    """Source Code Protection page."""
    return render_template("source_code.html")


@app.route("/verify")
def verify_page():
    """Central Content Verification Center."""
    return render_template("verify.html")


@app.route("/download/<token>")
def download_file(token):
    """Secure file download handler using single-use download tokens."""
    entry = get_download_file(token)
    if not entry:
        return render_template(
            "index.html", error="Download link invalid or expired."
        ), 404

    file_path, filename = entry
    return send_file(
        file_path,
        as_attachment=True,
        download_name=filename,
    )


@app.route("/api/public-key")
def download_public_key():
    """Endpoint to download the server's Ed25519 public key."""
    pem_bytes = get_public_key_pem()
    return Response(
        pem_bytes,
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=ed25519_public_key.pem"},
    )


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        "success": False,
        "error": "Uploaded file is too large. Maximum size is 30 MB.",
    }), 413


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        "success": False,
        "error": "An internal server error occurred. Please try again.",
    }), 500


if __name__ == "__main__":
    cleanup_temp_files()
    app.run(host="127.0.0.1", port=5001, debug=True)
