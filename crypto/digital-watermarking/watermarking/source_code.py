"""
Source Code Protection & Comment Header Watermarking.

Inserts language-specific comment headers at the top of source code files
without altering or corrupting code execution logic.
Integrates with Ed25519 digital signatures for cryptographic authenticity verification.
"""
import os
import re
from typing import Tuple, Dict, Any

from watermarking.metadata import generate_watermark_id, build_watermark_metadata
from watermarking.hashing import calculate_sha256
from watermarking.signatures import sign_file


def get_comment_syntax(filename: str) -> Tuple[str, str, str]:
    """
    Determine the appropriate comment syntax based on file extension.

    Returns:
        Tuple of (header_start, line_prefix, header_end)
    """
    ext = os.path.splitext(filename)[1].lower().lstrip(".")

    if ext in {"py", "sh", "bash", "yaml", "yml", "rb", "pl", "r", "sql"}:
        return ("# =========================================", "# ", "# =========================================")
    elif ext in {"java", "c", "cpp", "h", "hpp", "js", "ts", "jsx", "tsx", "css", "cs", "go", "rs", "php", "swift", "kt"}:
        return ("/* =========================================", " * ", " * ========================================= */")
    elif ext in {"html", "htm", "xml", "svg"}:
        return ("<!-- =========================================", " ", "========================================= -->")
    else:
        return ("# =========================================", "# ", "# =========================================")


def protect_source_code(
    code_bytes: bytes,
    filename: str,
    owner: str = "Mohan Kumar J",
    project_id: str = "PROJECT-001",
) -> Tuple[bytes, bytes, str, Dict[str, Any]]:
    """
    Apply structured protection header to source code and generate Ed25519 signature.

    Args:
        code_bytes: Raw source code file bytes.
        filename:   Original filename (e.g. 'main.py', 'App.java').
        owner:      Owner name.
        project_id: Project identifier.

    Returns:
        Tuple of (protected_code_bytes, signature_bytes, signature_hex, metadata_dict)
    """
    text_content = code_bytes.decode("utf-8", errors="replace")

    watermark_id = generate_watermark_id("CODE")
    meta = build_watermark_metadata(
        watermark_id=watermark_id,
        owner=owner,
        project_id=project_id,
        content_type="Source Code",
        extra={"filename": filename},
    )

    header_start, line_prefix, header_end = get_comment_syntax(filename)

    header_lines = [
        header_start,
        f"{line_prefix}Digital Content Protection & Authenticity",
        f"{line_prefix}Owner: {owner}",
        f"{line_prefix}Project ID: {project_id}",
        f"{line_prefix}Watermark ID: {watermark_id}",
        f"{line_prefix}Created: {meta['created_at']}",
        header_end,
        "",  # Blank line separator
    ]
    header_block = "\n".join(header_lines)

    # Handle sheath shebang in Python/Shell scripts
    if text_content.startswith("#!"):
        lines = text_content.splitlines(keepends=True)
        shebang = lines[0]
        rest = "".join(lines[1:])
        protected_text = shebang + "\n" + header_block + rest
    else:
        protected_text = header_block + text_content

    protected_code_bytes = protected_text.encode("utf-8")

    # Generate Ed25519 cryptographic signature of the exact protected code bytes
    sig_bytes, sig_hex = sign_file(protected_code_bytes)

    # Compute SHA-256 fingerprint of protected source code
    sha256_hash = calculate_sha256(protected_code_bytes)
    meta["sha256"] = sha256_hash
    meta["signature_hex"] = sig_hex

    return protected_code_bytes, sig_bytes, sig_hex, meta


def detect_code_watermark(code_bytes: bytes) -> Tuple[bool, Dict[str, Any]]:
    """
    Parse source code comments to extract Watermark ID, Owner, and Project ID.

    Returns:
        Tuple of (found_boolean, metadata_dict)
    """
    try:
        text = code_bytes.decode("utf-8", errors="replace")
        top_lines = "\n".join(text.splitlines()[:30])

        wmid_match  = re.search(r"Watermark\s*ID\s*:\s*(WM-CODE-[A-Za-z0-9-]+)", top_lines, re.IGNORECASE)
        owner_match = re.search(r"Owner\s*:\s*(.+)", top_lines, re.IGNORECASE)
        proj_match  = re.search(r"Project\s*ID\s*:\s*(.+)", top_lines, re.IGNORECASE)

        if wmid_match:
            return True, {
                "watermark_id": wmid_match.group(1).strip(),
                "owner":        owner_match.group(1).strip() if owner_match else "Unknown Owner",
                "project_id":   proj_match.group(1).strip() if proj_match else "UNKNOWN",
                "content_type": "Source Code",
            }
    except Exception:
        pass

    return False, {}
