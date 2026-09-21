"""
Verification Orchestrator Module.
"""
from typing import Dict, Any, Union

from watermarking.image_watermark import detect_image_watermark
from watermarking.pdf_watermark import detect_pdf_watermark
from watermarking.source_code import detect_code_watermark
from watermarking.hashing import calculate_sha256
from watermarking.signatures import verify_signature


def verify_image(image_bytes: bytes, reference_hash: str = "") -> Dict[str, Any]:
    """Verify a protected image file."""
    current_hash = calculate_sha256(image_bytes)
    found, meta = detect_image_watermark(image_bytes)

    if reference_hash and reference_hash.strip():
        hash_match = (current_hash.upper() == reference_hash.strip().upper())
    else:
        hash_match = None

    if found:
        status = "AUTHENTIC" if (hash_match is None or hash_match) else "INTEGRITY_CHECK_FAILED"
        integrity = "VERIFIED" if (hash_match is None or hash_match) else "FAILED"
    else:
        status = "WATERMARK_NOT_FOUND"
        integrity = "UNVERIFIED"

    return {
        "content_type":        "Image",
        "watermark_found":     found,
        "watermark_id":        meta.get("watermark_id", "N/A"),
        "owner":               meta.get("owner", "N/A"),
        "project_id":          meta.get("project_id", "N/A"),
        "created_at":          meta.get("created_at", "N/A"),
        "current_sha256":      current_hash,
        "reference_sha256":    reference_hash or "Not Provided",
        "integrity_status":    integrity,
        "final_status":        status,
        "verification_details": meta,
    }


def verify_pdf(pdf_bytes: bytes, reference_hash: str = "") -> Dict[str, Any]:
    """Verify a protected PDF document."""
    current_hash = calculate_sha256(pdf_bytes)
    found, meta = detect_pdf_watermark(pdf_bytes)

    if reference_hash and reference_hash.strip():
        hash_match = (current_hash.upper() == reference_hash.strip().upper())
    else:
        hash_match = None

    if found:
        status = "AUTHENTIC" if (hash_match is None or hash_match) else "INTEGRITY_CHECK_FAILED"
        integrity = "VERIFIED" if (hash_match is None or hash_match) else "FAILED"
    else:
        status = "WATERMARK_NOT_FOUND"
        integrity = "UNVERIFIED"

    return {
        "content_type":        "PDF",
        "watermark_found":     found,
        "watermark_id":        meta.get("watermark_id", "N/A"),
        "owner":               meta.get("owner", "N/A"),
        "project_id":          meta.get("project_id", "N/A"),
        "total_pages":         meta.get("total_pages", "N/A"),
        "current_sha256":      current_hash,
        "reference_sha256":    reference_hash or "Not Provided",
        "integrity_status":    integrity,
        "final_status":        status,
        "verification_details": meta,
    }


def verify_source_code(
    code_bytes: bytes,
    signature_input: Union[bytes, str],
    filename: str = "source_file",
) -> Dict[str, Any]:
    """Verify a protected source code file against an Ed25519 digital signature."""
    current_hash = calculate_sha256(code_bytes)
    header_found, meta = detect_code_watermark(code_bytes)

    signature_valid = verify_signature(code_bytes, signature_input)

    if signature_valid:
        status = "AUTHENTIC"
        integrity = "VERIFIED"
    else:
        status = "VERIFICATION_FAILED"
        integrity = "FAILED"

    return {
        "content_type":        "Source Code",
        "watermark_found":     header_found,
        "watermark_id":        meta.get("watermark_id", "N/A"),
        "owner":               meta.get("owner", "N/A"),
        "project_id":          meta.get("project_id", "N/A"),
        "current_sha256":      current_hash,
        "signature_valid":     signature_valid,
        "integrity_status":    integrity,
        "final_status":        status,
        "filename":            filename,
    }
