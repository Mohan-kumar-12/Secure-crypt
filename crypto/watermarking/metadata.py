"""
Watermark ID Generation and Metadata Structure.
"""
import uuid
import datetime
import json
from typing import Dict, Any


def generate_watermark_id(category: str) -> str:
    """
    Generate a dynamic unique Watermark ID.

    Examples:
        WM-IMG-2026-A8F291C4
        WM-PDF-2026-B3C402E1
        WM-CODE-2026-7E194D80
    """
    year = datetime.datetime.now().year
    prefix = category.upper()
    if prefix not in {"IMG", "PDF", "CODE"}:
        prefix = "DOC"

    hex_snippet = uuid.uuid4().hex[:8].upper()
    return f"WM-{prefix}-{year}-{hex_snippet}"


def build_watermark_metadata(
    watermark_id: str,
    owner: str,
    project_id: str,
    content_type: str,
    extra: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Create a structured watermark metadata dictionary.
    No passwords, private keys, or extraneous PII stored.
    """
    meta = {
        "watermark_id":   watermark_id,
        "owner":          owner or "Anonymous Owner",
        "project_id":     project_id or "GENERAL-PROJECT",
        "content_type":   content_type,
        "created_at":     datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hash_algorithm": "SHA-256",
    }
    if extra:
        meta.update(extra)
    return meta


def serialize_metadata(meta: Dict[str, Any]) -> str:
    """Serialize metadata dict to JSON string."""
    return json.dumps(meta, ensure_ascii=False)


def deserialize_metadata(json_str: str) -> Dict[str, Any]:
    """Parse JSON string back to metadata dict."""
    try:
        return json.loads(json_str)
    except Exception:
        return {}
