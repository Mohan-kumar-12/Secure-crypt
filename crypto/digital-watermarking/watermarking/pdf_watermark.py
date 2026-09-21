"""
PDF Watermarking Implementation using PyMuPDF (fitz).

Applies a visible text watermark directly onto PDF pages while preserving
PDF format, text quality, page dimensions, and document readability.
Embeds document metadata for detection and authenticity verification.
"""
import io
import fitz  # PyMuPDF
from typing import Tuple, Dict, Any, List

from watermarking.metadata import generate_watermark_id, build_watermark_metadata
from watermarking.hashing import calculate_sha256


def _parse_page_selection(pages_str: str, total_pages: int) -> List[int]:
    """
    Parse selected pages string e.g. '1, 3, 5-8' into 0-indexed page list.
    """
    if not pages_str or pages_str.strip().lower() in {"all", "*"}:
        return list(range(total_pages))

    selected = set()
    parts = pages_str.split(",")

    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start_s, end_s = part.split("-", 1)
                start = max(1, int(start_s.strip()))
                end   = min(total_pages, int(end_s.strip()))
                for p in range(start, end + 1):
                    selected.add(p - 1)
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= total_pages:
                    selected.add(p - 1)
            except ValueError:
                pass

    return sorted(list(selected)) if selected else list(range(total_pages))


def apply_pdf_watermark(
    pdf_bytes: bytes,
    watermark_text: str = "CONFIDENTIAL",
    owner: str = "Mohan Kumar J",
    project_id: str = "PROJECT-001",
    position: str = "center",
    opacity_pct: float = 20.0,
    font_size: int = 28,
    pages_option: str = "all",
    selected_pages: str = "",
) -> Tuple[bytes, Dict[str, Any]]:
    """
    Apply a visible watermark directly onto PDF document pages.

    Args:
        pdf_bytes:      Input PDF file bytes.
        watermark_text: Primary watermark text.
        owner:          Owner name.
        project_id:     Project ID.
        position:       'center', 'top-left', 'bottom-right', etc.
        opacity_pct:    Opacity percentage (5% to 100%).
        font_size:      Font size integer.
        pages_option:   'all' or 'selected'.
        selected_pages: Comma-separated page numbers e.g. '1, 2, 5-8'.

    Returns:
        Tuple of (watermarked_pdf_bytes, watermark_metadata_dict)
    """
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    total_pages = len(doc)
    if total_pages == 0:
        raise ValueError("PDF document contains no pages")

    watermark_id = generate_watermark_id("PDF")

    # Determine pages to watermark
    if pages_option.lower() == "selected" and selected_pages.strip():
        target_pages = _parse_page_selection(selected_pages, total_pages)
    else:
        target_pages = list(range(total_pages))

    opacity = max(0.05, min(1.0, opacity_pct / 100.0))

    watermark_line = f"{watermark_text}\n{owner} • {project_id}\n{watermark_id}"

    # Apply watermark to target pages
    for page_idx in target_pages:
        page = doc[page_idx]
        rect = page.rect

        # Center or custom position
        if position.lower() == "center":
            pos_point = fitz.Point(rect.width / 2 - 100, rect.height / 2)
            rotate = 0
        elif position.lower() == "top-left":
            pos_point = fitz.Point(50, 60)
            rotate = 0
        elif position.lower() == "bottom-right":
            pos_point = fitz.Point(rect.width - 200, rect.height - 60)
            rotate = 0
        else:
            pos_point = fitz.Point(rect.width / 2 - 100, rect.height / 2)
            rotate = 0

        # Insert watermark text layer
        page.insert_text(
            pos_point,
            watermark_line,
            fontsize=font_size,
            color=(0.2, 0.4, 0.8),  # Professional cyan-blue tint
            fill_opacity=opacity,
            rotate=rotate,
        )

    # Set document metadata
    meta = build_watermark_metadata(
        watermark_id=watermark_id,
        owner=owner,
        project_id=project_id,
        content_type="PDF",
        extra={
            "watermark_text": watermark_text,
            "total_pages": total_pages,
            "protected_pages": len(target_pages),
        },
    )

    doc_meta = doc.metadata or {}
    doc_meta["keywords"] = f"WMID:{watermark_id}; OWNER:{owner}; PROJ:{project_id}"
    doc_meta["subject"]  = f"SecureCrypt Watermarked Document ({watermark_id})"
    doc.set_metadata(doc_meta)

    out_bytes = doc.tobytes(garbage=3, deflate=True)
    doc.close()

    # Calculate SHA-256 hash
    sha256_hash = calculate_sha256(out_bytes)
    meta["sha256"] = sha256_hash

    return out_bytes, meta


import re

def detect_pdf_watermark(pdf_bytes: bytes) -> Tuple[bool, Dict[str, Any]]:
    """
    Inspect a PDF document to detect embedded watermark metadata.

    Returns:
        Tuple of (found_boolean, metadata_dict)
    """
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        doc_meta = doc.metadata or {}
        total_pages = len(doc)

        watermark_id = None
        owner = None
        project_id = None

        # Check metadata fields (keywords, subject)
        keywords = doc_meta.get("keywords") or ""
        subject  = doc_meta.get("subject") or ""
        meta_str = f"{keywords} {subject}"

        wmid_match = re.search(r"WM-PDF-[0-9]{4}-[A-Za-z0-9]+", meta_str)
        if wmid_match:
            watermark_id = wmid_match.group(0)

        if "OWNER:" in keywords:
            for part in keywords.split(";"):
                part = part.strip()
                if part.startswith("OWNER:"):
                    owner = part.replace("OWNER:", "").strip()
                elif part.startswith("PROJ:"):
                    project_id = part.replace("PROJ:", "").strip()

        # Scan text layer of pages if metadata search incomplete
        if not watermark_id:
            for page_idx in range(min(5, total_pages)):
                text = doc[page_idx].get_text("text")
                w_match = re.search(r"WM-PDF-[0-9]{4}-[A-Za-z0-9]+", text)
                if w_match:
                    watermark_id = w_match.group(0)
                    # Try to extract owner and project ID lines
                    lines = [l.strip() for l in text.splitlines() if l.strip()]
                    for l in lines:
                        if "•" in l:
                            parts = l.split("•")
                            owner = parts[0].strip()
                            project_id = parts[1].strip()
                    break

        doc.close()

        if watermark_id:
            return True, {
                "watermark_id": watermark_id,
                "owner":        owner or "Unknown Owner",
                "project_id":   project_id or "UNKNOWN",
                "content_type": "PDF",
                "total_pages":  total_pages,
            }
    except Exception:
        pass

    return False, {}
