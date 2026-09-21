"""
Image Watermarking Implementation using Pillow & EXIF/PNGInfo Metadata.

Renders a visible watermark text overlay on images with configurable position,
font size, opacity, owner name, project ID, and dynamic Watermark ID.
Embeds structured metadata into image files for verification detection.
"""
import io
import json
from typing import Tuple, Dict, Any
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin, ExifTags

from watermarking.metadata import generate_watermark_id, build_watermark_metadata
from watermarking.hashing import calculate_sha256


def _get_font(font_size: int) -> ImageFont.ImageFont:
    """Load a truetype font or fallback to default font."""
    font = None
    font_names = ["arial.ttf", "dejavusans.ttf", "liberation-sans.ttf", "tahoma.ttf", "helvetica.ttf"]
    for name in font_names:
        try:
            font = ImageFont.truetype(name, font_size)
            break
        except Exception:
            pass
    if font is None:
        try:
            font = ImageFont.load_default()
        except Exception:
            pass
    return font


def _calculate_text_position(
    img_w: int, img_h: int, text_w: int, text_h: int, position: str, padding: int = 20
) -> Tuple[int, int]:
    """Calculate (x, y) coordinates based on requested position tag."""
    pos = position.lower().replace("_", "-")

    if pos == "top-left":
        x, y = padding, padding
    elif pos == "top-center":
        x, y = (img_w - text_w) // 2, padding
    elif pos == "top-right":
        x, y = img_w - text_w - padding, padding
    elif pos == "center":
        x, y = (img_w - text_w) // 2, (img_h - text_h) // 2
    elif pos == "bottom-left":
        x, y = padding, img_h - text_h - padding
    elif pos == "bottom-center":
        x, y = (img_w - text_w) // 2, img_h - text_h - padding
    elif pos == "bottom-right":
        x, y = img_w - text_w - padding, img_h - text_h - padding
    else:
        # Default to center
        x, y = (img_w - text_w) // 2, (img_h - text_h) // 2

    return max(5, x), max(5, y)


def apply_image_watermark(
    image_bytes: bytes,
    watermark_text: str = "CONFIDENTIAL",
    owner: str = "Mohan Kumar J",
    project_id: str = "PROJECT-001",
    position: str = "center",
    opacity_pct: float = 30.0,
    font_size: int = 28,
) -> Tuple[bytes, Dict[str, Any]]:
    """
    Apply a visible text watermark onto an image using Pillow.

    Args:
        image_bytes:    Raw input image bytes.
        watermark_text: Primary watermark message string.
        owner:          Owner name.
        project_id:     Project/document identifier.
        position:       'top-left', 'top-center', 'top-right', 'center', 'bottom-left', 'bottom-center', 'bottom-right'.
        opacity_pct:    Opacity percentage (10.0 to 100.0).
        font_size:      Font size integer.

    Returns:
        Tuple of (watermarked_image_bytes, watermark_info_dict)
    """
    original_img = Image.open(io.BytesIO(image_bytes))
    fmt = (original_img.format or "PNG").upper()
    if fmt not in {"PNG", "JPEG", "JPG", "BMP", "WEBP"}:
        fmt = "PNG"

    watermark_id = generate_watermark_id("IMG")
    full_watermark_line = f"{watermark_text} • {owner} • {project_id} • {watermark_id}"

    # Convert image to RGBA for alpha blending overlay
    base = original_img.convert("RGBA")
    w, h = base.size

    # Create transparent layer for drawing watermark
    overlay = Image.new("RGBA", (w, h), (255, 255, 255, 0))
    draw    = ImageDraw.Draw(overlay)
    font    = _get_font(font_size)

    # Measure text bounding box
    bbox = draw.textbbox((0, 0), full_watermark_line, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]

    # Calculate position
    x, y = _calculate_text_position(w, h, text_w, text_h, position)

    # Opacity (0 to 255)
    alpha = int((max(5.0, min(100.0, opacity_pct)) / 100.0) * 255)

    # Draw dark shadow for contrast
    draw.text((x + 2, y + 2), full_watermark_line, font=font, fill=(0, 0, 0, alpha))
    # Draw primary text (cyan/white tint)
    draw.text((x, y), full_watermark_line, font=font, fill=(255, 255, 255, alpha))

    # Composite watermark layer onto base image
    watermarked_rgba = Image.alpha_composite(base, overlay)

    # Structured metadata
    meta = build_watermark_metadata(
        watermark_id=watermark_id,
        owner=owner,
        project_id=project_id,
        content_type="Image",
        extra={"watermark_text": watermark_text, "position": position, "format": fmt},
    )

    out_buf = io.BytesIO()

    if fmt == "PNG":
        png_info = PngImagePlugin.PngInfo()
        png_info.add_text("WatermarkMeta", json.dumps(meta))
        watermarked_rgba.save(out_buf, format="PNG", pnginfo=png_info)
    else:
        # Convert back to RGB for JPEG/BMP/WEBP
        out_img = watermarked_rgba.convert("RGB")
        out_img.save(out_buf, format=fmt if fmt != "JPG" else "JPEG")

    out_bytes = out_buf.getvalue()

    # Calculate SHA-256 fingerprint
    sha256_hash = calculate_sha256(out_bytes)
    meta["sha256"] = sha256_hash

    return out_bytes, meta


def detect_image_watermark(image_bytes: bytes) -> Tuple[bool, Dict[str, Any]]:
    """
    Detect and extract watermark metadata embedded in an image.

    Returns:
        Tuple of (found_boolean, metadata_dict)
    """
    try:
        img = Image.open(io.BytesIO(image_bytes))

        # Check PNGInfo chunk
        if hasattr(img, "info") and "WatermarkMeta" in img.info:
            meta = json.loads(img.info["WatermarkMeta"])
            return True, meta

        # Check EXIF data if present
        exif = img.getexif()
        if exif:
            for tag_id, value in exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                if tag_name in {"UserComment", "ImageDescription", "Copyright"}:
                    try:
                        meta = json.loads(value)
                        if "watermark_id" in meta:
                            return True, meta
                    except Exception:
                        pass
    except Exception:
        pass

    return False, {}
