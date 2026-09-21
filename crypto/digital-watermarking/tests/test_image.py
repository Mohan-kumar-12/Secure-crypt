"""
Tests for Image Watermarking & Detection (test_image.py).
"""
import io
import pytest
from PIL import Image

from watermarking.image_watermark import apply_image_watermark, detect_image_watermark
from watermarking.verification import verify_image


@pytest.fixture
def sample_png_bytes():
    img = Image.new("RGB", (400, 300), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


class TestImageWatermarking:
    def test_apply_watermark_png(self, sample_png_bytes):
        out_bytes, meta = apply_image_watermark(
            sample_png_bytes,
            watermark_text="CONFIDENTIAL TEST",
            owner="Test Owner",
            project_id="PROJ-999",
            position="center",
            opacity_pct=30.0,
            font_size=24,
        )

        assert out_bytes is not None
        assert len(out_bytes) > 0
        assert meta["watermark_id"].startswith("WM-IMG-")
        assert meta["owner"] == "Test Owner"
        assert meta["project_id"] == "PROJ-999"
        assert "sha256" in meta

        # Output image can be opened by Pillow
        out_img = Image.open(io.BytesIO(out_bytes))
        assert out_img.size == (400, 300)

    def test_detect_image_watermark(self, sample_png_bytes):
        out_bytes, meta = apply_image_watermark(
            sample_png_bytes,
            watermark_text="SECRET",
            owner="Alice",
            project_id="P123",
        )

        found, detected_meta = detect_image_watermark(out_bytes)
        assert found is True
        assert detected_meta["watermark_id"] == meta["watermark_id"]
        assert detected_meta["owner"] == "Alice"

    def test_verify_image_success(self, sample_png_bytes):
        out_bytes, meta = apply_image_watermark(sample_png_bytes)
        report = verify_image(out_bytes, reference_hash=meta["sha256"])

        assert report["watermark_found"] is True
        assert report["integrity_status"] == "VERIFIED"
        assert report["final_status"] == "AUTHENTIC"
