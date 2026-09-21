"""
Tests for PDF Watermarking & Detection (test_wm_pdf.py).
"""
import io
import fitz
import pytest

from watermarking.pdf_watermark import apply_pdf_watermark, detect_pdf_watermark
from watermarking.verification import verify_pdf


@pytest.fixture
def sample_pdf_bytes():
    doc = fitz.open()
    page1 = doc.new_page(width=595, height=842)
    page1.insert_text((50, 100), "Sample PDF Document Page 1")
    page2 = doc.new_page(width=595, height=842)
    page2.insert_text((50, 100), "Sample PDF Document Page 2")
    pdf_data = doc.tobytes()
    doc.close()
    return pdf_data


class TestPDFWatermarking:
    def test_apply_pdf_watermark(self, sample_pdf_bytes):
        out_bytes, meta = apply_pdf_watermark(
            sample_pdf_bytes,
            watermark_text="CONFIDENTIAL PDF",
            owner="PDF Owner",
            project_id="PROJ-PDF",
            position="center",
            pages_option="all",
        )

        assert out_bytes is not None
        assert meta["watermark_id"].startswith("WM-PDF-")
        assert meta["owner"] == "PDF Owner"
        assert meta["total_pages"] == 2

        doc = fitz.open(stream=out_bytes, filetype="pdf")
        assert len(doc) == 2
        doc.close()

    def test_detect_pdf_watermark(self, sample_pdf_bytes):
        out_bytes, meta = apply_pdf_watermark(sample_pdf_bytes, owner="Bob")
        found, detected_meta = detect_pdf_watermark(out_bytes)

        assert found is True
        assert detected_meta["watermark_id"] == meta["watermark_id"]

    def test_verify_pdf_success(self, sample_pdf_bytes):
        out_bytes, meta = apply_pdf_watermark(sample_pdf_bytes)
        report = verify_pdf(out_bytes, reference_hash=meta["sha256"])

        assert report["watermark_found"] is True
        assert report["integrity_status"] == "VERIFIED"
        assert report["final_status"] == "AUTHENTIC"
