"""
Tests for Source Code Protection & Ed25519 Signatures (test_source_code.py).
"""
import pytest
from watermarking.source_code import protect_source_code, get_comment_syntax, detect_code_watermark
from watermarking.verification import verify_source_code


class TestSourceCodeProtection:
    def test_comment_syntax_selection(self):
        py_syntax   = get_comment_syntax("script.py")
        java_syntax = get_comment_syntax("App.java")
        html_syntax = get_comment_syntax("index.html")

        assert py_syntax[0].startswith("#")
        assert java_syntax[0].startswith("/*")
        assert html_syntax[0].startswith("<!--")

    def test_protect_python_code(self):
        code = b"def hello():\n    print('world')\n"
        prot_bytes, sig_bytes, sig_hex, meta = protect_source_code(
            code,
            filename="hello.py",
            owner="Dev Owner",
            project_id="PROJ-DEV",
        )

        assert b"Digital Content Protection" in prot_bytes
        assert b"WM-CODE-" in prot_bytes
        assert len(sig_bytes) == 64
        assert meta["watermark_id"].startswith("WM-CODE-")

        # Source code syntax remains readable
        text = prot_bytes.decode()
        assert "def hello():" in text

    def test_detect_code_watermark(self):
        code = b"console.log('test');"
        prot_bytes, _, _, meta = protect_source_code(code, filename="app.js", owner="Charlie")

        found, detected_meta = detect_code_watermark(prot_bytes)
        assert found is True
        assert detected_meta["watermark_id"] == meta["watermark_id"]
        assert detected_meta["owner"] == "Charlie"

    def test_verify_source_code_valid_and_tampered(self):
        code = b"x = 42\n"
        prot_bytes, sig_bytes, _, _ = protect_source_code(code, filename="math.py")

        # 1. Valid Signature verification
        report_valid = verify_source_code(prot_bytes, sig_bytes, filename="math.py")
        assert report_valid["signature_valid"] is True
        assert report_valid["integrity_status"] == "VERIFIED"
        assert report_valid["final_status"] == "AUTHENTIC"

        # 2. Tampered code modification fails verification
        tampered_bytes = prot_bytes.replace(b"x = 42", b"x = 99")
        report_tampered = verify_source_code(tampered_bytes, sig_bytes, filename="math.py")
        assert report_tampered["signature_valid"] is False
        assert report_tampered["integrity_status"] == "FAILED"
        assert report_tampered["final_status"] == "VERIFICATION_FAILED"
