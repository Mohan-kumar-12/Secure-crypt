# DIGITAL WATERMARKING AND CONTENT AUTHENTICITY VERIFICATION SYSTEM (MODULE 2)

**Protect, Identify, and Verify Digital Images, PDF Documents, and Source Code Files.**

---

## 📋 ABSTRACT

The **Digital Watermarking and Content Authenticity Verification System (Module 2)** is a standalone cybersecurity platform designed to protect and verify digital assets. Supporting **Images**, **PDF Documents**, and **Source Code Files**, the system implements visible watermarking, embedded metadata tracking, cryptographic SHA-256 file fingerprinting, and Ed25519 asymmetric digital signatures to guarantee non-repudiation and detect unauthorized modifications.

---

## 🎯 PROBLEM STATEMENT

In digital content distribution, media assets and intellectual property are vulnerable to unauthorized copying, forgery, and subtle tampering:
- **Images**: Distributed without attribution or manipulated without detection.
- **PDF Documents**: Altered or plagiarized without proof of original authorship.
- **Source Code**: Modified or stolen without a mechanism to prove original author identity or detect unauthorized code alterations.

---

## 🚀 KEY FEATURES

- **Image Watermarking**: Visible Pillow text rendering (center, corners) + PNGInfo / EXIF metadata embedding and extraction.
- **PDF Watermarking**: Multi-page PyMuPDF direct layer watermarking + PDF metadata key-value storage.
- **Source Code Protection**: Language-aware comment headers (`#`, `/* ... */`, `<!-- ... -->`) combined with **Ed25519 digital signatures** (`.sig` files).
- **SHA-256 Fingerprinting**: Dynamically computed 256-bit cryptographic digest for every protected file.
- **Central Verification Center**: Unified verification tool for validating watermarks, checking SHA-256 reference hashes, and verifying Ed25519 digital signatures.

---

## 🏗️ SYSTEM ARCHITECTURE

```text
               +----------------------------------+
               |     Flask Web Server (app.py)    |
               +----------------------------------+
                                |
        +-----------------------+-----------------------+
        |                       |                       |
+---------------+       +---------------+       +---------------+
| Image Module  |       |  PDF Module   |       | Code & Sig    |
| (Pillow/EXIF) |       |   (PyMuPDF)   |       | (Ed25519)     |
+---------------+       +---------------+       +---------------+
        |                       |                       |
        v                       v                       v
Watermarked PNG/JPG     Watermarked PDF         Protected Code + .sig
```

---

## 💻 TECHNOLOGY STACK

- **Backend**: Python 3.11+, Flask
- **Image Processing**: Pillow (PIL), NumPy, OpenCV
- **PDF Processing**: PyMuPDF (`fitz`)
- **Cryptography**: Python `cryptography` library (SHA-256, Ed25519 asymmetric key pair)
- **Frontend**: HTML5, Vanilla CSS3 (Cybersecurity Dark Theme), JavaScript (ES6 fetch API)

---

## 🛠️ INSTALLATION & SETUP

### 1. Clone & Navigate
```bash
cd digital-watermarking
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Server
```bash
python app.py
```
Open your browser at `http://127.0.0.1:5001`.

---

## 📡 API DOCUMENTATION

### 1. Image Watermarking
- **Endpoint**: `POST /api/watermark/image`
- **Params**: `image` (file), `watermark_text`, `owner`, `project_id`, `position`, `opacity`, `font_size`.
- **Response**: JSON with `download_token`, `watermark_id`, `sha256`, `preview_b64`.

### 2. PDF Watermarking
- **Endpoint**: `POST /api/watermark/pdf`
- **Params**: `pdf` (file), `watermark_text`, `owner`, `project_id`, `position`, `pages_option`, `selected_pages`.
- **Response**: JSON with `download_token`, `watermark_id`, `sha256`.

### 3. Source Code Protection
- **Endpoint**: `POST /api/watermark/source-code`
- **Params**: `code_file` (file), `owner`, `project_id`.
- **Response**: JSON with `code_download_token`, `sig_download_token`, `watermark_id`, `signature_hex`, `sha256`.

### 4. Verification Endpoints
- **Endpoints**: `POST /api/verify/image`, `POST /api/verify/pdf`, `POST /api/verify/source-code`

---

## 🧪 TESTING

Run the automated pytest test suite:
```bash
python -m pytest tests/ -v
```

---

## 🛡️ SECURITY CONSIDERATIONS

1. **Private Key Protection**: Server-side Ed25519 private key is stored securely in `keys/private_key.pem` and is never exposed in API responses or frontend JavaScript.
2. **Path Traversal Shield**: File validation sanitizes all uploaded filenames and uses random UUID tokens for downloads.
3. **No Code Execution**: Uploaded source code is never executed or evaluated.

---

## 📂 PROJECT STRUCTURE

```
digital-watermarking/
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── watermarking/
│   ├── image_watermark.py
│   ├── pdf_watermark.py
│   ├── source_code.py
│   ├── metadata.py
│   ├── hashing.py
│   ├── signatures.py
│   └── verification.py
├── routes/
│   ├── watermark_routes.py
│   └── verification_routes.py
├── utils/
│   ├── file_validation.py
│   └── file_utils.py
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── image.html
│   ├── pdf.html
│   ├── source_code.html
│   └── verify.html
├── static/
│   ├── css/style.css
│   └── js/app.js
└── tests/
    ├── test_image.py
    ├── test_pdf.py
    ├── test_source_code.py
    ├── test_hashing.py
    └── test_signatures.py
```
