# SecureCrypt — Cryptographic Image Steganography

**Secure Cryptographic Image Steganography Using AES-256-GCM and Adaptive LSB with Tamper Detection**

---

## Abstract

SecureCrypt provides a secure method for hiding confidential text inside digital images by combining authenticated cryptographic encryption with adaptive image steganography. Secret messages are encrypted using AES-256-GCM with keys derived from user passwords through PBKDF2-HMAC-SHA256. The resulting ciphertext is embedded into suitable image regions using an adaptive LSB technique (ASEE — Adaptive Secure Embedding Engine) designed to reduce visible distortion. During extraction, the system reconstructs the embedding locations, verifies the authenticated payload, and decrypts the message only when the correct password is supplied. Image-quality metrics including MSE, PSNR, and SSIM are used to evaluate the effect of data embedding. The system also detects corrupted or modified payloads through authenticated encryption.

---

## Problem Statement

Digital communication requires methods that protect both the content and existence of sensitive information. Cryptography alone reveals that encrypted data was transmitted, making it a target. Steganography alone hides the existence of a message but leaves it unprotected if discovered. SecureCrypt combines both to provide a dual-layer security model: AES-256-GCM encryption protects message content even if the hidden data is found, while adaptive LSB steganography conceals the very existence of the hidden payload.

---

## Objectives

1. Implement AES-256-GCM authenticated encryption using Python's `cryptography` library.
2. Derive secure AES keys from user passwords via PBKDF2-HMAC-SHA256 with a random salt.
3. Build an Adaptive Secure Embedding Engine (ASEE) that selects embedding pixels based on image texture.
4. Embed encrypted payloads using LSB steganography with deterministic, reproducible embedding sequences.
5. Enable complete extraction and decryption using only the stego image and user password.
6. Detect tampered payloads or wrong passwords through AES-GCM authentication failure.
7. Measure image quality degradation using MSE, PSNR, and SSIM metrics.
8. Provide a professional web interface with real-time feedback.

---

## Features

- ✅ AES-256-GCM authenticated encryption (confidentiality + integrity + authenticity)
- ✅ PBKDF2-HMAC-SHA256 key derivation (600,000 iterations, random salt)
- ✅ Adaptive Secure Embedding Engine (ASEE) — texture-aware pixel selection
- ✅ Deterministic embedding sequence — receiver can reproduce without shared secret
- ✅ Tamper detection via AES-GCM authentication tag failure
- ✅ MSE, PSNR, SSIM image quality metrics
- ✅ Complete round-trip: encrypt → embed → download → upload → extract → decrypt
- ✅ Professional cybersecurity-style web UI
- ✅ Payload SHA-256 fingerprint display (analysis only)
- ✅ Automated test suite (crypto, steganography, integration)

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Flask Web Application                   │
├─────────────────┬────────────────────┬───────────────────────┤
│   Crypto Module  │  Steganography     │   Analysis Module     │
│  ─────────────  │  ──────────────    │  ─────────────────   │
│  key_derivation  │  adaptive (ASEE)   │  image_metrics       │
│  encryption      │  embed             │  image_analysis      │
│  hashing         │  extract           │                      │
│                  │  capacity          │                      │
├─────────────────┴────────────────────┴───────────────────────┤
│                        Utils Module                          │
│              payload.py │ validation.py │ file_utils.py      │
└─────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

| Component        | Technology                          |
|-----------------|-------------------------------------|
| Backend         | Python 3.11+, Flask 3.x             |
| Cryptography    | Python `cryptography` library        |
| Image Processing| Pillow, NumPy, OpenCV               |
| Image Quality   | scikit-image                        |
| Frontend        | HTML5, CSS3, Vanilla JavaScript     |
| Fonts           | Google Fonts (Inter, JetBrains Mono)|

---

## Cryptographic Workflow

### Encryption
```
Secret Text (UTF-8)
        ↓
Password → PBKDF2-HMAC-SHA256 (600,000 iterations, 16-byte random salt)
        ↓
32-byte AES-256 Key
        ↓
AES-256-GCM Encrypt (12-byte random nonce)
        ↓
Ciphertext + 16-byte GCM Authentication Tag
        ↓
Structured Binary Payload (SCST format)
        ↓
LSB Embedding via ASEE
        ↓
Stego PNG Image
```

### Decryption
```
Stego PNG Image
        ↓
ASEE Extraction (deterministic replay)
        ↓
Parse SCST Binary Payload → {salt, nonce, ciphertext+tag}
        ↓
Password → PBKDF2-HMAC-SHA256 + salt
        ↓
32-byte AES-256 Key
        ↓
AES-256-GCM Decrypt + Authenticate
        ↓
If valid → plaintext | If invalid → rejection
```

---

## Steganography Workflow

1. Convert payload to binary bits.
2. Run ASEE on cover image to rank pixels by texture suitability.
3. First `HEADER_BIT_SLOTS` positions embed the fixed binary header.
4. Remaining ASEE positions embed ciphertext bits.
5. Save result as lossless PNG.

---

## Adaptive Embedding Algorithm (ASEE)

The **Adaptive Secure Embedding Engine** is the primary unique contribution of this project.

### Algorithm
1. Convert image to grayscale NumPy array.
2. Apply OpenCV Laplacian filter (`cv2.Laplacian`) to compute per-pixel texture response.
3. Compute suitability score = `abs(laplacian_value)` per pixel.
4. Sort all pixels by descending suitability (most textured first).
5. Expand to per-channel positions: `(row, col, 0)`, `(row, col, 1)`, `(row, col, 2)`.
6. This ordered list defines the embedding sequence.

### Rationale
The human visual system is less sensitive to changes in high-frequency (textured/edge) regions. Embedding in these areas minimizes visible distortion. Additionally, LSB modifications in high-variance regions are statistically harder to detect steganalytically.

### Extraction Reproducibility
- **Fixed header** (38 bytes = 304 bits) is embedded in the first 304 ASEE positions.
- The receiver reads these positions from the stego image to get the header.
- The header contains the PBKDF2 salt, nonce, and ciphertext length.
- The receiver then re-runs ASEE on the stego image (same image → same ranking).
- Ciphertext bits are read from the next positions in the ASEE sequence.
- No shared secret beyond the password is required for extraction.

---

## Payload Format

Binary payload layout (all multi-byte integers big-endian):

```
┌──────────────┬──────────┬───────────────────────────────────┐
│ Field        │ Size     │ Description                       │
├──────────────┼──────────┼───────────────────────────────────┤
│ MAGIC        │  4 bytes │ ASCII "SCST"                      │
│ VERSION      │  1 byte  │ 0x01                              │
│ FLAGS        │  1 byte  │ Reserved, 0x00                    │
│ SALT         │ 16 bytes │ PBKDF2 random salt                │
│ NONCE        │ 12 bytes │ AES-GCM random nonce              │
│ CT_LEN       │  4 bytes │ uint32 — ciphertext length        │
│ CIPHERTEXT   │ variable │ AES-GCM ciphertext + 16-byte tag  │
└──────────────┴──────────┴───────────────────────────────────┘

Total fixed header: 38 bytes
```

---

## Installation

```bash
# Clone or download the project
cd crypto

# Install Python dependencies
pip install -r requirements.txt
```

**Requirements:**
- Python 3.11+
- pip

---

## Running the Application

```bash
python app.py
```

Then open: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## API Documentation

### `POST /api/encrypt`
**Input (multipart/form-data):**
- `image` — Cover image file (PNG, BMP, TIFF)
- `message` — Secret plaintext string
- `password` — Encryption password
- `confirm` — Password confirmation

**Response (JSON):**
```json
{
  "success": true,
  "download_token": "abc123...",
  "metrics": {"mse": 0.82, "psnr": 49.02, "ssim": 0.9981},
  "payload_size": 8500,
  "capacity_bytes": 390000,
  "embedding_pct": 2.17,
  "sha256_fingerprint": "abc...",
  "security_info": { ... }
}
```

### `POST /api/decrypt`
**Input (multipart/form-data):**
- `image` — Stego image file
- `password` — Decryption password

**Response (JSON):**
```json
{
  "success": true,
  "message": "Recovered plaintext",
  "authentication_status": "VERIFIED",
  "integrity_status": "VERIFIED",
  "sha256_fingerprint": "abc..."
}
```

### `GET /download/<token>`
Returns the stego PNG file for the given token. File is deleted after download.

### `POST /api/analyze`
Analyzes an image for capacity and SecureCrypt payload detection without decryption.

---

## Testing

```bash
python -m pytest tests/ -v
```

### Test Coverage
- `tests/test_crypto.py` — Key derivation, encryption, decryption, auth failures
- `tests/test_payload.py` — Binary payload build/parse, magic validation
- `tests/test_steganography.py` — Embed/extract, capacity, RGBA handling
- `tests/test_integrity.py` — Full integration roundtrip, tamper detection

---

## Security Considerations

1. **Password Security**: Passwords are never logged or stored. PBKDF2 with 600,000 iterations makes brute-force computationally expensive.
2. **AES-GCM Authentication**: Any modification to the stego image or ciphertext causes GCM authentication to fail. Wrong passwords cause the same failure.
3. **Salt and Nonce Freshness**: A new random 16-byte salt and 12-byte nonce are generated for every encryption. Nonce reuse with the same key is impossible in normal operation.
4. **SHA-256 Disclaimer**: SHA-256 fingerprints shown in the UI are for display/analysis only. They do not authenticate the payload against an attacker who controls the image — authentication is exclusively provided by the AES-GCM tag.
5. **Lossless Output**: The stego image is always saved as PNG (lossless). JPEG compression would destroy LSB data.
6. **File Security**: Uploaded files are validated by PIL before processing. Random UUIDs are used for all server-side filenames. Temporary files are deleted after use.

---

## Limitations

- JPEG input images are not supported (lossy compression destroys LSB data).
- Very large images may take several seconds due to PBKDF2 iterations and ASEE computation.
- LSB steganography is detectable by dedicated steganalysis tools. ASEE mitigates but does not eliminate this.
- The system does not claim to be "undetectable" — it provides strong cryptographic security.

---

## Future Enhancements

- Multi-bit LSB embedding for higher capacity with quality trade-off control.
- GPU acceleration for ASEE on large images.
- Batch processing mode.
- Alternative encryption algorithms (ChaCha20-Poly1305).
- Image histogram equalization to further hide statistical LSB traces.

---

## Project Structure

```
crypto/
├── app.py                    # Flask application entry point
├── config.py                 # Configuration constants
├── requirements.txt          # Python dependencies
├── README.md                 # This document
│
├── crypto/
│   ├── key_derivation.py     # PBKDF2-HMAC-SHA256
│   ├── encryption.py         # AES-256-GCM encrypt/decrypt
│   └── hashing.py            # SHA-256 fingerprinting
│
├── steganography/
│   ├── adaptive.py           # Adaptive Secure Embedding Engine (ASEE)
│   ├── embed.py              # LSB payload embedding
│   ├── extract.py            # LSB payload extraction
│   └── capacity.py           # Image capacity calculation
│
├── analysis/
│   ├── image_metrics.py      # MSE, PSNR, SSIM
│   └── image_analysis.py     # Image metadata extraction
│
├── routes/
│   ├── encryption_routes.py  # POST /api/encrypt
│   └── decryption_routes.py  # POST /api/decrypt, POST /api/analyze
│
├── utils/
│   ├── payload.py            # Binary payload packer/parser
│   ├── validation.py         # Input validation
│   └── file_utils.py         # Safe file management
│
├── templates/                # Jinja2 HTML templates
├── static/                   # CSS, JS, assets
├── uploads/                  # Temporary uploaded files
├── outputs/                  # Generated stego images
└── tests/                    # Automated test suite
```
