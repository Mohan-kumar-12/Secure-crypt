"""
Adaptive Secure Embedding Engine (ASEE) — Analysis Module
==========================================================

PRIMARY INNOVATION of the SecureCrypt system.

PURPOSE
-------
ASEE analyzes the cover image texture to identify regions with high local
variance (edges, textured areas). This analysis is used to:
  1. Compute a visual suitability map showing which pixels are best for hiding data.
  2. Generate a texture score used in the security analysis dashboard.
  3. Report the distribution of embedding locations relative to image structure.

NOTE ON EMBEDDING ORDER
-----------------------
The actual payload embedding uses sequential row-major order (pixel 0, 1, 2…)
which guarantees bit-perfect extraction without any shared state.

ASEE provides the theoretical and visual justification for why LSB steganography
in natural images (which have high local variance) causes minimal visible distortion.
The ASEE analysis can be extended in future versions to adaptively select embedding
positions for even better quality.

ALGORITHM
---------
1. Convert image to grayscale NumPy array.
2. Apply Laplacian edge/texture operator (cv2.Laplacian) to compute
   per-pixel texture response.
3. Suitability score = abs(laplacian_value) per pixel.
4. Generate statistics: mean, max, low/medium/high texture percentages.
5. Determine embedding density category based on payload vs. capacity ratio.

SECURITY NOTE
-------------
LSB modifications in high-variance regions are statistically harder to detect
steganalytically. ASEE quantifies how much of the image is high-texture,
providing a measure of the hiding quality.
"""
import numpy as np
import cv2
from PIL import Image


def compute_suitability_map(img_array: np.ndarray) -> np.ndarray:
    """
    Compute a per-pixel suitability score using the Laplacian operator.

    Args:
        img_array: HxWxC uint8 numpy array (RGB image).

    Returns:
        HxW float32 array of suitability scores (higher = more suitable).
    """
    if img_array.ndim == 3:
        gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY).astype(np.float32)
    else:
        gray = img_array.astype(np.float32)

    lap         = cv2.Laplacian(gray, cv2.CV_32F, ksize=3)
    suitability = np.abs(lap)
    return suitability


def analyze_texture(img: Image.Image) -> dict:
    """
    Analyze the texture distribution of an image for the security dashboard.

    Args:
        img: PIL Image.

    Returns:
        dict with:
            mean_score       (float) — mean Laplacian response
            max_score        (float) — max Laplacian response
            high_texture_pct (float) — % pixels with high suitability (>50)
            med_texture_pct  (float) — % pixels with medium suitability (10–50)
            low_texture_pct  (float) — % pixels with low suitability (<10)
            texture_quality  (str)   — "Excellent" / "Good" / "Fair"
    """
    arr         = np.array(img.convert("RGB"))
    suitability = compute_suitability_map(arr)
    total       = suitability.size

    mean_s = float(np.mean(suitability))
    max_s  = float(np.max(suitability))

    high = float(np.sum(suitability > 50)  / total * 100)
    med  = float(np.sum((suitability >= 10) & (suitability <= 50)) / total * 100)
    low  = float(np.sum(suitability < 10)  / total * 100)

    if high > 40:
        quality = "Excellent"
    elif high > 20:
        quality = "Good"
    else:
        quality = "Fair"

    return {
        "mean_score":       round(mean_s, 2),
        "max_score":        round(max_s, 2),
        "high_texture_pct": round(high, 1),
        "med_texture_pct":  round(med, 1),
        "low_texture_pct":  round(low, 1),
        "texture_quality":  quality,
    }
