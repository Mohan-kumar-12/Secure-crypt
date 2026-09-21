"""
Image quality metrics: MSE, PSNR, SSIM.
Quantifies the visual impact of LSB embedding.
Includes fallback NumPy calculations if scikit-image DLL fails to load.
"""
import numpy as np
from PIL import Image


def _to_rgb_array(img: Image.Image) -> np.ndarray:
    """Convert a PIL image to an RGB uint8 numpy array."""
    return np.array(img.convert("RGB"), dtype=np.uint8)


def compute_metrics(original: Image.Image, stego: Image.Image) -> dict:
    """
    Compute MSE, PSNR, and SSIM between the original cover and stego image.
    """
    orig_arr = _to_rgb_array(original).astype(np.float64)
    stego_arr = _to_rgb_array(stego).astype(np.float64)

    if orig_arr.shape != stego_arr.shape:
        stego = stego.resize((original.width, original.height), Image.LANCZOS)
        stego_arr = _to_rgb_array(stego).astype(np.float64)

    try:
        from skimage.metrics import (
            mean_squared_error,
            peak_signal_noise_ratio,
            structural_similarity,
        )
        orig_u8 = orig_arr.astype(np.uint8)
        stego_u8 = stego_arr.astype(np.uint8)

        mse = float(mean_squared_error(orig_u8, stego_u8))
        psnr = float("inf") if mse == 0 else float(peak_signal_noise_ratio(orig_u8, stego_u8, data_range=255))
        ssim = float(structural_similarity(orig_u8, stego_u8, channel_axis=2, data_range=255))

    except Exception:
        # Fallback pure NumPy calculation
        diff = orig_arr - stego_arr
        mse = float(np.mean(diff ** 2))
        psnr = 999.99 if mse == 0 else float(10 * np.log10((255.0 ** 2) / mse))

        c1 = (0.01 * 255) ** 2
        c2 = (0.03 * 255) ** 2
        mu_x = np.mean(orig_arr)
        mu_y = np.mean(stego_arr)
        sigma_x = np.var(orig_arr)
        sigma_y = np.var(stego_arr)
        cov_matrix = np.cov(orig_arr.flat, stego_arr.flat)
        sigma_xy = float(cov_matrix[0, 1]) if cov_matrix.shape == (2, 2) else 0.0

        ssim = float(((2 * mu_x * mu_y + c1) * (2 * sigma_xy + c2)) / (((mu_x ** 2) + (mu_y ** 2) + c1) * (sigma_x + sigma_y + c2)))

    return {
        "mse":  round(mse, 4),
        "psnr": round(psnr, 2) if not np.isinf(psnr) else 999.99,
        "ssim": round(min(1.0, max(-1.0, ssim)), 6),
    }
