"""Imperceptible pixel-domain watermark, using frequency-domain embedding
(dwtDctSvd) so the mark survives compression and resizing better than raw
metadata does. This is the layer that's still detectable after a crop or
re-save strips the C2PA manifest (see the research brief, §7-§8).

Uses `invisible-watermark` (ShieldMnt), the same library Stability AI
uses for Stable Diffusion's default output watermark.
"""

from __future__ import annotations

from pathlib import Path

import cv2
from imwatermark import WatermarkDecoder, WatermarkEncoder

_METHOD = "dwtDctSvd"
_PAYLOAD = b"WATERMARGIN-AI"
_PAYLOAD_BITS = len(_PAYLOAD) * 8
_MIN_PIXELS = 256 * 256


def embed_watermark(input_path: Path, output_path: Path) -> None:
    """Embed the fixed AI-generated payload into an image's pixel data."""
    image = cv2.imread(str(input_path))
    if image is None:
        raise ValueError(f"Could not read image: {input_path}")
    if image.shape[0] * image.shape[1] < _MIN_PIXELS:
        raise ValueError(
            "Image too small for pixel watermarking (must be at least 256x256)"
        )

    encoder = WatermarkEncoder(content=_PAYLOAD)
    watermarked = encoder.encode(image, method=_METHOD)
    cv2.imwrite(str(output_path), watermarked)


def _hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        return max(len(a), len(b)) * 8
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def detect_watermark(path: Path, max_bit_errors: int = 16) -> bool:
    """Return True if the watermark payload is detectable in the image.

    Real-world transformations (JPEG re-compression, the C2PA embed step
    itself re-encoding the file) flip a handful of bits without destroying
    the signal, so this allows up to `max_bit_errors` bits (out of the
    payload's 112 bits) to differ rather than requiring an exact match.
    16 bits still sits far below the ~56-bit average distance random,
    unrelated content would show against this payload, so this stays a
    meaningful detector rather than a coin flip. NOTE: dwtDctSvd is
    block-aligned and NOT crop-resistant, a crop shifts the block grid
    and reliably defeats detection even at a generous threshold; see
    README limitations.
    """
    image = cv2.imread(str(path))
    if image is None:
        raise ValueError(f"Could not read image: {path}")
    if image.shape[0] * image.shape[1] < _MIN_PIXELS:
        return False

    decoder = WatermarkDecoder(wm_type="bytes", length=_PAYLOAD_BITS)
    decoded = decoder.decode(image, method=_METHOD)
    return _hamming_distance(decoded, _PAYLOAD) <= max_bit_errors
