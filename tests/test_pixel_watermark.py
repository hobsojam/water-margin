from pathlib import Path

import cv2
import numpy as np
import pytest

from watermargin.pixel_watermark import (
    _PAYLOAD,
    _hamming_distance,
    detect_watermark,
    embed_watermark,
)


def test_embed_then_detect(sample_image: Path, tmp_output: Path) -> None:
    embed_watermark(sample_image, tmp_output)
    assert detect_watermark(tmp_output) is True


def test_unwatermarked_image_not_detected(sample_image: Path) -> None:
    assert detect_watermark(sample_image) is False


def test_watermark_survives_requantization(sample_image: Path, tmp_output: Path) -> None:
    embed_watermark(sample_image, tmp_output)
    img = cv2.imread(str(tmp_output))
    resaved = tmp_output.with_name("resaved.jpg")
    cv2.imwrite(str(resaved), img, [cv2.IMWRITE_JPEG_QUALITY, 80])
    assert detect_watermark(resaved) is True


def test_watermark_does_not_survive_crop(sample_image: Path, tmp_output: Path) -> None:
    """Known limitation: dwtDctSvd is block-aligned and not crop-resistant."""
    embed_watermark(sample_image, tmp_output)
    img = cv2.imread(str(tmp_output))
    h, w = img.shape[:2]
    cropped = img[10 : h - 10, 10 : w - 10]
    cropped_path = tmp_output.with_name("cropped.jpg")
    cv2.imwrite(str(cropped_path), cropped, [cv2.IMWRITE_JPEG_QUALITY, 90])
    assert detect_watermark(cropped_path) is False


def test_hamming_distance() -> None:
    assert _hamming_distance(_PAYLOAD, _PAYLOAD) == 0
    assert _hamming_distance(b"\x00", b"\x01") == 1
    assert _hamming_distance(b"\x00", b"\xff") == 8


def test_image_too_small_raises(tmp_path: Path) -> None:
    small = tmp_path / "small.jpg"
    cv2.imwrite(str(small), np.zeros((10, 10, 3), dtype=np.uint8))
    with pytest.raises(ValueError):
        embed_watermark(small, tmp_path / "out.jpg")
