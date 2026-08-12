from pathlib import Path

from watermargin.c2pa_layer import Signer
from watermargin.metadata import GenerationInfo
from watermargin.pipeline import mark_image, verify_image


def test_mark_image_applies_both_layers(
    sample_image: Path, tmp_output: Path, dev_signer: Signer
) -> None:
    info = GenerationInfo(generator_name="pipeline-test", generator_version="0.1")
    mark_image(sample_image, tmp_output, info, dev_signer)

    result = verify_image(tmp_output)
    assert result.has_c2pa_manifest is True
    assert result.c2pa_declares_ai_generated is True
    assert result.has_pixel_watermark is True
    assert result.trust_status is not None
    assert result.trust_status.signing_trusted is False  # dev cert, never trusted


def test_verify_unmarked_image(sample_image: Path) -> None:
    result = verify_image(sample_image)
    assert result.has_c2pa_manifest is False
    assert result.has_pixel_watermark is False
    assert result.c2pa_declares_ai_generated is False


def test_verify_exposes_generation_info_and_decoded_payload(
    sample_image: Path, tmp_output: Path, dev_signer: Signer
) -> None:
    info = GenerationInfo(
        generator_name="pipeline-test", generator_version="0.1", prompt="a red bicycle"
    )
    mark_image(sample_image, tmp_output, info, dev_signer)

    result = verify_image(tmp_output)
    assert result.pixel_watermark_payload is not None

    as_dict = result.to_dict()
    assert as_dict["generation_info"]["generator_name"] == "pipeline-test"
    assert as_dict["generation_info"]["generator_version"] == "0.1"
    assert as_dict["generation_info"]["prompt"] == "a red bicycle"
    assert as_dict["pixel_watermark_payload"] is not None
    assert "manifest" in as_dict and as_dict["manifest"] is not None


def test_verify_dict_has_null_fields_for_unmarked_image(sample_image: Path) -> None:
    result = verify_image(sample_image)
    as_dict = result.to_dict()
    assert as_dict["manifest"] is None
    assert as_dict["generation_info"] is None
    assert as_dict["trust_status"] is None
