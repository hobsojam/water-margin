from pathlib import Path

from watermargin.c2pa_layer import (
    Signer,
    is_ai_generated,
    read_manifest,
    read_trust_status,
    sign_and_embed,
)
from watermargin.metadata import GenerationInfo


def test_sign_and_embed_then_read(
    sample_image: Path, tmp_output: Path, dev_signer: Signer
) -> None:
    info = GenerationInfo(generator_name="test-gen", generator_version="1.0", prompt="a cat")
    sign_and_embed(sample_image, tmp_output, info, dev_signer)

    manifest = read_manifest(tmp_output)
    assert manifest is not None
    assert is_ai_generated(manifest)


def test_unsigned_image_has_no_manifest(sample_image: Path) -> None:
    assert read_manifest(sample_image) is None


def test_dev_cert_signed_image_is_not_trusted(
    sample_image: Path, tmp_output: Path, dev_signer: Signer
) -> None:
    """A --dev-cert signature must never be reported as trusted."""
    info = GenerationInfo(generator_name="test-gen", generator_version="1.0")
    sign_and_embed(sample_image, tmp_output, info, dev_signer)

    status = read_trust_status(tmp_output)
    assert status is not None
    assert status.signing_trusted is False
    assert any("untrusted" in issue for issue in status.issues)


def test_unsigned_image_has_no_trust_status(sample_image: Path) -> None:
    assert read_trust_status(sample_image) is None


def test_manifest_carries_generator_info(
    sample_image: Path, tmp_output: Path, dev_signer: Signer
) -> None:
    info = GenerationInfo(generator_name="my-generator", generator_version="2.3")
    sign_and_embed(sample_image, tmp_output, info, dev_signer)

    manifest = read_manifest(tmp_output)
    assert manifest is not None
    actions_assertion = next(
        a for a in manifest["assertions"] if a["label"] in ("c2pa.actions", "c2pa.actions.v2")
    )
    action = actions_assertion["data"]["actions"][0]
    assert action["softwareAgent"]["name"] == "my-generator"
    assert action["softwareAgent"]["version"] == "2.3"
