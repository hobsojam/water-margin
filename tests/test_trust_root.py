from pathlib import Path

from watermargin.c2pa_layer import Signer, read_trust_status, sign_and_embed
from watermargin.certs import generate_dev_cert, generate_root_ca, issue_leaf_cert
from watermargin.metadata import GenerationInfo


def test_leaf_from_private_root_is_trusted_against_that_root(
    sample_image: Path, tmp_output: Path
) -> None:
    ca = generate_root_ca()
    leaf = issue_leaf_cert(ca.cert_pem, ca.key_pem)
    signer = Signer(cert_pem=leaf.cert_pem, key_pem=leaf.key_pem)

    info = GenerationInfo(generator_name="ca-test", generator_version="1.0")
    sign_and_embed(sample_image, tmp_output, info, signer)

    status = read_trust_status(tmp_output, trust_anchor_pem=ca.cert_pem)
    assert status is not None
    assert status.signing_trusted is True
    assert status.checked_against_private_root is True
    assert status.issues == []


def test_leaf_from_private_root_is_untrusted_without_the_anchor(
    sample_image: Path, tmp_output: Path
) -> None:
    ca = generate_root_ca()
    leaf = issue_leaf_cert(ca.cert_pem, ca.key_pem)
    signer = Signer(cert_pem=leaf.cert_pem, key_pem=leaf.key_pem)

    info = GenerationInfo(generator_name="ca-test", generator_version="1.0")
    sign_and_embed(sample_image, tmp_output, info, signer)

    status = read_trust_status(tmp_output)  # no trust anchor supplied
    assert status is not None
    assert status.signing_trusted is False
    assert status.checked_against_private_root is False


def test_leaf_from_one_root_is_untrusted_against_a_different_root(
    sample_image: Path, tmp_output: Path
) -> None:
    ca_a = generate_root_ca()
    ca_b = generate_root_ca()
    leaf = issue_leaf_cert(ca_a.cert_pem, ca_a.key_pem)
    signer = Signer(cert_pem=leaf.cert_pem, key_pem=leaf.key_pem)

    info = GenerationInfo(generator_name="ca-test", generator_version="1.0")
    sign_and_embed(sample_image, tmp_output, info, signer)

    status = read_trust_status(tmp_output, trust_anchor_pem=ca_b.cert_pem)
    assert status is not None
    assert status.signing_trusted is False


def test_dev_cert_stays_untrusted_even_with_an_unrelated_trust_anchor(
    sample_image: Path, tmp_output: Path, dev_signer: Signer
) -> None:
    """A throwaway --dev-cert must never become trusted, even accidentally."""
    ca = generate_root_ca()

    info = GenerationInfo(generator_name="dev-test", generator_version="1.0")
    sign_and_embed(sample_image, tmp_output, info, dev_signer)

    status = read_trust_status(tmp_output, trust_anchor_pem=ca.cert_pem)
    assert status is not None
    assert status.signing_trusted is False
