"""Certificate generation for two distinct, non-interchangeable use cases:

- `generate_dev_cert()`: a throwaway self-signed leaf cert. Always
  untrusted, by design, even by this tool's own `verify`. Meant to prove
  the signing pipeline works end-to-end, nothing more.

- `generate_root_ca()` + `issue_leaf_cert()`: a persistent, private trust
  hierarchy you generate once and configure your own verifier to trust
  (see c2pa_layer.read_trust_status's trust_anchor_pem parameter). This
  makes `verify` report `signing certificate trusted: True` for images
  signed with a leaf issued from that root, but ONLY within your own
  tooling. It is not, and cannot become, publicly trusted the way a
  certificate from a CA on C2PA's trust list is. Treat the root private
  key with real care: whoever holds it can mint certificates your own
  verifier will accept as trusted, indefinitely, until the root is
  rotated and every trust config referencing it is updated.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509.oid import NameOID


@dataclass
class DevCert:
    cert_pem: bytes
    key_pem: bytes


def _name(common_name: str, org: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )


def _leaf_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def generate_dev_cert(common_name: str = "watermargin dev signer") -> DevCert:
    """Generate a throwaway self-signed ES256 cert + key pair, for local testing only."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = _name(common_name, "watermargin (dev, untrusted)")

    now = datetime.datetime.now(datetime.timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(_leaf_key_usage(), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=True,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    return DevCert(cert_pem=_to_pem_cert(cert), key_pem=_to_pem_key(private_key))


def generate_root_ca(common_name: str = "watermargin private trust root") -> DevCert:
    """Generate a self-signed root CA for a private trust hierarchy.

    This is meant to be generated ONCE and persisted, then used to issue
    leaf certs via `issue_leaf_cert`. Protect the returned key_pem like
    any CA root key: it is the single point of failure for everything
    your own verifier will treat as trusted.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = _name(common_name, "watermargin (private trust root)")

    now = datetime.datetime.now(datetime.timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    return DevCert(cert_pem=_to_pem_cert(cert), key_pem=_to_pem_key(private_key))


def issue_leaf_cert(
    root_cert_pem: bytes,
    root_key_pem: bytes,
    common_name: str = "watermargin signer",
) -> DevCert:
    """Issue a new leaf signing cert from a root generated by generate_root_ca.

    The root's private key is only needed for this one operation, day to
    day signing (via `mark --cert/--key`) uses the returned leaf key, not
    the root key. Keep the root key out of routine use.
    """
    root_cert = x509.load_pem_x509_certificate(root_cert_pem)
    root_key: EllipticCurvePrivateKey = serialization.load_pem_private_key(
        root_key_pem, password=None
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    subject = _name(common_name, "watermargin (private trust root)")

    now = datetime.datetime.now(datetime.timezone.utc)
    root_ski = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    leaf_ski = x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(_leaf_key_usage(), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=True,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(leaf_ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    return DevCert(cert_pem=_to_pem_cert(cert), key_pem=_to_pem_key(leaf_key))


def _to_pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _to_pem_key(key: EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
