from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import typer

from watermargin.c2pa_layer import Signer
from watermargin.certs import generate_dev_cert, generate_root_ca, issue_leaf_cert
from watermargin.metadata import GenerationInfo
from watermargin.pipeline import mark_image, verify_image

app = typer.Typer(
    help="Mark AI-generated images with C2PA provenance metadata and an imperceptible pixel watermark."
)


def _resolve_signer(cert: Optional[Path], key: Optional[Path], dev_cert: bool) -> Signer:
    if dev_cert:
        if cert or key:
            raise typer.BadParameter("--dev-cert cannot be combined with --cert/--key")
        typer.echo(
            "Using a self-signed dev certificate, NOT trusted by third-party verifiers. "
            "For real use, supply --cert/--key with a proper Content Credentials certificate.",
            err=True,
        )
        dc = generate_dev_cert()
        return Signer(cert_pem=dc.cert_pem, key_pem=dc.key_pem)

    if not cert or not key:
        raise typer.BadParameter("Provide both --cert and --key, or pass --dev-cert for local testing")
    return Signer(cert_pem=cert.read_bytes(), key_pem=key.read_bytes())


@app.command()
def mark(
    input_path: Path = typer.Argument(..., exists=True, readable=True),
    output_path: Path = typer.Argument(...),
    generator: str = typer.Option(..., help="Name of the AI system that generated the image"),
    version: str = typer.Option(..., "--version", help="Version of the generator"),
    prompt: Optional[str] = typer.Option(None, help="Generation prompt, if any"),
    cert: Optional[Path] = typer.Option(
        None, exists=True, readable=True, help="Path to a PEM signing certificate"
    ),
    key: Optional[Path] = typer.Option(
        None, exists=True, readable=True, help="Path to a PEM private key"
    ),
    dev_cert: bool = typer.Option(
        False, "--dev-cert", help="Use a throwaway self-signed cert for local testing"
    ),
) -> None:
    """Mark INPUT_PATH with a C2PA manifest + pixel watermark, writing to OUTPUT_PATH."""
    signer = _resolve_signer(cert, key, dev_cert)
    info = GenerationInfo(generator_name=generator, generator_version=version, prompt=prompt)
    mark_image(input_path, output_path, info, signer)
    typer.echo(f"Marked image written to {output_path}")


@app.command()
def verify(
    path: Path = typer.Argument(..., exists=True, readable=True),
    trust_anchor: Optional[Path] = typer.Option(
        None,
        exists=True,
        readable=True,
        help="Root cert from 'generate-ca' to check trust against a private "
        "trust root instead of the public C2PA trust list.",
    ),
    as_json: bool = typer.Option(
        False, "--json", help="Print the full structured result (manifest, decoded "
        "payload, trust status) as JSON instead of the human-readable summary."
    ),
) -> None:
    """Check PATH for both a C2PA manifest and the pixel watermark, independently."""
    trust_anchor_pem = trust_anchor.read_bytes() if trust_anchor else None
    result = verify_image(path, trust_anchor_pem=trust_anchor_pem)
    if as_json:
        typer.echo(json.dumps(result.to_dict(), indent=2))
    else:
        typer.echo(result.summary())


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best-effort; Windows ACLs aren't fully controlled by chmod


@app.command("generate-ca")
def generate_ca(
    out_dir: Path = typer.Argument(..., help="Directory to write root_cert.pem and root_key.pem into"),
    common_name: str = typer.Option("watermargin private trust root", help="CA common name"),
) -> None:
    """Generate a private trust root, ONCE, for your own closed-system verification.

    This does NOT make anything publicly trusted, it only lets your own
    'verify --trust-anchor' calls trust certs issued from this root via
    'issue-cert'. Protect root_key.pem like any CA private key: anyone who
    gets it can mint certs your own tooling will accept as trusted.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    ca = generate_root_ca(common_name=common_name)
    cert_path = out_dir / "root_cert.pem"
    key_path = out_dir / "root_key.pem"
    cert_path.write_bytes(ca.cert_pem)
    _write_private(key_path, ca.key_pem)
    typer.echo(f"Root cert: {cert_path}")
    typer.echo(f"Root key:  {key_path}  <-- keep this private and offline; do not commit it")


@app.command("issue-cert")
def issue_cert(
    ca_cert: Path = typer.Option(..., exists=True, readable=True, help="Path to root_cert.pem"),
    ca_key: Path = typer.Option(..., exists=True, readable=True, help="Path to root_key.pem"),
    out_dir: Path = typer.Argument(..., help="Directory to write leaf_cert.pem and leaf_key.pem into"),
    common_name: str = typer.Option("watermargin signer", help="Leaf cert common name"),
) -> None:
    """Issue a leaf signing cert from a root created by 'generate-ca'.

    Use the resulting leaf_cert.pem/leaf_key.pem with 'mark --cert --key'
    for day-to-day signing, the root key is only needed for this one
    issuance step, not for routine signing.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    leaf = issue_leaf_cert(ca_cert.read_bytes(), ca_key.read_bytes(), common_name=common_name)
    cert_path = out_dir / "leaf_cert.pem"
    key_path = out_dir / "leaf_key.pem"
    cert_path.write_bytes(leaf.cert_pem)
    _write_private(key_path, leaf.key_pem)
    typer.echo(f"Leaf cert: {cert_path}")
    typer.echo(f"Leaf key:  {key_path}")


if __name__ == "__main__":
    app()
