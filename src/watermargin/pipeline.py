"""End-to-end orchestration: pixel watermark + C2PA manifest, applied together.

Pixel watermark goes on first, then the C2PA manifest is built and signed
on top of the watermarked bytes, so both layers are present in the final
file, independently of each other (losing one via editing doesn't remove
the other; see the research brief, §3/§7-§8).
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from watermargin import c2pa_layer, pixel_watermark
from watermargin.c2pa_layer import Signer
from watermargin.metadata import GenerationInfo


@dataclass
class VerificationResult:
    has_c2pa_manifest: bool
    c2pa_declares_ai_generated: bool
    manifest: dict | None
    has_pixel_watermark: bool
    trust_status: c2pa_layer.TrustStatus | None

    def summary(self) -> str:
        lines = [
            f"C2PA manifest present: {self.has_c2pa_manifest}",
        ]
        if self.has_c2pa_manifest:
            lines.append(f"  declares AI-generated (trainedAlgorithmicMedia): {self.c2pa_declares_ai_generated}")
            if self.trust_status is not None:
                scope = (
                    "private trust root, NOT publicly trusted"
                    if self.trust_status.checked_against_private_root
                    else "public C2PA trust list"
                )
                lines.append(
                    f"  signing certificate trusted: {self.trust_status.signing_trusted} ({scope})"
                )
                if not self.trust_status.signing_trusted:
                    for issue in self.trust_status.issues:
                        lines.append(f"    - {issue}")
        lines.append(f"Pixel watermark detected: {self.has_pixel_watermark}")
        return "\n".join(lines)


def mark_image(
    input_path: Path, output_path: Path, info: GenerationInfo, signer: Signer
) -> None:
    """Apply the pixel watermark, then the signed C2PA manifest, to input_path -> output_path."""
    input_path = Path(input_path)
    output_path = Path(output_path)

    with tempfile.NamedTemporaryFile(suffix=input_path.suffix or ".jpg", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        pixel_watermark.embed_watermark(input_path, tmp_path)
        c2pa_layer.sign_and_embed(tmp_path, output_path, info, signer)
    finally:
        tmp_path.unlink(missing_ok=True)


def verify_image(path: Path, trust_anchor_pem: bytes | None = None) -> VerificationResult:
    """Independently check both marking layers on an image.

    trust_anchor_pem: a root cert from certs.generate_root_ca, to check
    trust against a private root instead of the public C2PA trust list.
    """
    path = Path(path)
    manifest = c2pa_layer.read_manifest(path)
    declares_ai = c2pa_layer.is_ai_generated(manifest) if manifest else False
    trust_status = (
        c2pa_layer.read_trust_status(path, trust_anchor_pem) if manifest else None
    )

    try:
        has_watermark = pixel_watermark.detect_watermark(path)
    except ValueError:
        has_watermark = False

    return VerificationResult(
        has_c2pa_manifest=manifest is not None,
        c2pa_declares_ai_generated=declares_ai,
        manifest=manifest,
        has_pixel_watermark=has_watermark,
        trust_status=trust_status,
    )
