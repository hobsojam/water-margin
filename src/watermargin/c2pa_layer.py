"""C2PA manifest construction, signing, and reading.

Wraps the official `c2pa-python` bindings (which wrap the c2pa-rs
reference implementation) rather than reimplementing the spec, so
manifests produced here interoperate with the same verifiers everyone
else's C2PA tooling targets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import c2pa

from watermargin.metadata import GenerationInfo

# IPTC digital source type for content produced by a trained algorithmic
# model, the C2PA-recommended way to declare "this is AI-generated".
DIGITAL_SOURCE_TYPE_AI_GENERATED = (
    "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
)

_CLAIM_GENERATOR_NAME = "watermargin"
_CLAIM_GENERATOR_VERSION = "0.1.0"


@dataclass
class Signer:
    cert_pem: bytes
    key_pem: bytes
    alg: bytes = b"es256"
    ta_url: bytes | None = b"http://timestamp.digicert.com"


def _build_manifest_definition(info: GenerationInfo) -> dict:
    creative_work: dict = {
        "@context": "https://schema.org",
        "@type": "CreativeWork",
        "creator": {
            "@type": "SoftwareApplication",
            "name": info.generator_name,
            "softwareVersion": info.generator_version,
        },
        "dateCreated": info.created_at,
    }
    if info.prompt:
        creative_work["disambiguatingDescription"] = info.prompt

    return {
        "claim_generator_info": [
            {"name": _CLAIM_GENERATOR_NAME, "version": _CLAIM_GENERATOR_VERSION}
        ],
        "format": "image/jpeg",
        "title": info.generator_name,
        "ingredients": [],
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.created",
                            "digitalSourceType": DIGITAL_SOURCE_TYPE_AI_GENERATED,
                            "softwareAgent": {
                                "name": info.generator_name,
                                "version": info.generator_version,
                            },
                        }
                    ]
                },
            },
            {"label": "stds.schema-org.CreativeWork", "data": creative_work},
        ],
    }


def sign_and_embed(input_path: Path, output_path: Path, info: GenerationInfo, signer: Signer) -> None:
    """Build a C2PA manifest declaring AI-generated content, sign it, and embed it in the image."""
    manifest_definition = _build_manifest_definition(info)

    signer_info = c2pa.C2paSignerInfo(
        alg=signer.alg,
        sign_cert=signer.cert_pem,
        private_key=signer.key_pem,
        ta_url=signer.ta_url,
    )

    with (
        c2pa.Context() as context,
        c2pa.Signer.from_info(signer_info) as c2pa_signer,
        c2pa.Builder(manifest_definition, context) as builder,
    ):
        builder.sign_file(str(input_path), str(output_path), c2pa_signer)


# Extended key usages watermargin-issued certs may carry. If you issue
# certs with a different tool/EKU, extend this (or build your own trust
# config) rather than assuming this list is exhaustive.
_TRUST_CONFIG_EKUS = "//id-kp-emailProtection\n1.3.6.1.5.5.7.3.4\n"


def _context_for(trust_anchor_pem: bytes | None) -> c2pa.Context:
    if trust_anchor_pem is None:
        return c2pa.Context()
    settings = c2pa.Settings.from_dict(
        {
            "trust": {
                "trust_anchors": trust_anchor_pem.decode("utf-8"),
                "trust_config": _TRUST_CONFIG_EKUS,
            }
        }
    )
    return c2pa.Context(settings=settings)


def _read_store(path: Path, trust_anchor_pem: bytes | None = None) -> dict | None:
    with _context_for(trust_anchor_pem) as context:
        try:
            with c2pa.Reader(str(path), context=context) as reader:
                return json.loads(reader.json())
        except Exception:
            return None


def read_manifest(path: Path) -> dict | None:
    """Return the active C2PA manifest as a dict, or None if the file has no manifest."""
    store = _read_store(path)
    if not store or not store.get("active_manifest"):
        return None
    return store["manifests"][store["active_manifest"]]


@dataclass
class TrustStatus:
    """Whether the manifest's signing credential is actually trusted.

    `validation_state` from c2pa-rs is a trap: "Valid" only means the
    manifest is structurally well-formed and its hashes/signature check
    out internally. It says nothing about whether the *signing
    certificate* is trusted, that's `signing_trusted` here, derived from
    `validation_status`, which c2pa-rs populates with problems (an empty
    list means no issues were found).

    `checked_against_private_root` distinguishes "trusted by C2PA's real,
    public trust list" (False, the default, no custom trust anchor
    supplied) from "trusted only because a private trust_anchor_pem was
    supplied" (True). The second is NOT public trust, no matter how the
    private root's key is protected. It only means your own tooling was
    told to believe this specific root.
    """

    validation_state: str
    signing_trusted: bool
    issues: list[str]
    checked_against_private_root: bool


def read_trust_status(path: Path, trust_anchor_pem: bytes | None = None) -> TrustStatus | None:
    """Return trust/validation info for a file's active manifest, or None if unsigned.

    By default this checks against c2pa-rs's built-in trust settings
    (i.e. the real, public C2PA trust list). Pass `trust_anchor_pem` (a
    root cert from `certs.generate_root_ca`) to instead check against a
    private trust root, see the module docstring in `certs.py` for what
    that does and does not mean.
    """
    store = _read_store(path, trust_anchor_pem)
    if not store or not store.get("active_manifest"):
        return None

    validation_status = store.get("validation_status", [])
    issues = [f"{e.get('code')}: {e.get('explanation')}" for e in validation_status]
    return TrustStatus(
        validation_state=store.get("validation_state", "Unknown"),
        signing_trusted=len(validation_status) == 0,
        issues=issues,
        checked_against_private_root=trust_anchor_pem is not None,
    )


def is_ai_generated(manifest: dict) -> bool:
    """Check whether a manifest dict declares trainedAlgorithmicMedia content."""
    for assertion in manifest.get("assertions", []):
        if assertion.get("label") not in ("c2pa.actions", "c2pa.actions.v2"):
            continue
        for action in assertion.get("data", {}).get("actions", []):
            if action.get("digitalSourceType") == DIGITAL_SOURCE_TYPE_AI_GENERATED:
                return True
    return False
