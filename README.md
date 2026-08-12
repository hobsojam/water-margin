# watermargin

Marks AI-generated images with a C2PA provenance manifest and an
imperceptible pixel watermark, aimed at the EU AI Act's Article 50(2)
machine-readable marking duty for providers of generative AI systems.

Two independent layers are applied to every image:

1. **Signed C2PA metadata**: a manifest declaring the image as
   `trainedAlgorithmicMedia` (the IPTC/C2PA vocabulary for AI-generated
   content), signed and embedded via the official `c2pa-python` bindings.
   Rich and precise, but stripped by re-encoding, screenshots, or most
   social platforms.
2. **Imperceptible pixel watermark**: a fixed payload embedded in the
   frequency domain via `invisible-watermark`'s `dwtDctSvd` method (the
   same library Stability AI uses for Stable Diffusion's default
   watermark). Survives JPEG re-compression; does **not** survive
   cropping (see Limitations).

Neither layer alone satisfies Article 50(2)'s "effective, interoperable,
robust, reliable" bar, that's why both are applied together.

## Install

```
pip install -e ".[dev]"
```

## Usage

```
watermargin mark input.jpg output.jpg --generator "my-model" --version "1.0" --dev-cert
watermargin verify output.jpg
```

`--dev-cert` generates a throwaway self-signed certificate for local
testing. It is **not trusted by any real C2PA verifier**, and is never
reported as trusted even by this tool's own `verify`. For real trust,
either get a certificate from a CA on C2PA's trust list (see below), or
set up a private trust root for your own closed system (also below).

`verify` reads both layers, not just detects them: it prints the actual
manifest contents (generator, version, prompt, creation time) when a
C2PA manifest is present, and the raw decoded pixel-watermark payload
alongside the pass/fail detection (real-world JPEG re-encoding, even
`mark`'s own output write, flips a couple of bits, so the decoded bytes
won't always match the expected payload exactly even when detection
correctly succeeds via the tolerant bit-error check). Pass `--json` for
the full structured result, including the raw manifest JSON, instead of
the human-readable summary.

`verify` reports signing trust explicitly (`signing certificate trusted:
False` for anything signed with `--dev-cert`, or any tampered/unknown
credential). It does not just report "manifest present". A manifest
being present says nothing about whether it should be believed; check
the trust line.

## Getting a real, publicly trusted certificate

Self-signed certificates are never trusted by third-party C2PA
verifiers, by design. To get one that is:

- **SSL.com's free tier**: one Level 1 Claim Signing Certificate, valid
  a year, issued through their portal without needing to already be on
  the C2PA Conforming Products List. The practical starting point for an
  individual or small project.
- **DigiCert / full C2PA conformance**: requires your organization to be
  legally registered and your product to already be on the C2PA
  Conforming Products List. Built for companies shipping a conforming
  product, not individuals.

Either way, you generate your own keypair and submit a CSR; the CA does
not generate private keys for you.

## Private trust roots (for closed systems you fully control)

If you control both the signer and the verifier (an internal pipeline
checking its own output, say), you can skip public trust entirely:

```
watermargin generate-ca ./ca               # once, ever
watermargin issue-cert --ca-cert ./ca/root_cert.pem --ca-key ./ca/root_key.pem ./signing
watermargin mark input.jpg out.jpg --generator "my-model" --version "1.0" \
    --cert ./signing/leaf_cert.pem --key ./signing/leaf_key.pem
watermargin verify out.jpg --trust-anchor ./ca/root_cert.pem
```

This makes `verify --trust-anchor` report `signing certificate trusted:
True` for images signed with a leaf issued from that root. It is
labelled `(private trust root, NOT publicly trusted)` in the output on
purpose: this is not, and cannot become, public trust. It only means
your own tooling was told to believe this specific root. Don't let
"trusted: True" here get conflated with "meets Article 50(2)" in any
compliance writeup; the private root is not interoperable with anyone
else's verifier.

**Protect `root_key.pem` like any CA private key.** Whoever holds it can
mint certificates your own `verify --trust-anchor` will accept as
trusted, indefinitely, until you rotate the root and update every trust
config referencing it. `generate-ca` writes it with `chmod 600`, but
that's a best-effort restriction, not a real ACL, especially on Windows.
Generate it once, keep it out of routine use (day-to-day signing uses
the leaf key from `issue-cert`, not the root key), don't commit it to
version control, and consider storing it somewhere better than a plain
file (a secrets manager, an offline machine) once this leaves local
testing.

## Security notes

- **`verify` parses untrusted input with native image libraries**
  (OpenCV/libjpeg via `cv2`, plus the native `c2pa-rs` reader). Fine for
  local files you already trust. If this is ever wrapped in a service
  that runs `verify` against files supplied by strangers, sandbox that
  process; malformed-image parsing bugs are a real, recurring CVE
  category in these libraries.
- **No decompression-bomb guard.** A small file can decode to a very
  large in-memory image. Not a concern for local CLI use; bound input
  size before exposing this as a service.
- **`--dev-cert` is a footgun, not a vulnerability.** It produces a
  manifest that looks signed at a glance. Nothing stops it from
  accidentally ending up in a real pipeline. `verify`'s trust-status
  output is the safeguard; don't ship images without checking it.
- **A private trust root's key is a real secret**, unlike the throwaway
  dev-cert key. See "Private trust roots" above for handling.
- Dependency versions in `pyproject.toml` are unpinned (`>=` only), no
  lockfile yet. Worth a pinned lockfile + Dependabot (with cooldown)
  before this goes into any real pipeline.

## Limitations (known, not hidden)

- **Cropping defeats the pixel watermark.** `dwtDctSvd` is block-aligned
  and not translation-invariant, shifting the block grid by even a few
  pixels breaks detection. Re-compression and quality changes survive
  fine; geometric edits (crop, rotate) do not. A future version could
  address this with tiled/redundant embedding.
- **JPEG only for v1.** PNG support was not evaluated.
- Scope is deliberately narrow: this marks newly generated images
  (Article 50(2), provider-side). It does not preserve manifests through
  downstream edits, does not handle audio/video, and does not implement
  the deployer-facing visible-disclosure duty (Article 50(4)).

## Tests

```
pytest
```
