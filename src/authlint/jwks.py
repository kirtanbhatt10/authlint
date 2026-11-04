"""Checks for a published JSON Web Key Set (the document at jwks_uri)."""

from __future__ import annotations

import base64
import binascii

from .findings import Finding
from .provider import finding

PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")


def _b64url_len_bits(value: str) -> int | None:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
    return int.from_bytes(raw, "big").bit_length()


def check_jwks(jwks: object) -> list[Finding]:
    """Audit a JWKS document."""
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        return [finding("AL204", "The document has no 'keys' array.", "Publish a JSON object with a 'keys' array (RFC 7517).")]
    keys = [k for k in jwks["keys"] if isinstance(k, dict)]
    if not keys:
        return [
            finding(
                "AL204", "The key set contains no keys, so no token can be verified.", "Publish at least one public signing key."
            )
        ]

    findings: list[Finding] = []
    kids: dict[str, int] = {}
    for index, key in enumerate(keys):
        kid = key.get("kid")
        label = f"keys[{index}]" + (f" (kid {kid})" if isinstance(kid, str) else "")
        if isinstance(kid, str):
            kids[kid] = kids.get(kid, 0) + 1

        exposed = [m for m in PRIVATE_MEMBERS if m in key]
        if exposed:
            what = "a symmetric secret (k)" if exposed == ["k"] else "private key members " + ", ".join(exposed)
            findings.append(
                finding(
                    "AL201",
                    f"{label} publishes {what}. Anyone can use it to forge tokens.",
                    "Remove the key, rotate it immediately and publish only public members (kty, n, e or crv, x, y).",
                    label,
                )
            )

        if key.get("kty") == "RSA" and isinstance(key.get("n"), str):
            bits = _b64url_len_bits(key["n"])
            if bits is not None and bits < 2048:
                findings.append(
                    finding(
                        "AL202",
                        f"{label} has a {bits}-bit modulus.",
                        "Use RSA keys of at least 2048 bits, or move to EC (ES256) or Ed25519 keys.",
                        label,
                    )
                )

    if len(keys) > 1 and any(not isinstance(k.get("kid"), str) for k in keys):
        findings.append(
            finding(
                "AL203",
                "Several keys are published and at least one has no kid.",
                "Give every key a unique kid so verifiers pick the right key during rotation.",
            )
        )
    duplicates = sorted(kid for kid, count in kids.items() if count > 1)
    if duplicates:
        findings.append(
            finding(
                "AL203",
                "Duplicate kid values: " + ", ".join(duplicates) + ".",
                "Make every kid unique.",
            )
        )
    return findings
