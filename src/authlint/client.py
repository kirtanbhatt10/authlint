"""Checks for an OAuth client registration (RFC 7591 client metadata)."""

from __future__ import annotations

from urllib.parse import urlsplit

from .findings import Finding
from .provider import _strings, finding

LOOPBACK_IPS = ("127.0.0.1", "::1")


def check_client(client: object) -> list[Finding]:
    """Audit one client registration, or a list of them."""
    if isinstance(client, list):
        findings: list[Finding] = []
        for item in client:
            findings += check_client(item)
        return findings
    if not isinstance(client, dict):
        return []

    findings = []
    name = client.get("client_id") or client.get("client_name") or "client"

    for uri in _strings(client.get("redirect_uris")):
        location = f"{name}: {uri}"
        parts = urlsplit(uri)
        if parts.scheme == "http":
            if parts.hostname in LOOPBACK_IPS:
                pass  # RFC 8252 allows http on loopback IP literals for native apps
            elif parts.hostname == "localhost":
                findings.append(
                    finding(
                        "AL301",
                        f"{uri} uses localhost, which can resolve to a non-loopback address.",
                        "Use the loopback IP literal (http://127.0.0.1) as RFC 8252 recommends.",
                        location,
                        "low",
                    )
                )
            else:
                findings.append(
                    finding(
                        "AL301",
                        f"{uri} sends authorization codes over plain HTTP.",
                        "Register an https redirect URI.",
                        location,
                    )
                )
        if "*" in uri:
            findings.append(
                finding(
                    "AL302",
                    f"{uri} contains a wildcard, so codes can be redirected to unintended hosts or paths.",
                    "Register every redirect URI exactly; the BCP requires exact string matching.",
                    location,
                )
            )
        if "#" in uri:
            findings.append(
                finding(
                    "AL303",
                    f"{uri} contains a fragment.",
                    "Remove the fragment; redirect URIs MUST NOT include one.",
                    location,
                )
            )

    grants = _strings(client.get("grant_types"))
    responses = _strings(client.get("response_types"))
    if "password" in grants:
        findings.append(
            finding(
                "AL304",
                f"{name} uses the password grant.",
                "Switch to the authorization code flow with PKCE.",
                f"{name}: grant_types",
            )
        )
    if "implicit" in grants or any("token" in rt.split() for rt in responses):
        findings.append(
            finding(
                "AL304",
                f"{name} uses the implicit flow.",
                "Switch to the authorization code flow with PKCE.",
                f"{name}: response_types",
                "medium",
            )
        )
    if "client_credentials" in grants and client.get("token_endpoint_auth_method") == "none":
        findings.append(
            finding(
                "AL305",
                f"{name} can use client_credentials with token_endpoint_auth_method none, so anyone who knows the client_id gets tokens.",
                "Authenticate the client (private_key_jwt or tls_client_auth preferred).",
                f"{name}: token_endpoint_auth_method",
            )
        )
    return findings
