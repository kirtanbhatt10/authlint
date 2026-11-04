"""Checks for authorization server / OpenID provider metadata.

The input is the JSON document served at /.well-known/openid-configuration
(OpenID Connect Discovery) or /.well-known/oauth-authorization-server (RFC 8414).
"""

from __future__ import annotations

from urllib.parse import SplitResult, urlsplit

from .findings import Finding
from .rules import RULES

ENDPOINT_KEYS = (
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "pushed_authorization_request_endpoint",
    "device_authorization_endpoint",
    "end_session_endpoint",
)

UNSIGNED_ALG_KEYS = {
    "token_endpoint_auth_signing_alg_values_supported": "high",
    "id_token_signing_alg_values_supported": "medium",
    "request_object_signing_alg_values_supported": "medium",
    "userinfo_signing_alg_values_supported": "low",
}


def finding(rule_id: str, detail: str, fix: str, location: str = "", severity: str | None = None) -> Finding:
    rule = RULES[rule_id]
    return Finding(rule_id, severity or rule.severity, rule.title, detail, fix, location)


def safe_split(url: str) -> SplitResult | None:
    """urlsplit that returns None for URLs Python cannot parse (e.g. an unclosed IPv6 bracket)."""
    try:
        return urlsplit(url)
    except ValueError:
        return None


def _strings(value: object) -> list[str]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def is_openid_provider(meta: dict) -> bool:
    """True when the metadata describes an OpenID provider, not only OAuth."""
    return (
        "openid" in _strings(meta.get("scopes_supported"))
        or "id_token_signing_alg_values_supported" in meta
        or "userinfo_endpoint" in meta
    )


def _is_loopback(host: str | None) -> bool:
    return host in ("localhost", "127.0.0.1", "::1")


def check_provider(meta: dict, expected_issuer: str | None = None) -> list[Finding]:
    """Audit provider metadata. expected_issuer is the URL the document was fetched for."""
    if not isinstance(meta, dict):
        return [finding("AL112", "The metadata is not a JSON object.", "Serve a JSON object as described in RFC 8414.")]

    findings: list[Finding] = []
    oidc = is_openid_provider(meta)
    issuer = meta.get("issuer")

    required = ["issuer", "response_types_supported"]
    if oidc:
        required += ["authorization_endpoint", "jwks_uri", "subject_types_supported", "id_token_signing_alg_values_supported"]
    missing = [key for key in required if key not in meta]
    if missing:
        findings.append(
            finding(
                "AL112",
                "Missing: " + ", ".join(missing) + ".",
                "Publish every required field so clients do not fall back to unsafe defaults.",
            )
        )

    if isinstance(issuer, str):
        issuer_parts = safe_split(issuer)
        if issuer_parts is None or issuer_parts.scheme != "https":
            findings.append(
                finding(
                    "AL102",
                    f"The issuer {issuer} does not use https.",
                    "Use an https issuer identifier with no query or fragment.",
                    "issuer",
                )
            )
        if expected_issuer and "{" in issuer:
            findings.append(
                finding(
                    "AL101",
                    f"The issuer {issuer} is a template (multi-tenant endpoint), so it cannot match {expected_issuer}.",
                    "Clients must substitute the tenant and validate the iss of every token against the expected tenant.",
                    "issuer",
                    "info",
                )
            )
        elif expected_issuer and issuer.rstrip("/") != expected_issuer.rstrip("/"):
            findings.append(
                finding(
                    "AL101",
                    f"The document was fetched for {expected_issuer} but claims issuer {issuer}.",
                    "Clients must reject this metadata. Serve it from the issuer's own /.well-known path.",
                    "issuer",
                )
            )

    for key in ENDPOINT_KEYS:
        value = meta.get(key)
        if not isinstance(value, str):
            continue
        parts = safe_split(value)
        if parts is None or (parts.scheme != "https" and not _is_loopback(parts.hostname)):
            findings.append(
                finding(
                    "AL102",
                    f"{key} is {value}.",
                    "Serve every endpoint over TLS; tokens and codes sent over plain HTTP can be stolen.",
                    key,
                )
            )

    response_types = _strings(meta.get("response_types_supported"))
    grant_types = _strings(meta.get("grant_types_supported"))
    implicit = sorted({rt for rt in response_types if "token" in rt.split()})
    if implicit or "implicit" in grant_types:
        shown = ", ".join(implicit) if implicit else "grant type implicit"
        findings.append(
            finding(
                "AL103",
                f"Supported: {shown}. Access tokens are returned in the URL, where they leak through history, referrers and logs.",
                "Remove response types that contain 'token' and use the authorization code flow with PKCE.",
                "response_types_supported",
            )
        )

    if "password" in grant_types:
        findings.append(
            finding(
                "AL104",
                "grant_types_supported includes password, so clients handle user credentials directly.",
                "Disable the password grant; the security BCP says it MUST NOT be used.",
                "grant_types_supported",
            )
        )

    uses_code = any("code" in rt.split() for rt in response_types) or "authorization_code" in grant_types
    methods = meta.get("code_challenge_methods_supported")
    if uses_code and methods is None:
        findings.append(
            finding(
                "AL105",
                "The code flow is supported but code_challenge_methods_supported is not published.",
                "Support PKCE with S256 and advertise it; clients cannot detect PKCE support otherwise.",
                "code_challenge_methods_supported",
            )
        )
    elif "plain" in _strings(methods):
        findings.append(
            finding(
                "AL106",
                "code_challenge_methods_supported includes plain, which sends the verifier in clear.",
                "Accept only S256.",
                "code_challenge_methods_supported",
            )
        )

    for key, severity in UNSIGNED_ALG_KEYS.items():
        if "none" in _strings(meta.get(key)):
            findings.append(
                finding(
                    "AL107",
                    f"{key} includes none.",
                    "Remove none so every token or request has to be signed.",
                    key,
                    severity,
                )
            )

    if (
        oidc
        and meta.get("request_uri_parameter_supported", True) is not False
        and meta.get("require_request_uri_registration") is not True
    ):
        explicit = "request_uri_parameter_supported" in meta
        if explicit:
            detail = (
                "request_uri_parameter_supported is true and require_request_uri_registration is not true, "
                "so the server may fetch any URL a client sends."
            )
        else:
            detail = (
                "The metadata does not set request_uri_parameter_supported, which defaults to true in OpenID Connect "
                "Discovery. If request_uri is accepted, the server may fetch any URL a client sends."
            )
        findings.append(
            finding(
                "AL108",
                detail,
                "Set request_uri_parameter_supported to false if you do not use it, or require_request_uri_registration to true.",
                "request_uri_parameter_supported",
                None if explicit else "low",
            )
        )

    if meta.get("authorization_response_iss_parameter_supported") is not True and "authorization_endpoint" in meta:
        findings.append(
            finding(
                "AL109",
                "authorization_response_iss_parameter_supported is not true.",
                "Return iss in authorization responses (RFC 9207) so clients using several providers can detect mix-up attacks.",
                "authorization_response_iss_parameter_supported",
            )
        )

    if "dpop_signing_alg_values_supported" not in meta and meta.get("tls_client_certificate_bound_access_tokens") is not True:
        findings.append(
            finding(
                "AL110",
                "Neither DPoP (RFC 9449) nor certificate-bound tokens (RFC 8705) are advertised, so a stolen access token works for anyone.",
                "Offer DPoP or mTLS-bound access tokens, at least for high-value APIs.",
                "dpop_signing_alg_values_supported",
            )
        )

    if isinstance(meta.get("registration_endpoint"), str):
        findings.append(
            finding(
                "AL111",
                f"registration_endpoint is {meta['registration_endpoint']}.",
                "Confirm that registration requires an initial access token, or that open registration is intended.",
                "registration_endpoint",
            )
        )

    return findings
