"""Catalogue of every rule authlint can report."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    target: str
    severity: str
    title: str
    reference: str


RULES: dict[str, Rule] = {
    rule.id: rule
    for rule in (
        Rule("AL101", "provider", "high", "Issuer does not match the discovery URL", "OpenID Connect Discovery 1.0, section 4.3"),
        Rule("AL102", "provider", "high", "Endpoint is not served over HTTPS", "RFC 8414, section 2"),
        Rule("AL103", "provider", "medium", "Implicit grant is enabled", "RFC 9700, section 2.1.2"),
        Rule("AL104", "provider", "high", "Resource owner password grant is enabled", "RFC 9700, section 2.4"),
        Rule("AL105", "provider", "medium", "PKCE support is not advertised", "RFC 9700, section 2.1.1"),
        Rule("AL106", "provider", "low", "PKCE plain method is allowed", "RFC 9700, section 2.1.1"),
        Rule(
            "AL107",
            "provider",
            "high",
            "Unsigned (alg none) tokens or requests are accepted",
            "OpenID Connect Discovery 1.0, section 3",
        ),
        Rule(
            "AL108",
            "provider",
            "medium",
            "request_uri can make the server fetch arbitrary URLs",
            "OpenID Connect Core 1.0, section 6.2",
        ),
        Rule("AL109", "provider", "low", "No mix-up defence (iss in authorization responses)", "RFC 9207"),
        Rule("AL110", "provider", "low", "No sender-constrained access tokens (DPoP or mTLS)", "RFC 9700, section 2.2.1"),
        Rule("AL111", "provider", "info", "Dynamic client registration is exposed", "RFC 7591, section 3"),
        Rule("AL112", "provider", "low", "Required metadata is missing", "RFC 8414, section 2"),
        Rule("AL201", "jwks", "critical", "Private or symmetric key material is published", "RFC 7517, section 9.2"),
        Rule("AL202", "jwks", "high", "RSA key is shorter than 2048 bits", "RFC 7518, section 3.3"),
        Rule("AL203", "jwks", "low", "Keys cannot be told apart (missing or duplicate kid)", "RFC 7517, section 4.5"),
        Rule("AL204", "jwks", "medium", "Key set is empty or malformed", "RFC 7517, section 5"),
        Rule("AL301", "client", "high", "Redirect URI uses plain HTTP", "RFC 6749, section 3.1.2.1"),
        Rule("AL302", "client", "high", "Redirect URI contains a wildcard", "RFC 9700, section 4.1.3"),
        Rule("AL303", "client", "medium", "Redirect URI contains a fragment", "RFC 6749, section 3.1.2"),
        Rule("AL304", "client", "high", "Client uses a grant the security BCP forbids", "RFC 9700, sections 2.1.2 and 2.4"),
        Rule("AL305", "client", "high", "Client credentials grant without client authentication", "RFC 6749, section 4.4"),
    )
}
