# Changelog

## 0.1.0 - 2026-11-04

First release.

- `authlint provider`: audits OpenID Connect discovery and RFC 8414 metadata from an issuer URL or a file
  (12 rules: issuer mismatch, plain-HTTP endpoints, implicit and password grants, PKCE, `alg: none`,
  `request_uri` SSRF, RFC 9207 mix-up defence, sender-constrained tokens, open registration, missing metadata).
- `authlint jwks`: finds published private or symmetric keys, short RSA keys and ambiguous `kid`s.
- `authlint client`: audits RFC 7591 client registrations (plain-HTTP, wildcard and fragment redirect URIs,
  forbidden grants, unauthenticated client credentials).
- Text, JSON, Markdown and SARIF 2.1.0 output, `--fail-on` and `--ignore` for CI gating.
- Composite GitHub Action.
