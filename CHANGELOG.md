# Changelog

## 0.1.1 - 2026-11-05

Hardening release; no rule changes.

- Malformed input (non-UTF-8 or deeply nested JSON, unparseable URLs, broken HTTP responses) now ends with
  exit code 2 and a one-line error instead of a traceback. Previously some of these crashed with exit code 1,
  which CI would read as "findings reached `--fail-on`".
- Unparseable URLs inside metadata no longer crash the checks: an invalid issuer or endpoint is reported as AL102.
- Redirects from `https` to plain `http`, or to a non-web scheme, are refused when fetching metadata or keys.
- `--timeout` must be greater than 0 and at most 300 seconds.
- `authlint ... | head` no longer prints a broken-pipe traceback, and the exit code still reflects the findings.
- Ctrl-C exits with code 130.
- Files starting with a UTF-8 byte order mark are accepted.
- `authlint client` reads a list of registrations one level deep and ignores nested lists.
- The package ships `py.typed`; Python 3.14 is tested in CI.

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
