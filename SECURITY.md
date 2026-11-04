# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem in authlint itself.
Email kirtan11bhatt@gmail.com or use GitHub's private vulnerability reporting
on this repository, with steps to reproduce. You should get a reply within a
few days.

## What authlint does on the network

`authlint provider <url>` sends ordinary `GET` requests to the provider's
`/.well-known` metadata and, unless `--no-jwks` is set, to its `jwks_uri`. It
never sends credentials, never calls authorization or token endpoints, and
reads at most 1 MB per response. Only audit providers you operate or are
allowed to test.

## False negatives

A clean report does not prove a deployment is secure. authlint checks
published metadata and registrations; it cannot see how the server behaves at
runtime (for example whether it really enforces PKCE or exact redirect URI
matching).
