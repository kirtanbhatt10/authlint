# Contributing

Thanks for helping. Bug reports, false positives and new rules are all welcome.

## Development

```bash
python -m pip install -e ".[dev]"
pytest -q
ruff check . && ruff format --check .
```

authlint has no runtime dependencies; please keep it that way.

## Adding a rule

1. Add it to `src/authlint/rules.py` with the next free id in its range
   (`AL1xx` provider, `AL2xx` JWKS, `AL3xx` client), a default severity and the
   spec section it comes from.
2. Implement the check in `provider.py`, `jwks.py` or `client.py`. Every
   finding needs a concrete `fix`.
3. Add tests for the positive case and for at least one look-alike that must
   not trigger.
4. Document it in the README rule table and in `CHANGELOG.md`.

Base rules on a published spec (RFC 9700, an OAuth/OIDC RFC or OpenID
specification) rather than on a single vendor's behaviour.
