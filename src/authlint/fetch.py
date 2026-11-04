"""Load metadata from a file or fetch it from a live provider."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from . import __version__

MAX_BYTES = 1_000_000
OIDC_SUFFIX = "/.well-known/openid-configuration"
OAUTH_PREFIX = "/.well-known/oauth-authorization-server"


class LoadError(Exception):
    """Raised when a document cannot be read or parsed."""


def is_url(value: str) -> bool:
    return urlsplit(value).scheme in ("http", "https")


def get_json(url: str, timeout: float = 10.0) -> object:
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": f"authlint/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - scheme checked by caller
            body = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise LoadError(f"{url}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LoadError(f"{url}: {getattr(exc, 'reason', exc)}") from exc
    if len(body) > MAX_BYTES:
        raise LoadError(f"{url}: response is larger than {MAX_BYTES} bytes")
    try:
        return json.loads(body)
    except ValueError as exc:
        raise LoadError(f"{url}: not valid JSON") from exc


def load_file(path: str) -> object:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise LoadError(f"{path}: {exc.strerror or exc}") from exc
    try:
        return json.loads(text)
    except ValueError as exc:
        raise LoadError(f"{path}: not valid JSON ({exc})") from exc


def discovery_candidates(target: str) -> list[tuple[str, str]]:
    """Return (metadata URL, expected issuer) pairs to try for an issuer or metadata URL."""
    parts = urlsplit(target)
    path = parts.path.rstrip("/")
    if path.endswith(OIDC_SUFFIX):
        issuer = urlunsplit((parts.scheme, parts.netloc, path[: -len(OIDC_SUFFIX)], "", ""))
        return [(target, issuer)]
    if path.startswith(OAUTH_PREFIX):
        issuer = urlunsplit((parts.scheme, parts.netloc, path[len(OAUTH_PREFIX) :], "", ""))
        return [(target, issuer)]
    issuer = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    return [
        (issuer + OIDC_SUFFIX, issuer),
        (urlunsplit((parts.scheme, parts.netloc, OAUTH_PREFIX + path, "", "")), issuer),
    ]


def load_provider(target: str, timeout: float = 10.0) -> tuple[object, str | None, str]:
    """Return (metadata, expected issuer or None, source) for a file or URL."""
    if not is_url(target):
        return load_file(target), None, target
    errors = []
    for url, issuer in discovery_candidates(target):
        try:
            return get_json(url, timeout), issuer, url
        except LoadError as exc:
            errors.append(str(exc))
    raise LoadError("; ".join(errors))


def load_document(target: str, timeout: float = 10.0) -> object:
    return get_json(target, timeout) if is_url(target) else load_file(target)
