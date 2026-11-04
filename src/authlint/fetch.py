"""Load metadata from a file or fetch it from a live provider."""

from __future__ import annotations

import http.client
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
    # Decide from the scheme alone so a malformed URL is reported by get_json, not raised here.
    scheme, sep, _ = value.partition(":")
    return bool(sep) and scheme.lower() in ("http", "https")


class _NoDowngradeRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never from https to plain http or to a non-web scheme."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001 - urllib signature
        new_scheme = newurl.partition(":")[0].lower()
        old_scheme = req.full_url.partition(":")[0].lower()
        if new_scheme not in ("http", "https") or (old_scheme == "https" and new_scheme != "https"):
            raise LoadError(f"{req.full_url}: refusing redirect to {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_NoDowngradeRedirects)


def parse_json(data: str | bytes, source: str) -> object:
    try:
        return json.loads(data)
    except RecursionError as exc:
        raise LoadError(f"{source}: JSON is nested too deeply") from exc
    except ValueError as exc:  # includes JSONDecodeError and UnicodeDecodeError
        raise LoadError(f"{source}: not valid JSON ({exc})") from exc


def get_json(url: str, timeout: float = 10.0) -> object:
    try:
        request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": f"authlint/{__version__}"})
        with _OPENER.open(request, timeout=timeout) as response:
            body = response.read(MAX_BYTES + 1)
    except LoadError:
        raise
    except urllib.error.HTTPError as exc:
        raise LoadError(f"{url}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LoadError(f"{url}: {getattr(exc, 'reason', exc)}") from exc
    except (http.client.HTTPException, ValueError, OverflowError) as exc:  # malformed URL or broken response
        raise LoadError(f"{url}: {exc or type(exc).__name__}") from exc
    if len(body) > MAX_BYTES:
        raise LoadError(f"{url}: response is larger than {MAX_BYTES} bytes")
    return parse_json(body, url)


def load_file(path: str) -> object:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise LoadError(f"{path}: {exc.strerror or exc}") from exc
    if len(data) > MAX_BYTES * 10:
        raise LoadError(f"{path}: file is larger than {MAX_BYTES * 10} bytes")
    if data.startswith(b"\xef\xbb\xbf"):  # tolerate a UTF-8 byte order mark written by some editors
        data = data[3:]
    return parse_json(data, path)


def discovery_candidates(target: str) -> list[tuple[str, str]]:
    """Return (metadata URL, expected issuer) pairs to try for an issuer or metadata URL."""
    try:
        parts = urlsplit(target)
    except ValueError as exc:
        raise LoadError(f"{target}: {exc}") from exc
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
