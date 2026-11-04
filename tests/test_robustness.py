"""Malformed input must give exit code 2 and a one-line error, never a traceback.

Exit code 1 means "findings reached --fail-on", so a crash that exits 1 would be
mistaken for a failed audit in CI.
"""

import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from authlint.cli import main
from authlint.client import check_client
from authlint.fetch import LoadError, get_json

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize(
    "content",
    [
        b"\xff\xfe{",  # not UTF-8
        b"[" * 100_000,  # nested too deeply for the JSON parser
        b"",  # empty file
        b"{'single': 'quotes'}",
    ],
)
def test_unreadable_json_file(tmp_path, capsys, content):
    path = tmp_path / "metadata.json"
    path.write_bytes(content)
    for command in ("provider", "jwks", "client"):
        assert main([command, str(path)]) == 2
        err = capsys.readouterr().err
        assert err.startswith("authlint: ") and "Traceback" not in err


def test_utf8_bom_is_accepted(tmp_path, capsys):
    path = tmp_path / "provider.json"
    path.write_bytes(b"\xef\xbb\xbf" + (ROOT / "examples" / "strong-provider.json").read_bytes())
    assert main(["provider", str(path)]) == 0


@pytest.mark.parametrize("url", ["https://[::1", "https://exa mple.invalid/jwks", "https://127.0.0.1:99999/jwks"])
def test_malformed_url(capsys, url):
    assert main(["jwks", url, "--timeout", "1"]) == 2
    assert capsys.readouterr().err.startswith("authlint: ")


@pytest.mark.parametrize("value", ["0", "-1", "abc", "301"])
def test_invalid_timeout(capsys, value):
    with pytest.raises(SystemExit) as exc:
        main(["jwks", "jwks.json", "--timeout", value])
    assert exc.value.code == 2
    assert "--timeout" in capsys.readouterr().err


def test_nested_client_lists_are_ignored():
    deep: list = []
    for _ in range(5000):
        deep = [deep]
    assert check_client(deep) == []
    assert check_client([[{"client_id": "x", "redirect_uris": ["http://evil.example/cb"]}]]) == []


class _Redirect(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        self.send_response(302)
        self.send_header("Location", self.server.location)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def redirect_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Redirect)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


@pytest.mark.parametrize("location", ["file:///etc/passwd", "ftp://example.com/jwks"])
def test_redirect_to_non_web_scheme_is_refused(redirect_server, location):
    redirect_server.location = location
    url = f"http://127.0.0.1:{redirect_server.server_address[1]}/jwks"
    with pytest.raises(LoadError, match="refusing redirect|HTTP 302"):
        get_json(url, timeout=2)


def test_https_to_http_redirect_is_refused():
    from authlint.fetch import _NoDowngradeRedirects

    class Req:
        full_url = "https://login.example/.well-known/openid-configuration"

    with pytest.raises(LoadError, match="refusing redirect"):
        _NoDowngradeRedirects().redirect_request(Req(), None, 302, "Found", {}, "http://login.example/metadata")


def test_broken_pipe_keeps_exit_code():
    # `authlint ... | head -1` must not print a traceback and must still report findings.
    script = (
        "import subprocess, sys\n"
        "p = subprocess.Popen([sys.executable, '-m', 'authlint', 'provider', sys.argv[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
        "p.stdout.close()\n"
        "err = p.stderr.read().decode()\n"
        "sys.exit(0 if p.wait() == 1 and 'Traceback' not in err else 3)\n"
    )
    env = {"PYTHONPATH": str(ROOT / "src")}
    result = subprocess.run([sys.executable, "-c", script, str(ROOT / "examples" / "weak-provider.json")], env=env, timeout=30)
    assert result.returncode == 0


def test_malformed_urls_inside_documents():
    from authlint.provider import check_provider

    meta = {
        "issuer": "https://[broken",
        "response_types_supported": ["code"],
        "token_endpoint": "https://[::1",
        "code_challenge_methods_supported": ["S256"],
    }
    rules = [f.rule for f in check_provider(meta, expected_issuer="https://login.example")]
    assert rules.count("AL102") == 2  # issuer and token_endpoint are not valid https URLs
    found = check_client({"client_id": "c", "redirect_uris": ["https://[bad*"]})
    assert [f.rule for f in found] == ["AL302"]
