import json
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from authlint.cli import main
from authlint.fetch import discovery_candidates

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def example(name):
    return str(EXAMPLES / name)


def test_weak_provider_fails(capsys):
    assert main(["provider", example("weak-provider.json")]) == 1
    out = capsys.readouterr().out
    assert "AL104" in out and "fix:" in out


def test_strong_provider_passes(capsys):
    assert main(["provider", example("strong-provider.json")]) == 0
    assert "no findings" in capsys.readouterr().out


def test_fail_on_threshold(capsys):
    # the weak client set has high findings, so it passes only when failing on critical
    assert main(["client", example("clients.json"), "--fail-on", "critical"]) == 0
    assert main(["client", example("clients.json")]) == 1


def test_ignore_rules(capsys):
    code = main(["provider", example("weak-provider.json"), "--ignore", "al102,AL104,AL107", "-F", "json"])
    data = json.loads(capsys.readouterr().out)
    found = {f["rule"] for f in data["results"][0]["findings"]}
    assert not found & {"AL102", "AL104", "AL107"}
    assert code == 0  # nothing high is left


def test_unknown_ignore_rule(capsys):
    assert main(["provider", example("weak-provider.json"), "--ignore", "AL999"]) == 2
    assert "unknown rule" in capsys.readouterr().err


def test_missing_file(capsys):
    assert main(["jwks", "does-not-exist.json"]) == 2
    assert "does-not-exist.json" in capsys.readouterr().err


def test_sarif_output(tmp_path, capsys):
    out = tmp_path / "report.sarif"
    assert main(["jwks", example("weak-jwks.json"), "-F", "sarif", "-o", str(out)]) == 1
    sarif = json.loads(out.read_text())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"AL201", "AL202", "AL203"}
    assert {r["level"] for r in run["results"]} == {"error", "note"}


def test_markdown_output(capsys):
    main(["client", example("clients.json"), "-F", "markdown"])
    out = capsys.readouterr().out
    assert out.startswith("## authlint report")
    assert "| high | AL305 |" in out


def test_rules_command(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 21 and "RFC 9700" in out


def test_discovery_candidates():
    assert discovery_candidates("https://id.example/tenant") == [
        ("https://id.example/tenant/.well-known/openid-configuration", "https://id.example/tenant"),
        ("https://id.example/.well-known/oauth-authorization-server/tenant", "https://id.example/tenant"),
    ]
    assert discovery_candidates("https://id.example/.well-known/openid-configuration") == [
        ("https://id.example/.well-known/openid-configuration", "https://id.example")
    ]


@pytest.fixture
def server(tmp_path):
    base = None

    def write(name, data):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))

    handler = partial(SimpleHTTPRequestHandler, directory=str(tmp_path))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    handler.log_message = lambda *a: None
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield base, write
    httpd.shutdown()


def test_live_fetch_and_issuer_check(server, capsys):
    base, write = server
    write(
        ".well-known/openid-configuration",
        {
            "issuer": "https://someone-else.example",
            "authorization_endpoint": base + "/authorize",
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
        },
    )
    assert main(["provider", base, "-F", "json", "--no-jwks"]) == 1
    data = json.loads(capsys.readouterr().out)
    rules = {f["rule"] for f in data["results"][0]["findings"]}
    assert "AL101" in rules
    assert data["results"][0]["source"] == base + "/.well-known/openid-configuration"


def test_live_fallback_to_rfc8414(server, capsys):
    base, write = server
    write(".well-known/oauth-authorization-server", {"issuer": base, "response_types_supported": ["code"]})
    main(["provider", base, "-F", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["results"][0]["source"] == base + "/.well-known/oauth-authorization-server"


def test_live_unreachable(capsys):
    assert main(["provider", "http://127.0.0.1:9/", "--timeout", "2"]) == 2
    assert "authlint:" in capsys.readouterr().err
