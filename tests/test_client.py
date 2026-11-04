import json
from pathlib import Path

from authlint.client import check_client

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_example_clients():
    findings = check_client(json.loads((EXAMPLES / "clients.json").read_text()))
    assert sorted((f.rule, f.location.split(":")[0]) for f in findings) == [
        ("AL301", "legacy-spa"),
        ("AL302", "legacy-spa"),
        ("AL304", "legacy-spa"),
        ("AL305", "batch-job"),
    ]


def test_loopback_ip_redirect_is_allowed():
    assert check_client({"client_id": "c", "redirect_uris": ["http://127.0.0.1:5000/cb", "http://[::1]/cb"]}) == []


def test_localhost_redirect_is_low():
    findings = check_client({"client_id": "c", "redirect_uris": ["http://localhost:5000/cb"]})
    assert [(f.rule, f.severity) for f in findings] == [("AL301", "low")]


def test_fragment_redirect():
    findings = check_client({"client_id": "c", "redirect_uris": ["https://app.example/cb#done"]})
    assert [f.rule for f in findings] == ["AL303"]


def test_password_grant():
    findings = check_client({"client_id": "c", "grant_types": ["password"]})
    assert [(f.rule, f.severity) for f in findings] == [("AL304", "high")]


def test_authenticated_client_credentials_is_fine():
    assert (
        check_client({"client_id": "c", "grant_types": ["client_credentials"], "token_endpoint_auth_method": "private_key_jwt"})
        == []
    )


def test_ignores_non_objects():
    assert check_client("nope") == []
    assert check_client([1, None]) == []
