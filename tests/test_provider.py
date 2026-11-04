import json
from pathlib import Path

from authlint.provider import check_provider

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def load(name):
    return json.loads((EXAMPLES / name).read_text())


def rules(findings):
    return sorted({f.rule for f in findings})


def base(**extra):
    meta = {
        "issuer": "https://id.example",
        "authorization_endpoint": "https://id.example/authorize",
        "token_endpoint": "https://id.example/token",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True,
        "dpop_signing_alg_values_supported": ["ES256"],
    }
    meta.update(extra)
    return meta


def test_strong_provider_is_clean():
    assert check_provider(load("strong-provider.json"), "https://login.strong.example") == []


def test_weak_provider_triggers_expected_rules():
    found = rules(check_provider(load("weak-provider.json")))
    assert found == ["AL102", "AL103", "AL104", "AL106", "AL107", "AL108", "AL109", "AL110", "AL111"]


def test_minimal_oauth_server_is_clean():
    assert check_provider(base()) == []


def test_issuer_mismatch_is_reported():
    findings = check_provider(base(), "https://evil.example")
    assert [f.rule for f in findings] == ["AL101"]


def test_template_issuer_is_info_only():
    findings = check_provider(base(issuer="https://login.example/{tenantid}/v2.0"), "https://login.example/common/v2.0")
    assert [(f.rule, f.severity) for f in findings] == [("AL101", "info")]


def test_issuer_trailing_slash_is_tolerated():
    assert check_provider(base(issuer="https://id.example/"), "https://id.example") == []


def test_http_issuer_and_endpoint():
    findings = check_provider(base(issuer="http://id.example", token_endpoint="http://id.example/token"))
    assert [f.location for f in findings if f.rule == "AL102"] == ["issuer", "token_endpoint"]


def test_loopback_endpoint_is_allowed():
    assert check_provider(base(token_endpoint="http://127.0.0.1:8080/token")) == []


def test_implicit_via_response_type_only():
    findings = check_provider(base(response_types_supported=["code", "code id_token token"]))
    assert rules(findings) == ["AL103"]


def test_code_id_token_hybrid_is_not_implicit():
    assert check_provider(base(response_types_supported=["code", "code id_token"])) == []


def test_missing_pkce_metadata():
    meta = base()
    del meta["code_challenge_methods_supported"]
    assert rules(check_provider(meta)) == ["AL105"]


def test_pkce_not_required_without_code_flow():
    meta = base(response_types_supported=["none"], grant_types_supported=["client_credentials"])
    del meta["code_challenge_methods_supported"]
    assert check_provider(meta) == []


def test_alg_none_severity_depends_on_field():
    findings = check_provider(
        base(
            token_endpoint_auth_signing_alg_values_supported=["none"],
            userinfo_signing_alg_values_supported=["none"],
        )
    )
    by_location = {f.location: f.severity for f in findings if f.rule == "AL107"}
    assert by_location == {
        "token_endpoint_auth_signing_alg_values_supported": "high",
        "userinfo_signing_alg_values_supported": "low",
    }


def test_request_uri_default_applies_to_openid_providers_only():
    oidc = base(
        scopes_supported=["openid"],
        jwks_uri="https://id.example/jwks",
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["ES256"],
    )
    assert [(f.rule, f.severity) for f in check_provider(oidc)] == [("AL108", "low")]
    explicit = check_provider({**oidc, "request_uri_parameter_supported": True})
    assert [(f.rule, f.severity) for f in explicit] == [("AL108", "medium")]
    assert rules(check_provider({**oidc, "require_request_uri_registration": True})) == []
    assert rules(check_provider({**oidc, "request_uri_parameter_supported": False})) == []


def test_missing_required_openid_fields():
    findings = check_provider({"issuer": "https://id.example", "scopes_supported": ["openid"]})
    missing = [f for f in findings if f.rule == "AL112"]
    assert len(missing) == 1
    assert "jwks_uri" in missing[0].detail and "response_types_supported" in missing[0].detail


def test_non_object_metadata():
    assert rules(check_provider(["not", "an", "object"])) == ["AL112"]
