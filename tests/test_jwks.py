import base64
import json
from pathlib import Path

from authlint.jwks import check_jwks

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def modulus(bits):
    value = (1 << (bits - 1)) | 1
    raw = value.to_bytes((bits + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def rsa(kid, bits=2048, **extra):
    return {"kty": "RSA", "kid": kid, "n": modulus(bits), "e": "AQAB", **extra}


def test_weak_example():
    findings = check_jwks(json.loads((EXAMPLES / "weak-jwks.json").read_text()))
    assert [(f.rule, f.severity) for f in findings] == [
        ("AL202", "high"),
        ("AL201", "critical"),
        ("AL201", "critical"),
        ("AL203", "low"),
    ]


def test_good_key_set_is_clean():
    assert check_jwks({"keys": [rsa("a"), rsa("b", 3072), {"kty": "EC", "kid": "c", "crv": "P-256", "x": "x", "y": "y"}]}) == []


def test_private_exponent_detected():
    findings = check_jwks({"keys": [rsa("a", d="secret")]})
    assert [f.rule for f in findings] == ["AL201"]
    assert "private key members d" in findings[0].detail


def test_symmetric_key_detected():
    findings = check_jwks({"keys": [{"kty": "oct", "kid": "h", "k": "c2VjcmV0"}]})
    assert "symmetric secret" in findings[0].detail


def test_short_rsa_key():
    findings = check_jwks({"keys": [rsa("a", 1024)]})
    assert [f.rule for f in findings] == ["AL202"]
    assert "1024-bit" in findings[0].detail


def test_2048_bit_key_is_fine():
    assert check_jwks({"keys": [rsa("a", 2048)]}) == []


def test_duplicate_kid():
    findings = check_jwks({"keys": [rsa("same"), rsa("same")]})
    assert [f.rule for f in findings] == ["AL203"]
    assert "Duplicate" in findings[0].detail


def test_single_key_without_kid_is_fine():
    key = rsa("x")
    del key["kid"]
    assert check_jwks({"keys": [key]}) == []


def test_empty_and_malformed():
    assert [f.rule for f in check_jwks({"keys": []})] == ["AL204"]
    assert [f.rule for f in check_jwks({"not": "a jwks"})] == ["AL204"]
    assert [f.rule for f in check_jwks([])] == ["AL204"]
