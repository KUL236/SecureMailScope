"""
X.509 parsing tests using certificates generated locally at test time
(never fetched from the internet -- see tests/certgen.py / section 38).
"""
from datetime import datetime, timedelta, timezone

from app.parsing.tls_x509 import parse_der_certificate, evaluate_hostname
from tests.certgen import make_self_signed_cert, make_ca_signed_cert


def test_valid_certificate_parses_fields():
    der, _ = make_self_signed_cert("mail.example.com", days_valid=365)
    info = parse_der_certificate(der, 0)
    assert info.public_key_type == "RSA"
    assert info.public_key_size == 2048
    assert "mail.example.com" in info.san
    assert info.status == "SELF_SIGNED"  # subject == issuer


def test_expired_certificate_detected():
    der, _ = make_self_signed_cert("expired.example.com", days_valid=-10, not_before_days_ago=400)
    info = parse_der_certificate(der, 0)
    assert info.status == "EXPIRED"


def test_not_yet_valid_certificate_detected():
    der, _ = make_self_signed_cert("future.example.com", not_before_days_ago=-10, days_valid=100)
    info = parse_der_certificate(der, 0)
    assert info.status == "NOT_YET_VALID"


def test_ca_signed_certificate_is_not_self_signed():
    leaf_der, ca_der = make_ca_signed_cert("mail.example.com")
    info = parse_der_certificate(leaf_der, 0)
    assert info.status == "VALID"
    assert info.subject != info.issuer


def test_fingerprint_is_sha256_hex():
    der, _ = make_self_signed_cert("mail.example.com")
    info = parse_der_certificate(der, 0)
    assert len(info.sha256_fingerprint) == 64
    int(info.sha256_fingerprint, 16)  # raises if not valid hex


def test_hostname_match():
    der, _ = make_self_signed_cert("mail.example.com")
    info = parse_der_certificate(der, 0)
    assert evaluate_hostname("mail.example.com", info) == "MATCH"


def test_hostname_wildcard_match():
    der, _ = make_self_signed_cert("*.example.com")
    info = parse_der_certificate(der, 0)
    assert evaluate_hostname("mail.example.com", info) == "MATCH"


def test_hostname_mismatch():
    der, _ = make_self_signed_cert("mail.example.com")
    info = parse_der_certificate(der, 0)
    assert evaluate_hostname("evil.example.org", info) == "MISMATCH"


def test_hostname_no_evidence_without_sni():
    der, _ = make_self_signed_cert("mail.example.com")
    info = parse_der_certificate(der, 0)
    assert evaluate_hostname(None, info) == "NO_HOSTNAME_EVIDENCE"
