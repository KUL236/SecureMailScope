"""
Unit tests for the rule engine (section 45), covering the minimum
required fixture scenarios: valid chain, expired, self-signed, broken
chain, weak key, legacy TLS, STARTTLS rejected/not offered, incomplete session.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.rules import evaluate_rules


def make_cert(**overrides):
    base = dict(
        chain_position=0, subject="CN=mail.example.com", issuer="CN=Demo CA",
        serial_number="123", version="v3",
        not_before=datetime.now(timezone.utc) - timedelta(days=30),
        not_after=datetime.now(timezone.utc) + timedelta(days=300),
        public_key_type="RSA", public_key_size=2048,
        signature_algorithm="sha256WithRSAEncryption",
        san=["mail.example.com"], status="VALID",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def make_tls(**overrides):
    base = dict(
        tls_version_negotiated="TLS 1.3", cipher_suite="TLS_AES_256_GCM_SHA384",
        cipher_suite_name="TLS_AES_256_GCM_SHA384", key_exchange="ECDHE/DHE (key_share)",
        forward_secrecy=True,
        handshake_complete=True, status="OBSERVED", alerts=[], certificates=[make_cert()],
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def make_email(**overrides):
    base = dict(protocol="SMTP", starttls_offered=True, state=SimpleNamespace(value="TLS_ESTABLISHED"))
    base.update(overrides)
    return SimpleNamespace(**base)


def make_session(is_complete=True, note=None):
    return SimpleNamespace(is_complete=is_complete, completeness_note=note)


def rule_ids(findings):
    return {f.rule_id for f in findings}


def test_valid_chain_no_findings():
    findings = evaluate_rules(email_session=make_email(), tls_info=make_tls(),
                               network_session=make_session(), hostname_status="MATCH")
    assert findings == []


def test_expired_certificate():
    tls = make_tls(certificates=[make_cert(status="EXPIRED")])
    findings = evaluate_rules(email_session=make_email(), tls_info=tls,
                               network_session=make_session(), hostname_status="MATCH")
    assert "CERT_EXPIRED" in rule_ids(findings)
    assert next(f for f in findings if f.rule_id == "CERT_EXPIRED").severity == "CRITICAL"


def test_self_signed_certificate():
    tls = make_tls(certificates=[make_cert(status="SELF_SIGNED", issuer="CN=mail.example.com")])
    findings = evaluate_rules(email_session=make_email(), tls_info=tls,
                               network_session=make_session(), hostname_status="MATCH")
    assert "CERT_SELF_SIGNED" in rule_ids(findings)


def test_broken_chain():
    tls = make_tls(certificates=[make_cert(status="CHAIN_ISSUE")])
    findings = evaluate_rules(email_session=make_email(), tls_info=tls,
                               network_session=make_session(), hostname_status="MATCH")
    assert "CERT_CHAIN_INCOMPLETE" in rule_ids(findings)


def test_weak_rsa_key():
    tls = make_tls(certificates=[make_cert(public_key_size=1024)])
    findings = evaluate_rules(email_session=make_email(), tls_info=tls,
                               network_session=make_session(), hostname_status="MATCH")
    assert "WEAK_KEY_SIZE" in rule_ids(findings)


def test_legacy_tls_version():
    tls = make_tls(tls_version_negotiated="TLS 1.0")
    findings = evaluate_rules(email_session=make_email(), tls_info=tls,
                               network_session=make_session(), hostname_status="MATCH")
    assert "LEGACY_TLS_VERSION" in rule_ids(findings)


def test_starttls_rejected():
    email = make_email(state=SimpleNamespace(value="STARTTLS_REJECTED"))
    findings = evaluate_rules(email_session=email, tls_info=None,
                               network_session=make_session(), hostname_status="NO_HOSTNAME_EVIDENCE")
    assert "STARTTLS_REJECTED" in rule_ids(findings)


def test_starttls_not_offered():
    email = make_email(starttls_offered=False, state=SimpleNamespace(value="PLAIN_SMTP"))
    findings = evaluate_rules(email_session=email, tls_info=None,
                               network_session=make_session(), hostname_status="NO_HOSTNAME_EVIDENCE")
    assert "STARTTLS_NOT_OBSERVED" in rule_ids(findings)


def test_hostname_mismatch():
    findings = evaluate_rules(email_session=make_email(), tls_info=make_tls(),
                               network_session=make_session(), hostname_status="MISMATCH")
    assert "CERT_HOSTNAME_MISMATCH" in rule_ids(findings)


def test_incomplete_tcp_session_flagged():
    findings = evaluate_rules(email_session=make_email(), tls_info=make_tls(),
                               network_session=make_session(is_complete=False, note="INCOMPLETE_CAPTURE: missing FIN/RST"),
                               hostname_status="MATCH")
    assert "SESSION_ANOMALY" in rule_ids(findings)


def test_incomplete_tls_handshake():
    tls = make_tls(certificates=[make_cert()], handshake_complete=False, status="INCOMPLETE")
    findings = evaluate_rules(email_session=make_email(), tls_info=tls,
                               network_session=make_session(), hostname_status="MATCH")
    assert "TLS_HANDSHAKE_INCOMPLETE" in rule_ids(findings)


def test_chain_signature_invalid_flagged_critical():
    tls = make_tls(certificates=[make_cert(
        status="CHAIN_SIGNATURE_INVALID", chain_validation_status="CHAIN_SIGNATURE_INVALID",
        chain_validation_detail={"links_checked": []},
    )])
    findings = evaluate_rules(email_session=make_email(), tls_info=tls,
                               network_session=make_session(), hostname_status="MATCH")
    assert "CERT_CHAIN_SIGNATURE_INVALID" in rule_ids(findings)
    assert next(f for f in findings if f.rule_id == "CERT_CHAIN_SIGNATURE_INVALID").severity == "CRITICAL"


def test_self_signed_root_not_in_trust_store_flagged():
    tls = make_tls(certificates=[make_cert(chain_validation_status="CHAIN_SELF_SIGNED_UNTRUSTED_ROOT")])
    findings = evaluate_rules(email_session=make_email(), tls_info=tls,
                               network_session=make_session(), hostname_status="MATCH")
    assert "CERT_UNTRUSTED_ROOT" in rule_ids(findings)


def test_revoked_certificate_flagged_critical():
    tls = make_tls(certificates=[make_cert(revocation_status="REVOKED_OCSP", revocation_checked_via="OCSP")])
    findings = evaluate_rules(email_session=make_email(), tls_info=tls,
                               network_session=make_session(), hostname_status="MATCH")
    assert "CERT_REVOKED" in rule_ids(findings)
    assert next(f for f in findings if f.rule_id == "CERT_REVOKED").severity == "CRITICAL"


def test_not_determined_revocation_status_does_not_fire_rule():
    """Default (live checks off) must never be mistaken for a clean bill of health."""
    tls = make_tls(certificates=[make_cert(revocation_status="NOT_DETERMINED_FROM_PCAP")])
    findings = evaluate_rules(email_session=make_email(), tls_info=tls,
                               network_session=make_session(), hostname_status="MATCH")
    assert "CERT_REVOKED" not in rule_ids(findings)
