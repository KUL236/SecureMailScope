from types import SimpleNamespace

from app.parsing.cipher_suites import lookup_cipher_suite
from app.rules import evaluate_rules
from tests.test_rules import make_cert, make_email, make_session


def test_ecdhe_suite_is_forward_secret():
    info = lookup_cipher_suite("0xC02F")  # ECDHE_RSA_WITH_AES_128_GCM_SHA256
    assert info.key_exchange == "ECDHE"
    assert info.forward_secrecy is True


def test_static_rsa_suite_is_not_forward_secret():
    info = lookup_cipher_suite("0x009C")  # RSA_WITH_AES_128_GCM_SHA256
    assert info.key_exchange == "RSA"
    assert info.forward_secrecy is False


def test_tls13_suite_is_always_forward_secret():
    info = lookup_cipher_suite("0x1301")  # TLS_AES_128_GCM_SHA256
    assert info.forward_secrecy is True


def test_unknown_cipher_suite_not_assumed_forward_secret():
    info = lookup_cipher_suite("0xFFFF")
    assert info.forward_secrecy is False
    assert "UNKNOWN" in info.name


def test_none_hex_code_returns_none():
    assert lookup_cipher_suite(None) is None


def make_tls_fs(forward_secrecy, key_exchange="RSA", cipher_suite="0x009C"):
    return SimpleNamespace(
        tls_version_negotiated="TLS 1.2", cipher_suite=cipher_suite, cipher_suite_name="TLS_RSA_WITH_AES_128_GCM_SHA256",
        key_exchange=key_exchange, forward_secrecy=forward_secrecy,
        handshake_complete=True, status="OBSERVED", alerts=[], certificates=[make_cert()],
    )


def test_no_forward_secrecy_rule_fires():
    tls = make_tls_fs(forward_secrecy=False)
    findings = evaluate_rules(email_session=make_email(), tls_info=tls,
                               network_session=make_session(), hostname_status="MATCH")
    assert any(f.rule_id == "NO_FORWARD_SECRECY" for f in findings)


def test_forward_secrecy_present_no_finding():
    tls = make_tls_fs(forward_secrecy=True, key_exchange="ECDHE", cipher_suite="0xC02F")
    findings = evaluate_rules(email_session=make_email(), tls_info=tls,
                               network_session=make_session(), hostname_status="MATCH")
    assert not any(f.rule_id == "NO_FORWARD_SECRECY" for f in findings)
