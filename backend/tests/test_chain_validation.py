"""
Tests for app/parsing/chain_validation.py -- real cryptographic signature
verification against observed certs + a local (test-only, injected)
trust store. Never touches the network or the real certifi bundle.
"""
from app.parsing.tls_x509 import parse_der_certificate
from app.parsing.chain_validation import (
    verify_certificate_chain,
    CHAIN_VALID_TRUSTED_ROOT,
    CHAIN_VALID_SELF_SIGNED_ROOT_TRUSTED,
    CHAIN_SIGNATURE_INVALID,
    CHAIN_SELF_SIGNED_UNTRUSTED_ROOT,
    CHAIN_INCOMPLETE_NO_TRUST_ANCHOR,
    SOURCE_LOCAL_TRUST_STORE,
    SOURCE_OBSERVED_IN_CAPTURE,
)
from tests.certgen import (
    make_root_ca, make_intermediate_ca, make_leaf_cert,
    make_self_signed_cert, tamper_signature, make_fake_trust_store,
)


def _infos_from_ders(*ders):
    return [parse_der_certificate(der, i) for i, der in enumerate(ders)]


def test_leaf_and_root_only_verifies_against_trust_store_when_root_omitted():
    """The common real-world case: server sends only the leaf (root/
    intermediate omitted), but the leaf's issuer is a known root."""
    root_der, root_key, root_cert = make_root_ca()
    leaf_der, _, _ = make_leaf_cert("mail.example.com", root_cert, root_key)

    certs = _infos_from_ders(leaf_der)  # root NOT included in the capture
    store = make_fake_trust_store(root_cert)
    detail = verify_certificate_chain(certs, trust_store=store)

    assert certs[0].chain_validation_status == CHAIN_VALID_TRUSTED_ROOT
    assert certs[0].chain_signature_verified is True
    assert certs[0].issuer_public_key_source == SOURCE_LOCAL_TRUST_STORE
    assert detail["trust_anchor_source"] == SOURCE_LOCAL_TRUST_STORE
    assert certs[0].status == "VALID"


def test_full_three_tier_chain_verifies_end_to_end():
    root_der, root_key, root_cert = make_root_ca()
    inter_der, inter_key, inter_cert = make_intermediate_ca("Test Intermediate CA", root_cert, root_key)
    leaf_der, _, _ = make_leaf_cert("mail.example.com", inter_cert, inter_key)

    certs = _infos_from_ders(leaf_der, inter_der, root_der)
    store = make_fake_trust_store(root_cert)
    verify_certificate_chain(certs, trust_store=store)

    assert certs[0].chain_signature_verified is True  # leaf signed by intermediate
    assert certs[0].issuer_public_key_source == SOURCE_OBSERVED_IN_CAPTURE
    assert certs[1].chain_signature_verified is True  # intermediate self... no, signed by root
    assert certs[0].chain_validation_status == CHAIN_VALID_SELF_SIGNED_ROOT_TRUSTED
    assert certs[0].status == "VALID"


def test_tampered_leaf_signature_is_detected_cryptographically():
    root_der, root_key, root_cert = make_root_ca()
    leaf_der, _, _ = make_leaf_cert("mail.example.com", root_cert, root_key)
    tampered = tamper_signature(leaf_der)

    certs = _infos_from_ders(tampered)
    store = make_fake_trust_store(root_cert)
    verify_certificate_chain(certs, trust_store=store)

    assert certs[0].chain_validation_status == CHAIN_SIGNATURE_INVALID
    assert certs[0].chain_signature_verified is False
    assert certs[0].status == "CHAIN_SIGNATURE_INVALID"


def test_self_signed_leaf_not_in_trust_store_is_untrusted_not_just_self_signed():
    der, _ = make_self_signed_cert("rogue.example.com")
    certs = _infos_from_ders(der)
    store = make_fake_trust_store(make_root_ca()[2])  # unrelated root in the store
    verify_certificate_chain(certs, trust_store=store)

    assert certs[0].chain_validation_status == CHAIN_SELF_SIGNED_UNTRUSTED_ROOT


def test_incomplete_chain_with_unknown_issuer_reports_no_trust_anchor():
    root_der, root_key, root_cert = make_root_ca()
    leaf_der, _, _ = make_leaf_cert("mail.example.com", root_cert, root_key)

    certs = _infos_from_ders(leaf_der)
    unrelated_root = make_root_ca("Completely Unrelated CA")[2]  # different subject entirely
    empty_store = make_fake_trust_store(unrelated_root)
    verify_certificate_chain(certs, trust_store=empty_store)

    assert certs[0].chain_validation_status == CHAIN_INCOMPLETE_NO_TRUST_ANCHOR
    assert certs[0].status == "CHAIN_ISSUE"


def test_real_certifi_trust_store_loads_and_is_usable():
    """Sanity check against the real bundle (local file only, no network)."""
    from app.parsing.chain_validation import load_default_trust_store
    store = load_default_trust_store()
    assert store.count > 50  # Mozilla's bundle has well over 100 roots
    assert store.source_path is not None
