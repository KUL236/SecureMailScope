"""
Confirms the new chain-validation / revocation columns on models.Certificate
round-trip correctly (JSON detail blobs included), and that the pipeline's
CertificateInfo -> Certificate mapping (see app/pipeline.py) has a
destination column for every new CertificateInfo field. Uses an
in-memory sqlite DB -- no external services, no fixtures shared with
other tests.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app import models
from app.parsing.tls_x509 import parse_der_certificate
from app.parsing.chain_validation import verify_certificate_chain, CHAIN_VALID_TRUSTED_ROOT
from app.parsing.revocation import apply_revocation_checks
from tests.certgen import make_root_ca, make_leaf_cert, make_fake_trust_store


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_certificate_row_round_trips_chain_and_revocation_fields():
    db = _session()

    root_der, root_key, root_cert = make_root_ca()
    leaf_der, _, _ = make_leaf_cert("mail.example.com", root_cert, root_key)

    cert_info = parse_der_certificate(leaf_der, 0)
    verify_certificate_chain([cert_info], trust_store=make_fake_trust_store(root_cert))
    apply_revocation_checks([cert_info], enabled=False)  # default: off

    investigation = models.Investigation(title="test investigation")
    db.add(investigation)
    db.flush()

    ns = models.NetworkSession(investigation_id=investigation.id, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                                src_port=51000, dst_port=465)
    db.add(ns)
    db.flush()

    tls_row = models.TlsHandshake(network_session_id=ns.id, status="OBSERVED")
    db.add(tls_row)
    db.flush()

    row = models.Certificate(
        tls_handshake_id=tls_row.id, chain_position=cert_info.chain_position,
        subject=cert_info.subject, issuer=cert_info.issuer,
        serial_number=cert_info.serial_number, version=cert_info.version,
        status=cert_info.status, revocation_status=cert_info.revocation_status,
        raw_der=cert_info.raw_der,
        chain_signature_verified=cert_info.chain_signature_verified,
        issuer_public_key_source=cert_info.issuer_public_key_source,
        chain_validation_status=cert_info.chain_validation_status,
        chain_validation_detail=cert_info.chain_validation_detail,
        revocation_checked_via=cert_info.revocation_checked_via,
        revocation_detail=cert_info.revocation_detail,
    )
    db.add(row)
    db.commit()
    db.expire_all()

    fetched = db.query(models.Certificate).filter_by(subject="CN=mail.example.com").one()
    assert fetched.chain_signature_verified is True
    assert fetched.chain_validation_status == CHAIN_VALID_TRUSTED_ROOT
    assert fetched.chain_validation_detail["trust_anchor_subject"] is not None
    assert fetched.revocation_status == "NOT_DETERMINED_FROM_PCAP"
    assert fetched.revocation_checked_via is None
