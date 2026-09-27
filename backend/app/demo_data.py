"""
Synthetic demo investigation (section 49). Clearly flagged is_demo=True
everywhere so it can never be confused with a real PCAP analysis.
"""
import hashlib
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app import models
from app.config import PARSER_VERSION, RULE_VERSION, MODEL_VERSION


def load_demo_investigation(db: Session) -> models.Investigation:
    fake_hash = hashlib.sha256(b"DEMO-SYNTHETIC-PCAP-NOT-REAL-TRAFFIC").hexdigest()

    inv = models.Investigation(title="DEMO: Corporate Mail Gateway (Synthetic)", is_demo=True,
                                status=models.InvestigationStatus.COMPLETE)
    db.add(inv)
    db.flush()

    pcap = models.Pcap(
        investigation_id=inv.id, filename="demo_mail_capture.pcapng", stored_path="DEMO",
        size_bytes=482_311, sha256=fake_hash, packet_count=1240,
        parser_version=PARSER_VERSION, analysis_version=PARSER_VERSION,
        capture_start=datetime.utcnow() - timedelta(minutes=4), capture_end=datetime.utcnow(),
    )
    db.add(pcap)

    scenarios = [
        # (label, starttls_state, tls_version, cert_status, severity_findings)
        ("mail1.example-corp.local -> mx.partner.example", "TLS_ESTABLISHED", "TLS 1.3", "VALID", []),
        ("mail2.example-corp.local -> legacy-mx.example.org", "TLS_ESTABLISHED", "TLS 1.0", "SELF_SIGNED",
         [("LEGACY_TLS_VERSION", "HIGH"), ("CERT_SELF_SIGNED", "MEDIUM")]),
        ("mail3.example-corp.local -> expired-cert.example.net", "TLS_ESTABLISHED", "TLS 1.2", "EXPIRED",
         [("CERT_EXPIRED", "CRITICAL")]),
        ("mail4.example-corp.local -> plaintext-mx.example.com", "STARTTLS_REJECTED", None, None,
         [("STARTTLS_REJECTED", "HIGH")]),
    ]

    for i, (label, starttls_state, tls_version, cert_status, findings) in enumerate(scenarios):
        src, dst = label.split(" -> ")
        ns = models.NetworkSession(
            investigation_id=inv.id, src_ip=f"10.0.0.{10+i}", src_port=52000 + i,
            dst_ip=f"203.0.113.{20+i}", dst_port=25,
            start_time=datetime.utcnow() - timedelta(minutes=3, seconds=i * 20),
            end_time=datetime.utcnow() - timedelta(minutes=2, seconds=i * 20),
            packet_count=180 + i * 12, byte_count=52000 + i * 3000, is_complete=True,
            protocol_guess="SMTP", protocol_confidence=0.95,
        )
        db.add(ns)
        db.flush()

        db.add(models.EmailSession(
            network_session_id=ns.id, protocol="SMTP",
            server_greeting=f"220 {dst} ESMTP Postfix (Demo)",
            ehlo_helo_command=f"EHLO {src}",
            capabilities=["STARTTLS", "8BITMIME", "SIZE 52428800"],
            starttls_state=starttls_state, starttls_offered=True,
            starttls_requested=True, starttls_accepted=(starttls_state != "STARTTLS_REJECTED"),
            starttls_timeline=[
                {"event": "SMTP greeting (220)", "packet_no": 1},
                {"event": f"Client: EHLO {src}", "packet_no": 2},
                {"event": "STARTTLS advertised (250-STARTTLS)", "packet_no": 3},
                {"event": "Client: STARTTLS", "packet_no": 4},
                {"event": "Server: 220 Ready to start TLS" if starttls_state != "STARTTLS_REJECTED"
                          else "Server rejected STARTTLS: 454 TLS not available", "packet_no": 5},
            ],
        ))

        tls_row = None
        if tls_version:
            tls_row = models.TlsHandshake(
                network_session_id=ns.id, tls_version_offered="TLS 1.3", tls_version_negotiated=tls_version,
                cipher_suite="TLS_AES_256_GCM_SHA384" if tls_version == "TLS 1.3" else "ECDHE-RSA-AES256-GCM-SHA384",
                sni=dst, handshake_complete=True, status="OBSERVED",
            )
            db.add(tls_row)
            db.flush()
            if cert_status:
                not_after = (datetime.utcnow() - timedelta(days=10)) if cert_status == "EXPIRED" \
                    else (datetime.utcnow() + timedelta(days=200))
                db.add(models.Certificate(
                    tls_handshake_id=tls_row.id, chain_position=0,
                    subject=f"CN={dst}", issuer=f"CN={dst}" if cert_status == "SELF_SIGNED" else "CN=Demo Intermediate CA",
                    serial_number=str(1000 + i), version="v3",
                    not_before=datetime.utcnow() - timedelta(days=165), not_after=not_after,
                    public_key_type="RSA", public_key_size=2048,
                    signature_algorithm="sha256WithRSAEncryption",
                    san=[dst], sha256_fingerprint=hashlib.sha256(f"demo-cert-{i}".encode()).hexdigest(),
                    length_bytes=1200, status=cert_status, revocation_status="NOT_DETERMINED_FROM_PCAP",
                ))

        finding_ids = []
        for rule_id, severity in findings:
            f = models.Finding(
                investigation_id=inv.id, network_session_id=ns.id, rule_id=rule_id,
                title=rule_id.replace("_", " ").title(), severity=severity,
                description=f"Demo finding illustrating {rule_id}.",
                observed_value="(synthetic demo value)", expected_value="(policy baseline)",
                confidence=1.0, recommendation="Review and remediate per organizational policy.",
                rule_version=RULE_VERSION,
            )
            db.add(f)
            db.flush()
            db.add(models.Evidence(
                finding_id=f.id, pcap_sha256=fake_hash, network_session_id=ns.id,
                protocol="SMTP", field_name=rule_id, observed_value="(synthetic demo value)",
                parser_version=PARSER_VERSION, rule_version=RULE_VERSION,
            ))

        rule_score = {"CRITICAL": 90, "HIGH": 65, "MEDIUM": 35}.get(
            findings[0][1] if findings else "LOW", 5)
        db.add(models.RiskScore(
            network_session_id=ns.id, rule_score=rule_score, ml_probability=min(rule_score / 100 + 0.05, 0.98),
            anomaly_score=0.2, evidence_quality=1.0, final_score=rule_score,
            severity={"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM"}.get(
                findings[0][1] if findings else "LOW", "LOW"),
            confidence=0.9, policy_version="1.0.0",
        ))

    db.commit()
    db.refresh(inv)
    return inv
