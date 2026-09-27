"""
End-to-end analysis pipeline (section 1). Runs as a background job so
large PCAPs don't block the API (section 44).
"""
import logging
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session

from app import models
from app.config import PARSER_VERSION, FEATURE_VERSION, RULE_VERSION
from app.parsing.pcap_loader import validate_pcap, PcapValidationError
from app.parsing.tcp_reassembly import reassemble_streams
from app.parsing.smtp_starttls import analyze_smtp_starttls
from app.parsing.tls_x509 import parse_tls_records, evaluate_hostname
from app.parsing.revocation import apply_revocation_checks
from app.rules import evaluate_rules
from app import config as app_config
from app.features import build_feature_vector
from app.ml.infer import score_session
from app.risk import fuse_risk

logger = logging.getLogger("securemailscope.pipeline")


def run_analysis(db: Session, investigation_id: str):
    investigation = db.query(models.Investigation).get(investigation_id)
    if not investigation:
        raise ValueError("Investigation not found")

    pcap_row = investigation.pcap
    investigation.status = models.InvestigationStatus.PROCESSING
    investigation.current_stage = "VALIDATING_PCAP"
    db.commit()

    try:
        # --- validation / integrity already done at upload time; re-check here for safety ---
        result = validate_pcap(Path(pcap_row.stored_path), pcap_row.filename)
        pcap_row.sha256 = result.sha256
        pcap_row.parser_version = PARSER_VERSION
        investigation.current_stage = "EXTRACTING_PACKETS"
        db.commit()

        streams = reassemble_streams(pcap_row.stored_path)
        pcap_row.packet_count = sum(len(s.packets) for s in streams)
        investigation.current_stage = "RECONSTRUCTING_STREAMS"
        db.commit()

        investigation.current_stage = "IDENTIFYING_PROTOCOLS"
        db.commit()

        for stream in streams:
            ns = models.NetworkSession(
                investigation_id=investigation.id,
                src_ip=stream.key[0], src_port=stream.key[1],
                dst_ip=stream.key[2], dst_port=stream.key[3],
                start_time=datetime.utcfromtimestamp(stream.start_time) if stream.start_time else None,
                end_time=datetime.utcfromtimestamp(stream.end_time) if stream.end_time else None,
                packet_count=len(stream.packets),
                byte_count=len(stream.client_bytes) + len(stream.server_bytes),
                is_complete=stream.is_complete,
                completeness_note=stream.completeness_note,
                retransmission_count=stream.retransmission_count,
            )
            db.add(ns)
            db.flush()

            email_result = analyze_smtp_starttls(stream.client_events, stream.server_events, stream.key[3])
            ns.protocol_guess = email_result.protocol
            ns.protocol_confidence = email_result.protocol_confidence

            email_session_row = None
            if email_result.protocol:
                email_session_row = models.EmailSession(
                    network_session_id=ns.id, protocol=email_result.protocol,
                    server_greeting=email_result.server_greeting,
                    ehlo_helo_command=email_result.client_command,
                    capabilities=email_result.capabilities,
                    starttls_state=email_result.state.value,
                    starttls_offered=email_result.starttls_offered,
                    starttls_requested=email_result.starttls_requested,
                    starttls_accepted=email_result.starttls_accepted,
                    starttls_timeline=email_result.timeline,
                )
                db.add(email_session_row)

            # --- TLS: analyze bytes after STARTTLS was accepted (or whole stream if TLS-from-start, e.g. port 465) ---
            tls_info = None
            if email_result.starttls_accepted or stream.key[3] == 465:
                tls_info = parse_tls_records(stream.client_bytes, stream.server_bytes)
                if tls_info.certificates:
                    # Chain signature verification already ran inside
                    # parse_tls_records() (local-only, always on). Live
                    # revocation checking is opt-in -- see config.py.
                    apply_revocation_checks(
                        tls_info.certificates,
                        enabled=app_config.ENABLE_LIVE_REVOCATION_CHECKS,
                        timeout=app_config.REVOCATION_CHECK_TIMEOUT_SECONDS,
                    )

            tls_row = None
            if tls_info and tls_info.status != "NOT_OBSERVED":
                tls_row = models.TlsHandshake(
                    network_session_id=ns.id,
                    tls_version_offered=tls_info.tls_version_offered,
                    tls_version_negotiated=tls_info.tls_version_negotiated,
                    cipher_suite=tls_info.cipher_suite,
                    cipher_suite_name=tls_info.cipher_suite_name,
                    key_exchange=tls_info.key_exchange,
                    authentication=tls_info.authentication,
                    forward_secrecy=tls_info.forward_secrecy,
                    sni=tls_info.sni, alpn=tls_info.alpn,
                    supported_groups=tls_info.supported_groups,
                    signature_algorithms=tls_info.signature_algorithms,
                    handshake_complete=tls_info.handshake_complete,
                    alerts=tls_info.alerts, status=tls_info.status,
                )
                db.add(tls_row)
                db.flush()

                for c in tls_info.certificates:
                    db.add(models.Certificate(
                        tls_handshake_id=tls_row.id, chain_position=c.chain_position,
                        subject=c.subject, issuer=c.issuer, serial_number=c.serial_number,
                        version=c.version, not_before=c.not_before, not_after=c.not_after,
                        public_key_type=c.public_key_type, public_key_size=c.public_key_size,
                        signature_algorithm=c.signature_algorithm, san=c.san,
                        basic_constraints=c.basic_constraints, key_usage=c.key_usage,
                        extended_key_usage=c.extended_key_usage,
                        authority_key_identifier=c.authority_key_identifier,
                        subject_key_identifier=c.subject_key_identifier,
                        sha256_fingerprint=c.sha256_fingerprint, length_bytes=c.length_bytes,
                        status=c.status, revocation_status=c.revocation_status, raw_der=c.raw_der,
                        chain_signature_verified=c.chain_signature_verified,
                        issuer_public_key_source=c.issuer_public_key_source,
                        chain_validation_status=c.chain_validation_status,
                        chain_validation_detail=c.chain_validation_detail,
                        revocation_checked_via=c.revocation_checked_via,
                        revocation_detail=c.revocation_detail,
                    ))

            hostname_status = evaluate_hostname(
                tls_info.sni if tls_info else None,
                tls_info.certificates[0] if (tls_info and tls_info.certificates) else None,
            )

            # --- rules ---
            rule_findings = evaluate_rules(
                email_session=email_result if email_result.protocol else None,
                tls_info=tls_info, network_session=ns, hostname_status=hostname_status,
            )
            for rf in rule_findings:
                finding_row = models.Finding(
                    investigation_id=investigation.id, network_session_id=ns.id,
                    rule_id=rf.rule_id, title=rf.title, description=rf.description,
                    severity=rf.severity, observed_value=rf.observed_value,
                    expected_value=rf.expected_value, confidence=rf.confidence,
                    recommendation=rf.recommendation, rule_version=rf.rule_version,
                )
                db.add(finding_row)
                db.flush()
                db.add(models.Evidence(
                    finding_id=finding_row.id, pcap_sha256=pcap_row.sha256,
                    network_session_id=ns.id, protocol=ns.protocol_guess,
                    field_name=rf.rule_id, observed_value=rf.observed_value,
                    parser_version=PARSER_VERSION, rule_version=RULE_VERSION,
                ))

            # --- features + ML + risk ---
            feature_vec = build_feature_vector(network_session=ns, email_session=email_result, tls_info=tls_info)
            db.add(models.FeatureSet(network_session_id=ns.id, feature_version=FEATURE_VERSION, values=feature_vec))

            ml_result = score_session(feature_vec)
            db.add(models.ModelRun(
                network_session_id=ns.id, model_version=ml_result["model_version"],
                model_name="fused" if ml_result["scored"] else "unscored",
                probability=ml_result["probability"], anomaly_score=ml_result["anomaly_score"],
                top_contributors=ml_result["top_contributors"],
            ))

            risk = fuse_risk(findings=rule_findings, ml_result=ml_result, network_session=ns,
                              tls_info=tls_info, email_session=email_result)
            db.add(models.RiskScore(
                network_session_id=ns.id, rule_score=risk.rule_score,
                ml_probability=risk.ml_probability, anomaly_score=risk.anomaly_score,
                evidence_quality=risk.evidence_quality, final_score=risk.final_score,
                severity=risk.severity, confidence=risk.confidence,
                policy_version=risk.policy_version,
            ))

        # By this point STARTTLS analysis, TLS/certificate parsing, rule
        # evaluation and risk fusion have genuinely run for every session --
        # see the loop above. This is the last real checkpoint before the
        # investigation is marked COMPLETE.
        investigation.current_stage = "PREPARING_REPORT"
        db.commit()

        investigation.status = models.InvestigationStatus.COMPLETE
        investigation.current_stage = "DONE"
        db.commit()

    except PcapValidationError as e:
        investigation.status = models.InvestigationStatus.FAILED
        investigation.error_message = str(e)
        db.commit()
        logger.error("PCAP validation failed for %s: %s", investigation_id, e)
    except Exception as e:  # never hide errors (section 43) -- record and re-raise for logs
        investigation.status = models.InvestigationStatus.FAILED
        investigation.error_message = f"{type(e).__name__}: {e}"
        db.commit()
        logger.exception("Analysis pipeline failed for investigation %s", investigation_id)
        raise
