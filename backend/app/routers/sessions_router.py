from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.auth import get_current_user
from app.pagination import normalize_pagination, total_pages

router = APIRouter(prefix="/api", tags=["sessions"])


def _session_summary(s: models.NetworkSession):
    return {
        "id": s.id, "src_ip": s.src_ip, "src_port": s.src_port,
        "dst_ip": s.dst_ip, "dst_port": s.dst_port,
        "protocol": s.protocol_guess, "protocol_confidence": s.protocol_confidence,
        "is_complete": s.is_complete, "completeness_note": s.completeness_note,
        "start_time": s.start_time, "end_time": s.end_time,
        "starttls_state": s.email_session.starttls_state if s.email_session else "NOT_OBSERVED",
        "tls_status": s.tls_handshake.status if s.tls_handshake else "NOT_OBSERVED",
    }


@router.get("/sessions")
def list_sessions(
    investigation_id: str,
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Paginated so a large PCAP (thousands of reconstructed sessions) doesn't
    have to be sent -- and rendered -- in one response. Ordered by start_time
    (nulls last) then id, so the ordering is stable across pages even while
    sessions with no timestamp exist."""
    page, page_size, offset = normalize_pagination(page, page_size)
    base_q = db.query(models.NetworkSession).filter_by(investigation_id=investigation_id)
    total = base_q.count()
    rows = (
        base_q.order_by(models.NetworkSession.start_time.is_(None), models.NetworkSession.start_time, models.NetworkSession.id)
        .offset(offset)
        .limit(page_size)
        .all()
    )
    return {
        "items": [_session_summary(s) for s in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages(total, page_size),
    }


@router.get("/sessions/{session_id}")
def get_session(session_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    s = db.query(models.NetworkSession).get(session_id)
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    base = _session_summary(s)
    base["email"] = None
    if s.email_session:
        base["email"] = {
            "server_greeting": s.email_session.server_greeting,
            "ehlo_helo_command": s.email_session.ehlo_helo_command,
            "capabilities": s.email_session.capabilities,
            "starttls_offered": s.email_session.starttls_offered,
            "starttls_requested": s.email_session.starttls_requested,
            "starttls_accepted": s.email_session.starttls_accepted,
            "timeline": s.email_session.starttls_timeline,
        }
    return base


@router.get("/sessions/{session_id}/tls")
def get_session_tls(session_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    s = db.query(models.NetworkSession).get(session_id)
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    if not s.tls_handshake:
        return {"status": "NOT_OBSERVED"}
    t = s.tls_handshake
    return {
        "tls_version_offered": t.tls_version_offered, "tls_version_negotiated": t.tls_version_negotiated,
        "cipher_suite": t.cipher_suite, "cipher_suite_name": t.cipher_suite_name,
        "key_exchange": t.key_exchange, "authentication": t.authentication,
        "forward_secrecy": t.forward_secrecy,
        "sni": t.sni, "alpn": t.alpn,
        "handshake_complete": t.handshake_complete, "alerts": t.alerts, "status": t.status,
        "certificate_count": len(t.certificates),
    }


@router.get("/sessions/{session_id}/certificate")
def get_session_certificate(session_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    s = db.query(models.NetworkSession).get(session_id)
    if not s or not s.tls_handshake:
        return {"status": "NOT_OBSERVED", "certificates": []}
    certs = []
    for c in s.tls_handshake.certificates:
        certs.append({
            "chain_position": c.chain_position, "subject": c.subject, "issuer": c.issuer,
            "serial_number": c.serial_number, "not_before": c.not_before, "not_after": c.not_after,
            "public_key_type": c.public_key_type, "public_key_size": c.public_key_size,
            "signature_algorithm": c.signature_algorithm, "san": c.san,
            "sha256_fingerprint": c.sha256_fingerprint, "status": c.status,
            "revocation_status": c.revocation_status,
            # -- cryptographic chain verification (app/parsing/chain_validation.py) --
            "chain_signature_verified": c.chain_signature_verified,
            "issuer_public_key_source": c.issuer_public_key_source,
            "chain_validation_status": c.chain_validation_status,
            "chain_validation_detail": c.chain_validation_detail,
            # -- revocation (app/parsing/revocation.py), opt-in --
            "revocation_checked_via": c.revocation_checked_via,
            "revocation_detail": c.revocation_detail,
        })
    return {"status": "OBSERVED" if certs else "NOT_OBSERVED", "certificates": certs}


@router.get("/risk/{session_id}")
def get_risk(session_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    risk = (db.query(models.RiskScore)
            .filter_by(network_session_id=session_id)
            .order_by(models.RiskScore.created_at.desc()).first())
    if not risk:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No risk score computed yet")
    return {
        "rule_score": risk.rule_score, "ml_probability": risk.ml_probability,
        "anomaly_score": risk.anomaly_score, "evidence_quality": risk.evidence_quality,
        "final_score": risk.final_score, "severity": risk.severity,
        "confidence": risk.confidence, "policy_version": risk.policy_version,
    }


@router.get("/ai/{session_id}")
def get_ai_explanation(session_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    run = (db.query(models.ModelRun)
           .filter_by(network_session_id=session_id)
           .order_by(models.ModelRun.created_at.desc()).first())
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No model run found")
    return {
        "model_name": run.model_name, "model_version": run.model_version,
        "probability": run.probability, "anomaly_score": run.anomaly_score,
        "top_contributors": run.top_contributors,
        "note": "ANOMALOUS does not mean MALICIOUS -- it flags an unusual cryptographic/session pattern for analyst review.",
    }
