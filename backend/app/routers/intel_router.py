from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.auth import get_current_user
from app.threat_intel import build_indicators, summarize_severity

router = APIRouter(prefix="/api", tags=["threat-intel"])


@router.get("/threat-intel")
def get_threat_intel(investigation_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    inv = db.query(models.Investigation).get(investigation_id)
    if not inv:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")

    sessions = db.query(models.NetworkSession).filter_by(investigation_id=investigation_id).all()
    findings = db.query(models.Finding).filter_by(investigation_id=investigation_id).all()

    session_dicts = [{
        "id": s.id, "dst_ip": s.dst_ip, "dst_port": s.dst_port,
        "protocol_guess": s.protocol_guess, "start_time": s.start_time,
    } for s in sessions]
    finding_dicts = [{
        "id": f.id, "network_session_id": f.network_session_id,
        "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
    } for f in findings]

    certs_by_session = {}
    for s in sessions:
        if s.tls_handshake and s.tls_handshake.certificates:
            certs_by_session[s.id] = [{
                "status": c.status, "subject": c.subject,
                "issuer": c.issuer, "sha256_fingerprint": c.sha256_fingerprint,
            } for c in s.tls_handshake.certificates]

    indicators = build_indicators(session_dicts, finding_dicts, certs_by_session)
    return {
        "investigation_id": investigation_id,
        "indicators": indicators,
        "severity_counts": summarize_severity(indicators),
        "total": len(indicators),
    }
