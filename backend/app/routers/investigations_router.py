import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.auth import get_current_user
from app.config import UPLOAD_DIR, PARSER_VERSION
from app.parsing.pcap_loader import validate_pcap, PcapValidationError
from app.pipeline import run_analysis

router = APIRouter(prefix="/api", tags=["investigations"])


@router.post("/investigations")
def create_investigation(title: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    inv = models.Investigation(title=title, created_by=user.id)
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return {"id": inv.id, "title": inv.title, "status": inv.status.value}


@router.get("/investigations")
def list_investigations(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = db.query(models.Investigation).order_by(models.Investigation.created_at.desc()).all()
    return [{"id": r.id, "title": r.title, "status": r.status.value, "created_at": r.created_at,
             "is_demo": r.is_demo} for r in rows]


@router.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    inv = db.query(models.Investigation).get(investigation_id)
    if not inv:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    return {
        "id": inv.id, "title": inv.title, "status": inv.status.value,
        "current_stage": inv.current_stage,
        "error_message": inv.error_message, "is_demo": inv.is_demo,
        "pcap": {
            "filename": inv.pcap.filename, "sha256": inv.pcap.sha256,
            "size_bytes": inv.pcap.size_bytes, "packet_count": inv.pcap.packet_count,
        } if inv.pcap else None,
        "finding_count": len(inv.findings),
    }


@router.post("/pcaps/upload")
def upload_pcap(
    background_tasks: BackgroundTasks,
    title: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    inv = models.Investigation(title=title, created_by=user.id, status=models.InvestigationStatus.VALIDATING)
    db.add(inv)
    db.commit()
    db.refresh(inv)

    dest_name = f"{inv.id}_{uuid.uuid4().hex[:8]}{Path(file.filename).suffix.lower()}"
    dest_path = UPLOAD_DIR / dest_name
    with open(dest_path, "wb") as out:
        shutil.copyfileobj(file.file, out)

    try:
        result = validate_pcap(dest_path, file.filename)
    except PcapValidationError as e:
        inv.status = models.InvestigationStatus.FAILED
        inv.error_message = str(e)
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    pcap_row = models.Pcap(
        investigation_id=inv.id, filename=file.filename, stored_path=str(dest_path),
        size_bytes=result.size_bytes, sha256=result.sha256,
        parser_version=PARSER_VERSION, analysis_version=PARSER_VERSION,
    )
    db.add(pcap_row)
    inv.status = models.InvestigationStatus.QUEUED
    db.commit()

    background_tasks.add_task(_run_in_background, inv.id)
    return {"investigation_id": inv.id, "sha256": result.sha256, "status": "QUEUED"}


def _run_in_background(investigation_id: str):
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        run_analysis(db, investigation_id)
    finally:
        db.close()


@router.get("/pcaps/{pcap_id}/status")
def pcap_status(pcap_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    pcap_row = db.query(models.Pcap).get(pcap_id)
    if not pcap_row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "PCAP not found")
    return {"investigation_id": pcap_row.investigation_id, "status": pcap_row.investigation.status.value}


# ---------------------------------------------------------------------------
# Dashboard summary -- the single source of truth for every KPI/chart the
# frontend renders (Overview, Results page, AI Assistant context). Nothing
# here is invented: every field is a real aggregate over this investigation's
# rows, or an explicit null/"insufficient data" when nothing was observed.
# ---------------------------------------------------------------------------
@router.get("/investigations/{investigation_id}/summary")
def get_investigation_summary(investigation_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    inv = db.query(models.Investigation).get(investigation_id)
    if not inv:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")

    sessions = db.query(models.NetworkSession).filter_by(investigation_id=investigation_id).all()
    findings = db.query(models.Finding).filter_by(investigation_id=investigation_id).all()

    session_count = len(sessions)
    packet_count = inv.pcap.packet_count if inv.pcap else None

    protocol_counts = {}
    for s in sessions:
        key = s.protocol_guess or "UNKNOWN"
        protocol_counts[key] = protocol_counts.get(key, 0) + 1

    tls_observed = sum(1 for s in sessions if s.tls_handshake and s.tls_handshake.status == "OBSERVED")
    tls_coverage_pct = round(100 * tls_observed / session_count, 1) if session_count else None

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1
    high_risk_count = severity_counts["CRITICAL"] + severity_counts["HIGH"]

    risk_rows = (
        db.query(models.RiskScore)
        .join(models.NetworkSession, models.RiskScore.network_session_id == models.NetworkSession.id)
        .filter(models.NetworkSession.investigation_id == investigation_id)
        .all()
    )
    avg_risk = round(sum(r.final_score for r in risk_rows) / len(risk_rows), 1) if risk_rows else None
    max_risk = round(max((r.final_score for r in risk_rows), default=0), 1) if risk_rows else None

    cert_statuses = {}
    for s in sessions:
        if s.tls_handshake:
            for c in s.tls_handshake.certificates:
                cert_statuses[c.status or "UNKNOWN"] = cert_statuses.get(c.status or "UNKNOWN", 0) + 1

    starttls_counts = {}
    for s in sessions:
        if s.email_session:
            st = s.email_session.starttls_state or "NOT_OBSERVED"
            starttls_counts[st] = starttls_counts.get(st, 0) + 1

    return {
        "investigation_id": inv.id,
        "title": inv.title,
        "status": inv.status.value,
        "is_demo": inv.is_demo,
        "pcap": {
            "filename": inv.pcap.filename, "sha256": inv.pcap.sha256,
            "size_bytes": inv.pcap.size_bytes,
        } if inv.pcap else None,
        "packet_count": packet_count,
        "session_count": session_count,
        "tls_coverage_pct": tls_coverage_pct,
        "protocol_distribution": protocol_counts,
        "severity_distribution": severity_counts,
        "high_risk_count": high_risk_count,
        "finding_count": len(findings),
        "avg_risk_score": avg_risk,
        "max_risk_score": max_risk,
        "certificate_status_distribution": cert_statuses,
        "starttls_distribution": starttls_counts,
    }
