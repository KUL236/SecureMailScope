import importlib
import shutil

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.auth import get_current_user
from app.config import DATABASE_URL

router = APIRouter(prefix="/api", tags=["misc"])


@router.get("/findings")
def list_findings(investigation_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = db.query(models.Finding).filter_by(investigation_id=investigation_id).all()
    return [{
        "id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
        "description": f.description, "observed_value": f.observed_value,
        "expected_value": f.expected_value, "confidence": f.confidence,
        "recommendation": f.recommendation, "network_session_id": f.network_session_id,
    } for f in rows]


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    f = db.query(models.Finding).get(finding_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return {
        "id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
        "description": f.description, "observed_value": f.observed_value,
        "expected_value": f.expected_value, "confidence": f.confidence,
        "recommendation": f.recommendation, "rule_version": f.rule_version,
        "evidence": [{
            "pcap_sha256": e.pcap_sha256, "packet_number": e.packet_number,
            "timestamp": e.timestamp, "field_name": e.field_name,
            "observed_value": e.observed_value, "parser_version": e.parser_version,
        } for e in f.evidence],
    }


@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    e = db.query(models.Evidence).get(evidence_id)
    if not e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evidence not found")
    return {
        "pcap_sha256": e.pcap_sha256, "network_session_id": e.network_session_id,
        "packet_number": e.packet_number, "timestamp": e.timestamp, "protocol": e.protocol,
        "field_name": e.field_name, "observed_value": e.observed_value,
        "parser_version": e.parser_version, "rule_version": e.rule_version, "model_version": e.model_version,
    }


@router.get("/audit-log")
def audit_log(db: Session = Depends(get_db), user=Depends(get_current_user)):
    roles = {r.name for r in user.roles}
    if "admin" not in roles:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin only")
    rows = db.query(models.AuditLog).order_by(models.AuditLog.created_at.desc()).limit(200).all()
    return [{"action": r.action, "target_type": r.target_type, "target_id": r.target_id,
              "user_id": r.user_id, "created_at": r.created_at} for r in rows]


def _module_available(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except ImportError:
        return False


@router.get("/system/dependencies")
def system_dependencies():
    """No auth required -- used by the frontend setup/health screen."""
    return {
        "tshark": shutil.which("tshark") is not None,
        "python_ok": True,
        "scapy": _module_available("scapy"),
        "cryptography": _module_available("cryptography"),
        "database_configured": bool(DATABASE_URL),
        "ml_runtime": {
            "scikit_learn": _module_available("sklearn"),
            "xgboost": _module_available("xgboost"),
        },
    }
