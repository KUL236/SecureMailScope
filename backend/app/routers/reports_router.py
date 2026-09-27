from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.auth import get_current_user
from app.reports import generate_json_report, generate_html_report, generate_pdf_report

router = APIRouter(prefix="/api", tags=["reports"])

GENERATORS = {"JSON": generate_json_report, "HTML": generate_html_report, "PDF": generate_pdf_report}


@router.post("/reports")
def create_report(investigation_id: str, format: str = "PDF", db: Session = Depends(get_db), user=Depends(get_current_user)):
    fmt = format.upper()
    if fmt not in GENERATORS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "format must be one of PDF, JSON, HTML")
    path = GENERATORS[fmt](db, investigation_id)

    from app.config import PARSER_VERSION, FEATURE_VERSION, RULE_VERSION, MODEL_VERSION
    row = models.Report(
        investigation_id=investigation_id, format=fmt, stored_path=str(path),
        software_version="SecureMailScope 1.0.0", model_version=MODEL_VERSION,
        feature_version=FEATURE_VERSION, rule_version=RULE_VERSION,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "format": row.format, "generated_at": row.generated_at}


@router.get("/reports")
def list_reports(investigation_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Every report already generated for this investigation, newest first --
    lets the Reports page reload its list on a page refresh instead of only
    showing reports generated earlier in the same browser session."""
    rows = (
        db.query(models.Report)
        .filter_by(investigation_id=investigation_id)
        .order_by(models.Report.generated_at.desc())
        .all()
    )
    return [{"id": r.id, "format": r.format, "generated_at": r.generated_at} for r in rows]


@router.get("/reports/{report_id}")
def download_report(report_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    row = db.query(models.Report).get(report_id)
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    media_types = {"PDF": "application/pdf", "JSON": "application/json", "HTML": "text/html"}
    return FileResponse(row.stored_path, media_type=media_types[row.format])
