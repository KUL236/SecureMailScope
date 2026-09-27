"""
Report generation (section 33). Every report is stamped with PCAP SHA-256,
analysis timestamp, and every component version -- required for forensic
defensibility.
"""
import json
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app import models
from app.config import (
    REPORT_DIR, PARSER_VERSION, FEATURE_VERSION, RULE_VERSION, MODEL_VERSION,
)

SOFTWARE_VERSION = "SecureMailScope 1.0.0"


def _collect_report_data(db: Session, investigation_id: str) -> dict:
    inv = db.query(models.Investigation).get(investigation_id)
    if not inv:
        raise ValueError("Investigation not found")
    sessions = db.query(models.NetworkSession).filter_by(investigation_id=investigation_id).all()
    findings = db.query(models.Finding).filter_by(investigation_id=investigation_id).all()

    session_blocks = []
    for s in sessions:
        risk = (db.query(models.RiskScore).filter_by(network_session_id=s.id)
                .order_by(models.RiskScore.created_at.desc()).first())
        session_blocks.append({
            "session_id": s.id, "src": f"{s.src_ip}:{s.src_port}", "dst": f"{s.dst_ip}:{s.dst_port}",
            "protocol": s.protocol_guess, "is_complete": s.is_complete,
            "starttls_state": s.email_session.starttls_state if s.email_session else "NOT_OBSERVED",
            "tls_status": s.tls_handshake.status if s.tls_handshake else "NOT_OBSERVED",
            "tls_version": s.tls_handshake.tls_version_negotiated if s.tls_handshake else None,
            "cipher_suite_name": s.tls_handshake.cipher_suite_name if s.tls_handshake else None,
            "key_exchange": s.tls_handshake.key_exchange if s.tls_handshake else None,
            "forward_secrecy": s.tls_handshake.forward_secrecy if s.tls_handshake else None,
            "certificates": [
                {"subject": c.subject, "issuer": c.issuer, "status": c.status,
                 "not_after": str(c.not_after), "fingerprint": c.sha256_fingerprint,
                 "chain_validation_status": c.chain_validation_status,
                 "revocation_status": c.revocation_status}
                for c in (s.tls_handshake.certificates if s.tls_handshake else [])
            ],
            "risk": {
                "final_score": risk.final_score, "severity": risk.severity,
                "confidence": risk.confidence,
            } if risk else None,
        })

    return {
        "investigation": {"id": inv.id, "title": inv.title, "status": inv.status.value, "is_demo": inv.is_demo},
        "pcap": {
            "filename": inv.pcap.filename, "sha256": inv.pcap.sha256,
            "size_bytes": inv.pcap.size_bytes, "packet_count": inv.pcap.packet_count,
        } if inv.pcap else None,
        "sessions": session_blocks,
        "findings": [{
            "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
            "description": f.description, "observed_value": f.observed_value,
            "expected_value": f.expected_value, "recommendation": f.recommendation,
        } for f in findings],
        "metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "software_version": SOFTWARE_VERSION,
            "parser_version": PARSER_VERSION, "feature_version": FEATURE_VERSION,
            "rule_version": RULE_VERSION, "model_version": MODEL_VERSION,
        },
        "limitations": [
            "This tool performs passive metadata/certificate analysis only; it never decrypts email payloads.",
            "Revocation status (OCSP/CRL) is NOT DETERMINED FROM PCAP unless external validation was explicitly enabled.",
            "Findings marked NOT_OBSERVED reflect absence of evidence in the capture, not absence of the underlying condition.",
        ],
    }


def generate_json_report(db: Session, investigation_id: str) -> Path:
    data = _collect_report_data(db, investigation_id)
    out_path = REPORT_DIR / f"{investigation_id}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str))
    return out_path


def generate_html_report(db: Session, investigation_id: str) -> Path:
    data = _collect_report_data(db, investigation_id)
    rows = "".join(
        f"<tr><td>{f['severity']}</td><td>{f['title']}</td><td>{f['description']}</td>"
        f"<td>{f['recommendation']}</td></tr>"
        for f in data["findings"]
    )
    sess_rows = "".join(
        f"<tr><td>{s['src']}</td><td>{s['dst']}</td><td>{s['protocol']}</td>"
        f"<td>{s['starttls_state']}</td><td>{s['tls_status']}</td>"
        f"<td>{s['risk']['severity'] if s['risk'] else 'N/A'}</td></tr>"
        for s in data["sessions"]
    )
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>SecureMailScope Report - {data['investigation']['title']}</title>
<style>
body {{ font-family: -apple-system, sans-serif; background:#0b0d10; color:#e6e8eb; padding:32px; }}
h1,h2 {{ color:#7ee0d6; }} table {{ width:100%; border-collapse:collapse; margin:16px 0; }}
td,th {{ border:1px solid #2a2f36; padding:8px; text-align:left; font-size:13px; }}
.meta {{ color:#9aa4af; font-size:12px; }}
</style></head><body>
<h1>SecureMailScope Forensic Report</h1>
<p class="meta">Generated {data['metadata']['generated_at']} · {data['metadata']['software_version']}</p>
<p class="meta">PCAP SHA-256: {data['pcap']['sha256'] if data['pcap'] else 'N/A'}</p>
<h2>Executive Summary</h2>
<p>{len(data['sessions'])} session(s) analyzed, {len(data['findings'])} finding(s) generated.</p>
<h2>Sessions</h2>
<table><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>STARTTLS</th><th>TLS</th><th>Risk</th></tr>{sess_rows}</table>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>Description</th><th>Recommendation</th></tr>{rows}</table>
<h2>Limitations</h2>
<ul>{''.join(f'<li>{l}</li>' for l in data['limitations'])}</ul>
</body></html>"""
    out_path = REPORT_DIR / f"{investigation_id}.html"
    out_path.write_text(html)
    return out_path


def generate_pdf_report(db: Session, investigation_id: str) -> Path:
    """Uses reportlab -- kept intentionally simple/legible over decorative."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas

    data = _collect_report_data(db, investigation_id)
    out_path = REPORT_DIR / f"{investigation_id}.pdf"
    c = canvas.Canvas(str(out_path), pagesize=A4)
    width, height = A4
    y = height - 25 * mm

    def line(text, size=10, dy=6 * mm, bold=False):
        nonlocal y
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(20 * mm, y, text[:110])
        y -= dy
        if y < 20 * mm:
            c.showPage()
            y = height - 25 * mm

    line("SecureMailScope Forensic Report", 16, bold=True)
    line(f"Investigation: {data['investigation']['title']}", 11)
    line(f"Generated: {data['metadata']['generated_at']}", 9)
    line(f"PCAP SHA-256: {data['pcap']['sha256'] if data['pcap'] else 'N/A'}", 9)
    line(f"Versions: parser={data['metadata']['parser_version']} rule={data['metadata']['rule_version']} "
         f"model={data['metadata']['model_version']}", 9)
    line("")
    line(f"Sessions analyzed: {len(data['sessions'])}   Findings: {len(data['findings'])}", 11, bold=True)
    line("")
    line("Findings:", 12, bold=True)
    for f in data["findings"]:
        line(f"[{f['severity']}] {f['title']}", 10, bold=True)
        line(f"  {f['description']}", 9)
        line(f"  Recommendation: {f['recommendation']}", 9)
    line("")
    line("Limitations:", 12, bold=True)
    for lim in data["limitations"]:
        line(f"- {lim}", 9)
    c.save()
    return out_path
