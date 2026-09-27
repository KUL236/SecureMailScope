"""
In-app "MailSecure AI" forensic assistant.

Architecture (matches the required PCAP-aware chatbot design):

    user message -> intent match against REAL backend data for this
    investigation (sessions, findings, TLS, certificates, STARTTLS,
    risk scores) -> deterministic, evidence-grounded answer + source
    references.

This module is the source of truth. If an LLM_API_KEY is configured it
may be used later to *phrase* an answer more naturally, but it is never
allowed to invent sessions, packet numbers, IPs, certificates or CVEs --
every fact below is read straight from the database for this
investigation_id. If nothing matches, the assistant says so explicitly
rather than guessing: no hallucinated forensic claims.

Works with ZERO external API key.
"""
import re
from typing import Optional
from sqlalchemy.orm import Session

from app import models

KNOWLEDGE_BASE = {
    "starttls": "STARTTLS is an SMTP extension (RFC 3207) that lets a plaintext connection "
                "upgrade to TLS mid-session. The server advertises it in the EHLO response, "
                "the client sends the STARTTLS command, and the server replies 220 before the "
                "TLS handshake begins.",
    "self-signed": "A self-signed certificate has the same subject and issuer -- it wasn't "
                    "issued by a separate certificate authority. It can still encrypt traffic, "
                    "but clients can't verify it against a trusted CA chain.",
    "chain": "A certificate chain links a leaf certificate up through intermediate CAs to a "
             "trusted root. An incomplete chain means the server didn't send the intermediate "
             "certificate(s) needed to validate the leaf.",
    "expired": "An expired certificate has a not_after date in the past. Mail clients and "
               "servers may reject or warn on connections using it.",
    "weak key": "Keys below common minimums (e.g. RSA < 2048 bits) are considered weak because "
                "they're more feasible to break with modern computing resources.",
    "forward secrecy": "Forward secrecy means each session uses an ephemeral key (ECDHE/DHE), "
                        "so recording traffic today and stealing the server's long-term key "
                        "later still wouldn't decrypt it. Static RSA key exchange has no "
                        "forward secrecy.",
    "risk score": "The 0-100 risk score fuses deterministic rule findings, an ML classifier's "
                   "probability, and an anomaly score, weighted toward the rule findings since "
                   "those are directly evidence-backed.",
    "anomaly": "An anomaly score flags statistically unusual sessions. ANOMALOUS does not mean "
               "MALICIOUS -- it's a prompt for analyst review, not a verdict.",
    "revocation": "This tool cannot determine certificate revocation status from a passive PCAP "
                  "alone (no OCSP/CRL lookup by default), so it's reported as NOT DETERMINED "
                  "FROM PCAP rather than guessed.",
    "sha-256": "Every uploaded PCAP is hashed with SHA-256 at upload time. That hash is stamped "
               "on every finding and report so results can be tied back to an exact, unmodified capture.",
    "not observed": "NOT_OBSERVED means the relevant evidence simply wasn't present in the capture "
                     "-- it is not a judgment that the condition is absent.",
}


def _short(session_id: str) -> str:
    return f"S-{session_id[:8]}" if session_id else "S-unknown"


def _lookup_terms(message: str):
    msg = message.lower()
    return [(term, expl) for term, expl in KNOWLEDGE_BASE.items() if term in msg]


def _get_investigation(db, investigation_id):
    return db.query(models.Investigation).get(investigation_id) if investigation_id else None


def _sessions(db, investigation_id):
    return db.query(models.NetworkSession).filter_by(investigation_id=investigation_id).all()


def _findings(db, investigation_id):
    return db.query(models.Finding).filter_by(investigation_id=investigation_id).all()


def _no_data(inv) -> dict:
    return {
        "answer": "No analysis is loaded yet, or this investigation has not finished processing. "
                  "Upload and analyze a PCAP first, then ask me again.",
        "sources": [],
    }


def _investigation_overview(db: Session, inv) -> dict:
    sessions = _sessions(db, inv.id)
    findings = _findings(db, inv.id)
    if inv.status.value != "COMPLETE":
        return {
            "answer": f"'{inv.title}' is currently {inv.status.value}. "
                      f"I'll have a full summary once analysis reaches COMPLETE.",
            "sources": [],
        }
    if not sessions:
        return {
            "answer": f"'{inv.title}' completed analysis but no TCP sessions were reconstructed "
                      f"from this capture -- insufficient evidence to summarize traffic.",
            "sources": [{"type": "investigation", "id": inv.id}],
        }

    protos = {}
    for s in sessions:
        protos[s.protocol_guess or "UNKNOWN"] = protos.get(s.protocol_guess or "UNKNOWN", 0) + 1
    proto_str = ", ".join(f"{k}: {v}" for k, v in sorted(protos.items(), key=lambda x: -x[1]))

    tls_observed = sum(1 for s in sessions if s.tls_handshake and s.tls_handshake.status == "OBSERVED")
    tls_pct = round(100 * tls_observed / len(sessions), 1)

    by_sev = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)
    sev_str = ", ".join(f"{sev}: {len(by_sev[sev])}" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if sev in by_sev)

    pcap = inv.pcap
    parts = [
        f"Capture: {pcap.filename if pcap else 'unknown'}"
        + (f" (SHA-256 {pcap.sha256[:16]}...)" if pcap else "") + ".",
        f"{len(sessions)} session(s) reconstructed. Protocol mix: {proto_str or 'none identified'}.",
        f"TLS observed on {tls_observed}/{len(sessions)} sessions ({tls_pct}%).",
    ]
    if findings:
        parts.append(f"{len(findings)} finding(s) -- {sev_str}.")
        top = sorted(findings, key=lambda f: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}.get(f.severity, 0), reverse=True)[:3]
        parts.append("Top findings: " + "; ".join(f"[{f.severity}] {f.title} ({_short(f.network_session_id)})" for f in top) + ".")
    else:
        parts.append("No security findings were raised against this capture.")

    sources = [{"type": "investigation", "id": inv.id}]
    sources += [{"type": "finding", "id": f.id} for f in findings[:5]]
    return {"answer": " ".join(parts), "sources": sources}


def _high_risk_sessions(db: Session, inv) -> dict:
    rows = (
        db.query(models.RiskScore)
        .join(models.NetworkSession, models.RiskScore.network_session_id == models.NetworkSession.id)
        .filter(models.NetworkSession.investigation_id == inv.id)
        .filter(models.RiskScore.severity.in_(["HIGH", "CRITICAL"]))
        .order_by(models.RiskScore.final_score.desc())
        .all()
    )
    if not rows:
        return {"answer": "No sessions in this investigation were scored HIGH or CRITICAL risk.", "sources": []}
    lines = []
    sources = []
    for r in rows[:8]:
        s = db.query(models.NetworkSession).get(r.network_session_id)
        endpoint = f"{s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}" if s else "unknown"
        lines.append(f"{_short(r.network_session_id)} ({endpoint}): {r.severity}, score {r.final_score}/100")
        sources.append({"type": "session", "id": r.network_session_id})
    return {"answer": f"{len(rows)} high-risk session(s): " + "; ".join(lines) + ".", "sources": sources}


def _tls_versions(db: Session, inv) -> dict:
    sessions = _sessions(db, inv.id)
    versions = {}
    for s in sessions:
        if s.tls_handshake and s.tls_handshake.tls_version_negotiated:
            v = s.tls_handshake.tls_version_negotiated
            versions[v] = versions.get(v, 0) + 1
    if not versions:
        return {"answer": "No completed TLS handshakes were observed in this capture, so no TLS version could be determined.", "sources": []}
    vstr = ", ".join(f"{k}: {v} session(s)" for k, v in sorted(versions.items(), key=lambda x: -x[1]))
    legacy = [k for k in versions if k in ("TLS 1.0", "TLS 1.1", "SSLv3")]
    note = f" {', '.join(legacy)} were negotiated on at least one session -- these are legacy/weak protocol versions." if legacy else " No legacy TLS versions were negotiated."
    return {"answer": f"Negotiated TLS versions: {vstr}." + note, "sources": [{"type": "investigation", "id": inv.id}]}


def _certificates(db: Session, inv, want_status: str) -> dict:
    sessions = _sessions(db, inv.id)
    hits = []
    for s in sessions:
        if not s.tls_handshake:
            continue
        for c in s.tls_handshake.certificates:
            if c.status == want_status:
                hits.append((s, c))
    label = want_status.replace("_", "-").lower()
    if not hits:
        return {"answer": f"No {label} certificates were observed in this capture.", "sources": []}
    lines = [f"{_short(s.id)}: subject={c.subject or 'unknown'}, issuer={c.issuer or 'unknown'}"
              + (f", expired {c.not_after}" if want_status == "EXPIRED" and c.not_after else "")
              for s, c in hits[:6]]
    sources = [{"type": "session", "id": s.id} for s, _ in hits[:6]]
    return {"answer": f"{len(hits)} {label} certificate(s) found: " + "; ".join(lines) + ".", "sources": sources}


def _forward_secrecy(db: Session, inv) -> dict:
    sessions = _sessions(db, inv.id)
    no_fs = [s for s in sessions if s.tls_handshake and s.tls_handshake.forward_secrecy is False]
    if not no_fs:
        return {"answer": "Every TLS session with a determinable key exchange used forward secrecy (ECDHE/DHE). None were flagged as lacking it.", "sources": []}
    lines = [f"{_short(s.id)} ({s.tls_handshake.key_exchange or 'unknown key exchange'})" for s in no_fs[:8]]
    return {"answer": f"{len(no_fs)} session(s) without forward secrecy: " + "; ".join(lines) + ".",
            "sources": [{"type": "session", "id": s.id} for s in no_fs[:8]]}


def _starttls(db: Session, inv, rejected_only: bool) -> dict:
    sessions = _sessions(db, inv.id)
    relevant = [s for s in sessions if s.email_session]
    if rejected_only:
        hits = [s for s in relevant if s.email_session.starttls_state in ("STARTTLS_REJECTED", "STARTTLS_FAILED")]
        if not hits:
            return {"answer": "No STARTTLS negotiations failed or were rejected in this capture.", "sources": []}
        lines = [f"{_short(s.id)}: {s.email_session.starttls_state}" for s in hits]
        return {"answer": f"{len(hits)} session(s) with a failed/rejected STARTTLS: " + "; ".join(lines) + ".",
                "sources": [{"type": "session", "id": s.id} for s in hits]}
    used = [s for s in relevant if s.email_session.starttls_accepted]
    if not used:
        return {"answer": "No SMTP sessions in this capture successfully completed a STARTTLS upgrade.", "sources": []}
    lines = [f"{_short(s.id)} ({s.protocol_guess})" for s in used]
    return {"answer": f"{len(used)} SMTP session(s) used STARTTLS successfully: " + "; ".join(lines) + ".",
            "sources": [{"type": "session", "id": s.id} for s in used]}


def _recommendations(db: Session, inv) -> dict:
    findings = _findings(db, inv.id)
    recs = [(f, f.recommendation) for f in findings if f.recommendation]
    if not recs:
        return {"answer": "No findings with recommendations are available for this investigation.", "sources": []}
    lines = [f"[{f.severity}] {f.title}: {rec}" for f, rec in recs[:6]]
    return {"answer": " ".join(lines), "sources": [{"type": "finding", "id": f.id} for f, _ in recs[:6]]}


def _session_explanation(db: Session, session_id: str) -> Optional[dict]:
    s = db.query(models.NetworkSession).get(session_id)
    if not s:
        return None
    risk = (db.query(models.RiskScore).filter_by(network_session_id=session_id)
            .order_by(models.RiskScore.created_at.desc()).first())
    findings = db.query(models.Finding).filter_by(network_session_id=session_id).all()
    parts = [f"Session {_short(session_id)} ({s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}, {s.protocol_guess or 'unknown protocol'})."]
    if risk:
        parts.append(f"Risk score {risk.final_score}/100 ({risk.severity}, confidence {risk.confidence}).")
    else:
        parts.append("No risk score has been computed for this session yet.")
    if findings:
        parts.append("Findings: " + "; ".join(f"[{f.severity}] {f.title} -- {f.description or ''}".strip() for f in findings) + ".")
    else:
        parts.append("No rule-based findings were raised against this session.")
    sources = [{"type": "session", "id": session_id}] + [{"type": "finding", "id": f.id} for f in findings]
    return {"answer": " ".join(parts), "sources": sources}


def answer(db: Session, message: str, investigation_id: Optional[str] = None, session_id: Optional[str] = None) -> dict:
    inv = _get_investigation(db, investigation_id)
    msg = message.lower()

    # Direct question about a specific session (explicit session_id, e.g. clicked from UI)
    if session_id and re.search(r"\b(why|risk|explain|this session)\b", msg):
        result = _session_explanation(db, session_id)
        if result:
            return result

    if not inv:
        term_hits = _lookup_terms(message)
        if term_hits:
            return {"answer": " ".join(expl for _, expl in term_hits[:2]), "sources": []}
        return {
            "answer": "No analysis is currently loaded. Upload and analyze a PCAP first -- "
                      "then I can answer questions grounded in that capture's real sessions, "
                      "findings, TLS and certificate data.",
            "sources": [],
        }

    if inv.status.value != "COMPLETE":
        return _no_data(inv)

    if re.search(r"\bhigh.?risk\b", msg) and re.search(r"\bsession", msg):
        return _high_risk_sessions(db, inv)
    if "tls version" in msg or ("tls" in msg and "version" in msg):
        return _tls_versions(db, inv)
    if "self-signed" in msg or "self signed" in msg:
        return _certificates(db, inv, "SELF_SIGNED")
    if "expired" in msg and "cert" in msg:
        return _certificates(db, inv, "EXPIRED")
    if "forward secrecy" in msg or "forward-secrecy" in msg:
        return _forward_secrecy(db, inv)
    if "starttls" in msg and ("fail" in msg or "reject" in msg):
        return _starttls(db, inv, rejected_only=True)
    if "starttls" in msg:
        return _starttls(db, inv, rejected_only=False)
    if "recommend" in msg or "mitigat" in msg:
        return _recommendations(db, inv)

    if re.search(r"\bsession\b", msg):
        m = re.search(r"[0-9a-fA-F]{8}", msg)
        if m:
            candidates = db.query(models.NetworkSession).filter(
                models.NetworkSession.investigation_id == inv.id,
                models.NetworkSession.id.like(f"{m.group(0).lower()}%"),
            ).all()
            if len(candidates) == 1:
                result = _session_explanation(db, candidates[0].id)
                if result:
                    return result

    if re.search(r"\bwhat happened\b|\bsummar\w*\b|\boverview\b|\bposture\b|\bjudge\b", msg):
        return _investigation_overview(db, inv)

    term_hits = _lookup_terms(message)
    if term_hits:
        return {"answer": " ".join(expl for _, expl in term_hits[:2]), "sources": []}

    return {
        "answer": "I can summarize this capture, list high-risk sessions, explain a specific "
                  "session's risk, check TLS versions and certificates (self-signed/expired), "
                  "check forward secrecy, check STARTTLS outcomes, or give recommendations. "
                  "Try \"What happened in this PCAP?\" or \"Show me all high-risk sessions.\"",
        "sources": [],
    }
