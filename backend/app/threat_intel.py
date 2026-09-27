"""
Threat intelligence correlation.

No external feed: THREAT_INTEL_API_KEY (see config.py) is enrichment-only
and unused today. Everything here is derived purely from evidence already
extracted from an analyzed capture -- findings, sessions and certificates
already in this investigation. An "indicator" is a destination endpoint
(dst_ip:dst_port) that has one or more HIGH/CRITICAL-severity findings
attached to sessions talking to it, optionally enriched with certificate
irregularities observed on the same session.

Kept dependency-free (no SQLAlchemy imports) so it can be unit tested with
plain dicts, the same way app/rules.py and app/risk.py are tested.
"""
from collections import defaultdict

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Only findings at or above this severity become a threat indicator --
# Threat Intelligence is meant to surface what needs attention, not
# restate every LOW/MEDIUM finding already visible on the Findings page.
MIN_SEVERITY = "MEDIUM"


def _severity_rank(sev):
    return SEVERITY_RANK.get((sev or "").upper(), 0)


def build_indicators(sessions, findings, certificates_by_session):
    """
    sessions: list of dicts with at least {id, dst_ip, dst_port, protocol_guess, start_time}
    findings: list of dicts with at least {id, network_session_id, rule_id, title, severity}
    certificates_by_session: {session_id: [{status, subject, issuer, sha256_fingerprint}, ...]}

    Returns a list of indicator dicts, most severe / most-corroborated first.
    """
    threshold = _severity_rank(MIN_SEVERITY)
    by_session = defaultdict(list)
    for f in findings:
        if f.get("network_session_id") and _severity_rank(f.get("severity")) >= threshold:
            by_session[f["network_session_id"]].append(f)

    sessions_by_id = {s["id"]: s for s in sessions}
    indicators = []
    for session_id, flist in by_session.items():
        s = sessions_by_id.get(session_id)
        if not s:
            continue
        max_sev = max(flist, key=lambda f: _severity_rank(f.get("severity")))["severity"]
        certs = certificates_by_session.get(session_id, [])
        cert_flags = sorted({c["status"] for c in certs if c.get("status") and c["status"] != "VALID"})

        dst_ip = s.get("dst_ip") or "unknown"
        dst_port = s.get("dst_port")
        indicator_label = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

        indicators.append({
            "session_id": session_id,
            "indicator": indicator_label,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": s.get("protocol_guess") or "UNKNOWN",
            "severity": max_sev,
            "finding_count": len(flist),
            "rule_ids": sorted({f["rule_id"] for f in flist if f.get("rule_id")}),
            "titles": sorted({f["title"] for f in flist if f.get("title")}),
            "certificate_flags": cert_flags,
            "first_seen": s.get("start_time"),
        })

    indicators.sort(key=lambda i: (-_severity_rank(i["severity"]), -i["finding_count"], i["indicator"]))
    return indicators


def summarize_severity(indicators):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for i in indicators:
        sev = (i.get("severity") or "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts
