"""
Unit tests for app.threat_intel -- the correlation logic behind the Threat
Intelligence page. Pure logic, no DB required, same style as
test_pagination.py.
"""
from app.threat_intel import build_indicators, summarize_severity


def _session(id="s1", dst_ip="203.0.113.5", dst_port=443, protocol="SMTP", start_time="2026-01-01T00:00:00"):
    return {"id": id, "dst_ip": dst_ip, "dst_port": dst_port, "protocol_guess": protocol, "start_time": start_time}


def _finding(id="f1", session_id="s1", rule_id="R1", title="Weak cipher", severity="HIGH"):
    return {"id": id, "network_session_id": session_id, "rule_id": rule_id, "title": title, "severity": severity}


def test_no_findings_means_no_indicators():
    assert build_indicators([_session()], [], {}) == []


def test_low_and_medium_below_threshold_are_dropped_medium_kept():
    # MIN_SEVERITY is MEDIUM, so LOW is excluded but MEDIUM is kept.
    findings = [_finding(id="f1", severity="LOW"), _finding(id="f2", severity="MEDIUM")]
    out = build_indicators([_session()], findings, {})
    assert len(out) == 1
    assert out[0]["finding_count"] == 1
    assert out[0]["severity"] == "MEDIUM"


def test_findings_without_a_session_are_ignored():
    findings = [{"id": "f1", "network_session_id": None, "rule_id": "R1", "title": "x", "severity": "CRITICAL"}]
    assert build_indicators([_session()], findings, {}) == []


def test_groups_multiple_findings_on_same_session_into_one_indicator():
    findings = [
        _finding(id="f1", severity="HIGH", rule_id="R1", title="Weak cipher"),
        _finding(id="f2", severity="CRITICAL", rule_id="R2", title="Self-signed cert"),
    ]
    out = build_indicators([_session()], findings, {})
    assert len(out) == 1
    ind = out[0]
    assert ind["finding_count"] == 2
    assert ind["severity"] == "CRITICAL"  # most severe of the group
    assert ind["rule_ids"] == ["R1", "R2"]
    assert ind["indicator"] == "203.0.113.5:443"


def test_certificate_flags_exclude_valid_status():
    certs_by_session = {"s1": [{"status": "VALID"}, {"status": "SELF_SIGNED"}, {"status": "EXPIRED"}]}
    out = build_indicators([_session()], [_finding(severity="HIGH")], certs_by_session)
    assert out[0]["certificate_flags"] == ["EXPIRED", "SELF_SIGNED"]


def test_indicators_sorted_by_severity_then_finding_count():
    sessions = [_session(id="s1", dst_ip="203.0.113.1"), _session(id="s2", dst_ip="203.0.113.2")]
    findings = [
        _finding(id="f1", session_id="s1", severity="MEDIUM"),
        _finding(id="f2", session_id="s2", severity="CRITICAL"),
    ]
    out = build_indicators(sessions, findings, {})
    assert [i["session_id"] for i in out] == ["s2", "s1"]


def test_summarize_severity_counts_only_known_buckets():
    indicators = [{"severity": "HIGH"}, {"severity": "HIGH"}, {"severity": "CRITICAL"}, {"severity": "MEDIUM"}]
    assert summarize_severity(indicators) == {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def test_orphaned_session_reference_is_skipped():
    # Finding points at a session_id that isn't in the sessions list (e.g.
    # deleted or from a different investigation) -- must not crash.
    out = build_indicators([], [_finding(session_id="missing")], {})
    assert out == []
