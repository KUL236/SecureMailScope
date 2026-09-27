"""
Risk fusion (section 23). Deterministic and versioned: same inputs always
produce the same score, so results are reproducible and defensible in a
forensic context.
"""
from dataclasses import dataclass
from typing import List, Optional

from app.config import POLICY_VERSION
from app.rules import RuleFinding

SEVERITY_WEIGHT = {"LOW": 10, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 100}

# Fusion weights -- rules dominate because they're evidence-backed;
# ML/anomaly contribute but never solely drive a CRITICAL verdict.
W_RULES = 0.55
W_ML = 0.30
W_ANOMALY = 0.15


@dataclass
class RiskResult:
    rule_score: float
    ml_probability: Optional[float]
    anomaly_score: Optional[float]
    evidence_quality: float
    final_score: float
    severity: str
    confidence: float
    policy_version: str = POLICY_VERSION


def compute_rule_score(findings: List[RuleFinding]) -> float:
    if not findings:
        return 0.0
    # Diminishing-returns sum so 5 LOW findings don't outrank one CRITICAL.
    total = 0.0
    for f in sorted(findings, key=lambda x: -SEVERITY_WEIGHT[x.severity]):
        remaining = 100 - total
        total += remaining * (SEVERITY_WEIGHT[f.severity] / 100) * f.confidence
    return round(min(total, 100.0), 2)


def evidence_quality_score(*, network_session, tls_info, email_session) -> float:
    """0..1: how complete/trustworthy is the underlying evidence."""
    score = 1.0
    if network_session and not network_session.is_complete:
        score -= 0.25
    if tls_info and tls_info.status != "OBSERVED":
        score -= 0.25
    if tls_info and not tls_info.handshake_complete:
        score -= 0.15
    if email_session and email_session.protocol_confidence < 0.7:
        score -= 0.15
    return round(max(score, 0.1), 2)


def severity_from_score(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def fuse_risk(*, findings: List[RuleFinding], ml_result: dict, network_session, tls_info, email_session) -> RiskResult:
    rule_score = compute_rule_score(findings)
    ml_prob = ml_result.get("probability") if ml_result.get("scored") else None
    anomaly = ml_result.get("anomaly_score") if ml_result.get("scored") else None
    eq = evidence_quality_score(network_session=network_session, tls_info=tls_info, email_session=email_session)

    ml_component = (ml_prob * 100) if ml_prob is not None else rule_score  # fall back to rules if unscored
    anomaly_component = (anomaly * 100) if anomaly is not None else 0.0

    final = (W_RULES * rule_score) + (W_ML * ml_component) + (W_ANOMALY * anomaly_component)
    final = round(final * eq + final * (1 - eq) * 0.5, 2)  # low evidence quality pulls score toward caution, not zero
    final = min(final, 100.0)

    confidence = round(eq * (1.0 if ml_prob is not None else 0.85), 2)

    return RiskResult(
        rule_score=rule_score, ml_probability=ml_prob, anomaly_score=anomaly,
        evidence_quality=eq, final_score=final, severity=severity_from_score(final),
        confidence=confidence,
    )
