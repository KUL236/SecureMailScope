"""
Feature engineering (section 20). Versioned; missing values are explicit
None, never fabricated defaults -- the ML layer handles None via imputation
it can justify (see ml/train.py), not this module.
"""
from datetime import datetime, timezone
from typing import Optional

from app.config import FEATURE_VERSION

KEY_TYPE_MAP = {"RSA": 1, "EC (secp256r1)": 2, "DSA": 3}


def build_feature_vector(*, network_session, email_session, tls_info) -> dict:
    leaf = tls_info.certificates[0] if (tls_info and tls_info.certificates) else None

    cert_age_days = None
    cert_remaining_days = None
    cert_validity_days = None
    if leaf and leaf.not_before and leaf.not_after:
        now = datetime.now(timezone.utc)
        cert_age_days = (now - leaf.not_before).days
        cert_remaining_days = (leaf.not_after - now).days
        cert_validity_days = (leaf.not_after - leaf.not_before).days

    features = {
        "protocol": email_session.protocol if email_session else None,
        "tls_version": tls_info.tls_version_negotiated if tls_info else None,
        "cipher_suite": tls_info.cipher_suite if tls_info else None,
        "key_exchange": tls_info.key_exchange if tls_info else None,
        "forward_secrecy": tls_info.forward_secrecy if tls_info else None,
        "certificate_age_days": cert_age_days,
        "certificate_remaining_days": cert_remaining_days,
        "certificate_validity_days": cert_validity_days,
        "certificate_key_type": leaf.public_key_type if leaf else None,
        "certificate_key_size": leaf.public_key_size if leaf else None,
        "signature_algorithm": leaf.signature_algorithm if leaf else None,
        "chain_depth": len(tls_info.certificates) if tls_info else 0,
        "san_count": len(leaf.san) if leaf else None,
        "expired": (leaf.status == "EXPIRED") if leaf else None,
        "not_yet_valid": (leaf.status == "NOT_YET_VALID") if leaf else None,
        "self_signed": (leaf.status == "SELF_SIGNED") if leaf else None,
        "chain_issue": (leaf.status == "CHAIN_ISSUE") if leaf else None,
        "starttls_offered": email_session.starttls_offered if email_session else None,
        "starttls_requested": email_session.starttls_requested if email_session else None,
        "starttls_accepted": email_session.starttls_accepted if email_session else None,
        "tls_handshake_complete": tls_info.handshake_complete if tls_info else None,
        "packet_count": network_session.packet_count if network_session else None,
        "session_duration_s": (
            (network_session.end_time - network_session.start_time).total_seconds()
            if network_session and network_session.start_time and network_session.end_time else None
        ),
        "retransmission_ratio": (
            network_session.retransmission_count / network_session.packet_count
            if network_session and network_session.packet_count else None
        ),
        "stream_complete": network_session.is_complete if network_session else None,
        "feature_version": FEATURE_VERSION,
    }
    return features
