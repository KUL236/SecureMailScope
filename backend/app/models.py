"""
Database schema for SecureMailScope.

Tables: users, roles, user_roles, investigations, pcaps, network_sessions,
email_sessions, tls_handshakes, certificates, certificate_chain_links,
findings, evidence, features, model_runs, risk_scores, reports, audit_logs.
"""
import uuid
import enum
from datetime import datetime

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text,
    JSON, Enum, LargeBinary, Table
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


def gen_uuid():
    return str(uuid.uuid4())


# ---------------------------------------------------------------- Auth ----

user_roles = Table(
    "user_roles", Base.metadata,
    Column("user_id", UUID(as_uuid=False), ForeignKey("users.id"), primary_key=True),
    Column("role_id", UUID(as_uuid=False), ForeignKey("roles.id"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=False)
    full_name = Column(String(256), nullable=True)
    password_hash = Column(String(256), nullable=False)  # Argon2id
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    roles = relationship("Role", secondary=user_roles, back_populates="users")


class Role(Base):
    __tablename__ = "roles"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String(64), unique=True, nullable=False)  # e.g. admin, analyst, viewer
    users = relationship("User", secondary=user_roles, back_populates="roles")


# ---------------------------------------------------------- Investigation ----

class InvestigationStatus(str, enum.Enum):
    UPLOADED = "UPLOADED"
    VALIDATING = "VALIDATING"
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class Investigation(Base):
    __tablename__ = "investigations"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    title = Column(String(256), nullable=False)
    status = Column(Enum(InvestigationStatus), default=InvestigationStatus.UPLOADED)
    created_by = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_demo = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)
    # Real, granular pipeline checkpoint -- set only when that stage actually
    # finishes in app/pipeline.py. Never advanced by a timer. One of:
    # VALIDATING_PCAP, EXTRACTING_PACKETS, RECONSTRUCTING_STREAMS,
    # IDENTIFYING_PROTOCOLS, ANALYZING_STARTTLS, ANALYZING_TLS,
    # EXTRACTING_CERTIFICATES, EVALUATING_RULES, SCORING_RISK,
    # PREPARING_REPORT, DONE.
    current_stage = Column(String(64), nullable=True)

    pcap = relationship("Pcap", back_populates="investigation", uselist=False)
    findings = relationship("Finding", back_populates="investigation")
    reports = relationship("Report", back_populates="investigation")


class Pcap(Base):
    __tablename__ = "pcaps"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    investigation_id = Column(UUID(as_uuid=False), ForeignKey("investigations.id"), nullable=False)
    filename = Column(String(512), nullable=False)
    stored_path = Column(String(1024), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    upload_time = Column(DateTime, default=datetime.utcnow)
    capture_start = Column(DateTime, nullable=True)
    capture_end = Column(DateTime, nullable=True)
    packet_count = Column(Integer, nullable=True)
    parser_version = Column(String(32), nullable=False)
    analysis_version = Column(String(32), nullable=False)
    is_valid = Column(Boolean, default=True)
    validation_error = Column(Text, nullable=True)

    investigation = relationship("Investigation", back_populates="pcap")


# ------------------------------------------------------------- Sessions ----

class NetworkSession(Base):
    """TCP-level reconstructed stream."""
    __tablename__ = "network_sessions"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    investigation_id = Column(UUID(as_uuid=False), ForeignKey("investigations.id"), nullable=False)
    src_ip = Column(String(64))
    dst_ip = Column(String(64))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    is_complete = Column(Boolean, default=True)  # False if SYN/FIN missing etc.
    completeness_note = Column(String(256), nullable=True)
    retransmission_count = Column(Integer, default=0)
    protocol_guess = Column(String(16), nullable=True)  # SMTP / IMAP / POP3 / UNKNOWN
    protocol_confidence = Column(Float, default=0.0)

    email_session = relationship("EmailSession", back_populates="network_session", uselist=False)
    tls_handshake = relationship("TlsHandshake", back_populates="network_session", uselist=False)


class EmailSession(Base):
    __tablename__ = "email_sessions"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    network_session_id = Column(UUID(as_uuid=False), ForeignKey("network_sessions.id"), nullable=False)
    protocol = Column(String(16))  # SMTP/IMAP/POP3
    server_greeting = Column(Text, nullable=True)
    ehlo_helo_command = Column(Text, nullable=True)
    capabilities = Column(JSON, nullable=True)  # list of advertised capabilities
    starttls_state = Column(String(32), default="NOT_OBSERVED")
    starttls_offered = Column(Boolean, default=False)
    starttls_requested = Column(Boolean, default=False)
    starttls_accepted = Column(Boolean, default=False)
    starttls_timeline = Column(JSON, nullable=True)  # ordered list of {ts, event, packet_no}

    network_session = relationship("NetworkSession", back_populates="email_session")


# ----------------------------------------------------------------- TLS ----

class TlsHandshake(Base):
    __tablename__ = "tls_handshakes"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    network_session_id = Column(UUID(as_uuid=False), ForeignKey("network_sessions.id"), nullable=False)
    tls_version_offered = Column(String(16), nullable=True)   # from ClientHello
    tls_version_negotiated = Column(String(16), nullable=True)  # from ServerHello
    cipher_suite = Column(String(128), nullable=True)
    cipher_suite_name = Column(String(128), nullable=True)
    key_exchange = Column(String(32), nullable=True)  # ECDHE / DHE / RSA / UNKNOWN
    authentication = Column(String(32), nullable=True)
    forward_secrecy = Column(Boolean, nullable=True)  # None = not determined (unknown cipher/no handshake)
    sni = Column(String(256), nullable=True)
    alpn = Column(JSON, nullable=True)
    supported_groups = Column(JSON, nullable=True)
    signature_algorithms = Column(JSON, nullable=True)
    handshake_complete = Column(Boolean, default=False)
    alerts = Column(JSON, nullable=True)  # list of {level, description}
    status = Column(String(32), default="NOT_OBSERVED")  # OBSERVED/NOT_OBSERVED/INCOMPLETE

    network_session = relationship("NetworkSession", back_populates="tls_handshake")
    certificates = relationship("Certificate", back_populates="tls_handshake", order_by="Certificate.chain_position")


class Certificate(Base):
    __tablename__ = "certificates"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    tls_handshake_id = Column(UUID(as_uuid=False), ForeignKey("tls_handshakes.id"), nullable=False)
    chain_position = Column(Integer, default=0)  # 0 = leaf
    subject = Column(Text, nullable=True)
    issuer = Column(Text, nullable=True)
    serial_number = Column(String(128), nullable=True)
    version = Column(String(16), nullable=True)
    not_before = Column(DateTime, nullable=True)
    not_after = Column(DateTime, nullable=True)
    public_key_type = Column(String(32), nullable=True)
    public_key_size = Column(Integer, nullable=True)
    signature_algorithm = Column(String(128), nullable=True)
    san = Column(JSON, nullable=True)
    basic_constraints = Column(JSON, nullable=True)
    key_usage = Column(JSON, nullable=True)
    extended_key_usage = Column(JSON, nullable=True)
    authority_key_identifier = Column(String(256), nullable=True)
    subject_key_identifier = Column(String(256), nullable=True)
    sha256_fingerprint = Column(String(64), nullable=True, index=True)
    length_bytes = Column(Integer, nullable=True)
    status = Column(String(32), nullable=True)  # VALID/EXPIRED/NOT_YET_VALID/SELF_SIGNED/...
    revocation_status = Column(String(64), default="NOT_DETERMINED_FROM_PCAP")
    raw_der = Column(LargeBinary, nullable=True)

    # -- cryptographic chain verification (app/parsing/chain_validation.py) --
    chain_signature_verified = Column(Boolean, nullable=True)  # was this cert's own signature verified?
    issuer_public_key_source = Column(String(32), nullable=True)  # OBSERVED_IN_CAPTURE/LOCAL_TRUST_STORE/NOT_AVAILABLE
    chain_validation_status = Column(String(48), nullable=True)  # leaf-only overall verdict
    chain_validation_detail = Column(JSON, nullable=True)  # leaf-only: what was checked

    # -- revocation (app/parsing/revocation.py), opt-in via ENABLE_LIVE_REVOCATION_CHECKS --
    revocation_checked_via = Column(String(16), nullable=True)  # "OCSP" / "CRL" / None
    revocation_detail = Column(JSON, nullable=True)

    tls_handshake = relationship("TlsHandshake", back_populates="certificates")


class CertificateChainLink(Base):
    __tablename__ = "certificate_chain_links"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    tls_handshake_id = Column(UUID(as_uuid=False), ForeignKey("tls_handshakes.id"), nullable=False)
    child_certificate_id = Column(UUID(as_uuid=False), ForeignKey("certificates.id"), nullable=False)
    parent_certificate_id = Column(UUID(as_uuid=False), ForeignKey("certificates.id"), nullable=True)
    link_type = Column(String(32), default="OBSERVED")  # OBSERVED vs EXPECTED_EXTERNAL


# ------------------------------------------------------------- Findings ----

class Finding(Base):
    __tablename__ = "findings"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    investigation_id = Column(UUID(as_uuid=False), ForeignKey("investigations.id"), nullable=False)
    network_session_id = Column(UUID(as_uuid=False), ForeignKey("network_sessions.id"), nullable=True)
    rule_id = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=False)  # LOW/MEDIUM/HIGH/CRITICAL
    observed_value = Column(Text, nullable=True)
    expected_value = Column(Text, nullable=True)
    confidence = Column(Float, default=1.0)
    recommendation = Column(Text, nullable=True)
    rule_version = Column(String(32), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="findings")
    evidence = relationship("Evidence", back_populates="finding")


class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id"), nullable=False)
    pcap_sha256 = Column(String(64), nullable=False)
    network_session_id = Column(UUID(as_uuid=False), ForeignKey("network_sessions.id"), nullable=True)
    packet_number = Column(Integer, nullable=True)
    packet_range_start = Column(Integer, nullable=True)
    packet_range_end = Column(Integer, nullable=True)
    timestamp = Column(DateTime, nullable=True)
    protocol = Column(String(16), nullable=True)
    field_name = Column(String(128), nullable=True)
    observed_value = Column(Text, nullable=True)
    parser_version = Column(String(32), nullable=True)
    rule_version = Column(String(32), nullable=True)
    model_version = Column(String(32), nullable=True)

    finding = relationship("Finding", back_populates="evidence")


# --------------------------------------------------------- ML / Risk ----

class FeatureSet(Base):
    __tablename__ = "features"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    network_session_id = Column(UUID(as_uuid=False), ForeignKey("network_sessions.id"), nullable=False)
    feature_version = Column(String(32), nullable=False)
    values = Column(JSON, nullable=False)  # {feature_name: value}, explicit None for missing


class ModelRun(Base):
    __tablename__ = "model_runs"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    network_session_id = Column(UUID(as_uuid=False), ForeignKey("network_sessions.id"), nullable=False)
    model_version = Column(String(32), nullable=False)
    model_name = Column(String(64), nullable=False)  # xgboost/random_forest/logreg/isolation_forest
    probability = Column(Float, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    top_contributors = Column(JSON, nullable=True)  # [{feature, contribution}]
    created_at = Column(DateTime, default=datetime.utcnow)


class RiskScore(Base):
    __tablename__ = "risk_scores"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    network_session_id = Column(UUID(as_uuid=False), ForeignKey("network_sessions.id"), nullable=False)
    rule_score = Column(Float, default=0.0)
    ml_probability = Column(Float, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    evidence_quality = Column(Float, default=1.0)
    final_score = Column(Float, nullable=False)
    severity = Column(String(16), nullable=False)
    confidence = Column(Float, default=1.0)
    policy_version = Column(String(32), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Report(Base):
    __tablename__ = "reports"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    investigation_id = Column(UUID(as_uuid=False), ForeignKey("investigations.id"), nullable=False)
    format = Column(String(8), nullable=False)  # PDF/JSON/HTML
    stored_path = Column(String(1024), nullable=True)
    generated_at = Column(DateTime, default=datetime.utcnow)
    software_version = Column(String(32), nullable=False)
    model_version = Column(String(32), nullable=False)
    feature_version = Column(String(32), nullable=False)
    rule_version = Column(String(32), nullable=False)

    investigation = relationship("Investigation", back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    action = Column(String(128), nullable=False)
    target_type = Column(String(64), nullable=True)
    target_id = Column(String(64), nullable=True)
    detail = Column(JSON, nullable=True)
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
