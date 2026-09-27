"""
TLS handshake analysis + X.509 certificate extraction (sections 12-18).

Pipeline (per your spec, section 13):
  TLS bytes (post-STARTTLS, from the reassembled stream)
    -> TLS record/handshake parsing (scapy.layers.tls if available)
    -> Certificate handshake message -> DER bytes
    -> cryptography.x509.load_der_x509_certificate()
    -> structured metadata

No certificate is ever fabricated or fetched from the internet. If a field
isn't observed in the capture, it is reported as NOT_OBSERVED /
NOT_DETERMINED_FROM_AVAILABLE_EVIDENCE, never guessed.
"""
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import NameOID, ExtensionOID

from app.parsing.cipher_suites import lookup_cipher_suite
from app.parsing.chain_validation import verify_certificate_chain

TLS_VERSION_MAP = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",  # also used as legacy_version in TLS1.3 records
    0x0304: "TLS 1.3",
}


@dataclass
class CertificateInfo:
    chain_position: int
    subject: str
    issuer: str
    serial_number: str
    version: str
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    public_key_type: str
    public_key_size: Optional[int]
    signature_algorithm: str
    san: List[str] = field(default_factory=list)
    basic_constraints: Optional[dict] = None
    key_usage: Optional[dict] = None
    extended_key_usage: List[str] = field(default_factory=list)
    authority_key_identifier: Optional[str] = None
    subject_key_identifier: Optional[str] = None
    sha256_fingerprint: str = ""
    length_bytes: int = 0
    status: str = "UNABLE_TO_VALIDATE"
    revocation_status: str = "NOT_DETERMINED_FROM_PCAP"
    raw_der: bytes = b""
    # -- populated by app.parsing.chain_validation.verify_certificate_chain --
    chain_signature_verified: Optional[bool] = None  # was THIS cert's signature cryptographically verified?
    issuer_public_key_source: Optional[str] = None  # OBSERVED_IN_CAPTURE / LOCAL_TRUST_STORE / NOT_AVAILABLE
    chain_validation_status: Optional[str] = None  # leaf-only: overall chain verdict, see chain_validation.py
    chain_validation_detail: Optional[dict] = None  # leaf-only: what was checked, for the report/UI
    # -- populated by app.parsing.revocation.determine_revocation_status (opt-in) --
    revocation_checked_via: Optional[str] = None  # "OCSP" / "CRL" / None
    revocation_detail: Optional[dict] = None


@dataclass
class TlsHandshakeInfo:
    tls_version_offered: Optional[str] = None
    tls_version_negotiated: Optional[str] = None
    cipher_suite: Optional[str] = None
    cipher_suite_name: Optional[str] = None
    key_exchange: Optional[str] = None
    authentication: Optional[str] = None
    forward_secrecy: Optional[bool] = None
    sni: Optional[str] = None
    alpn: List[str] = field(default_factory=list)
    supported_groups: List[str] = field(default_factory=list)
    signature_algorithms: List[str] = field(default_factory=list)
    handshake_complete: bool = False
    alerts: List[dict] = field(default_factory=list)
    status: str = "NOT_OBSERVED"
    certificates: List[CertificateInfo] = field(default_factory=list)


def parse_der_certificate(der_bytes: bytes, chain_position: int) -> CertificateInfo:
    """Parse one DER-encoded certificate observed in the TLS Certificate message."""
    cert = x509.load_der_x509_certificate(der_bytes)

    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_type, key_size = "RSA", pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_type, key_size = f"EC ({pub_key.curve.name})", pub_key.key_size
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_type, key_size = "DSA", pub_key.key_size
    else:
        key_type, key_size = type(pub_key).__name__, None

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = [str(name.value) for name in san_ext.value]
    except x509.ExtensionNotFound:
        san = []

    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        basic_constraints = {"ca": bc.ca, "path_length": bc.path_length}
    except x509.ExtensionNotFound:
        basic_constraints = None

    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        key_usage = {
            "digital_signature": ku.digital_signature,
            "key_encipherment": ku.key_encipherment,
            "key_cert_sign": ku.key_cert_sign,
            "crl_sign": ku.crl_sign,
        }
    except x509.ExtensionNotFound:
        key_usage = None

    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        extended_key_usage = [oid._name or oid.dotted_string for oid in eku]
    except x509.ExtensionNotFound:
        extended_key_usage = []

    try:
        aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
        aki_str = aki.key_identifier.hex() if aki.key_identifier else None
    except x509.ExtensionNotFound:
        aki_str = None

    try:
        ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
        ski_str = ski.digest.hex()
    except x509.ExtensionNotFound:
        ski_str = None

    fingerprint = hashlib.sha256(der_bytes).hexdigest()

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    is_self_signed = subject == issuer

    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after

    now = datetime.now(timezone.utc)
    nb = not_before if not_before.tzinfo else not_before.replace(tzinfo=timezone.utc)
    na = not_after if not_after.tzinfo else not_after.replace(tzinfo=timezone.utc)

    if now < nb:
        status = "NOT_YET_VALID"
    elif now > na:
        status = "EXPIRED"
    elif is_self_signed:
        status = "SELF_SIGNED"
    else:
        status = "VALID"  # chain completeness re-evaluated at the chain level

    return CertificateInfo(
        chain_position=chain_position,
        subject=subject,
        issuer=issuer,
        serial_number=str(cert.serial_number),
        version=str(cert.version),
        not_before=nb,
        not_after=na,
        public_key_type=key_type,
        public_key_size=key_size,
        signature_algorithm=cert.signature_algorithm_oid._name,
        san=san,
        basic_constraints=basic_constraints,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        authority_key_identifier=aki_str,
        subject_key_identifier=ski_str,
        sha256_fingerprint=fingerprint,
        length_bytes=len(der_bytes),
        status=status,
        revocation_status="NOT_DETERMINED_FROM_PCAP",
        raw_der=der_bytes,
    )


def evaluate_chain(certs: List[CertificateInfo]) -> None:
    """First-pass, cheap issuer<->subject *string* match across observed
    certs. Kept as a fast pre-check; the real cryptographic verdict
    (signature verification against observed certs + local root CA
    store) comes from verify_certificate_chain() in chain_validation.py,
    which runs right after this and can correct an over-pessimistic
    CHAIN_ISSUE here once it proves the signature actually chains to a
    trusted root."""
    if not certs:
        return
    subjects = {c.subject for c in certs}
    leaf = certs[0]
    if leaf.issuer not in subjects and leaf.status == "VALID":
        leaf.status = "CHAIN_ISSUE"


def evaluate_hostname(sni: Optional[str], leaf_cert: Optional[CertificateInfo]) -> str:
    """Returns MATCH / MISMATCH / NO_HOSTNAME_EVIDENCE (section 17)."""
    if not sni or not leaf_cert:
        return "NO_HOSTNAME_EVIDENCE"
    candidates = set(leaf_cert.san)
    try:
        cn_attrs = x509.Name.from_rfc4514_string(leaf_cert.subject).get_attributes_for_oid(NameOID.COMMON_NAME)
        candidates.update(a.value for a in cn_attrs)
    except Exception:
        pass
    sni_l = sni.lower()
    for c in candidates:
        c_l = c.lower()
        if c_l == sni_l:
            return "MATCH"
        if c_l.startswith("*.") and sni_l.endswith(c_l[1:]):
            return "MATCH"
    return "MISMATCH" if candidates else "NO_HOSTNAME_EVIDENCE"


def parse_tls_records(post_starttls_client_bytes: bytes, post_starttls_server_bytes: bytes) -> TlsHandshakeInfo:
    """
    Best-effort pure-Python TLS record parser for the handshake metadata we
    need (version, cipher suite, SNI, ALPN, certificate messages). Falls
    back gracefully when scapy's TLS layer / a fuller parser is available
    in the deployment environment -- see PCAP_ANALYSIS.md for the
    TShark-based alternative extraction path used in production.
    """
    info = TlsHandshakeInfo()
    if not post_starttls_client_bytes and not post_starttls_server_bytes:
        info.status = "NOT_OBSERVED"
        return info

    info.status = "INCOMPLETE"

    def iter_records(buf: bytes):
        offset = 0
        while offset + 5 <= len(buf):
            content_type = buf[offset]
            version = (buf[offset + 1] << 8) | buf[offset + 2]
            length = (buf[offset + 3] << 8) | buf[offset + 4]
            body = buf[offset + 5: offset + 5 + length]
            if len(body) < length:
                break  # truncated capture
            yield content_type, version, body
            offset += 5 + length

    def parse_client_hello(body: bytes):
        try:
            idx = 0
            msg_type = body[idx]; idx += 1
            if msg_type != 1:
                return
            idx += 3  # length
            legacy_version = (body[idx] << 8) | body[idx + 1]
            info.tls_version_offered = TLS_VERSION_MAP.get(legacy_version, hex(legacy_version))
            idx += 2 + 32  # version + random
            sid_len = body[idx]; idx += 1 + sid_len
            cs_len = (body[idx] << 8) | body[idx + 1]; idx += 2 + cs_len
            comp_len = body[idx]; idx += 1 + comp_len
            if idx + 2 > len(body):
                return
            ext_total_len = (body[idx] << 8) | body[idx + 1]; idx += 2
            end = idx + ext_total_len
            while idx + 4 <= min(end, len(body)):
                ext_type = (body[idx] << 8) | body[idx + 1]
                ext_len = (body[idx + 2] << 8) | body[idx + 3]
                ext_data = body[idx + 4: idx + 4 + ext_len]
                if ext_type == 0 and len(ext_data) >= 5:  # server_name
                    name_len = (ext_data[3] << 8) | ext_data[4]
                    info.sni = ext_data[5:5 + name_len].decode("idna", errors="ignore")
                elif ext_type == 16:  # ALPN
                    p = 2
                    protos = []
                    while p < len(ext_data):
                        plen = ext_data[p]
                        protos.append(ext_data[p + 1: p + 1 + plen].decode("ascii", errors="ignore"))
                        p += 1 + plen
                    info.alpn = protos
                elif ext_type == 43:  # supported_versions (client)
                    pass
                idx += 4 + ext_len
        except (IndexError, UnicodeError):
            return  # malformed / truncated -- leave fields as NOT_OBSERVED

    def parse_server_hello(body: bytes):
        try:
            idx = 0
            msg_type = body[idx]; idx += 1
            if msg_type != 2:
                return
            idx += 3
            legacy_version = (body[idx] << 8) | body[idx + 1]
            idx += 2 + 32
            sid_len = body[idx]; idx += 1 + sid_len
            cipher = (body[idx] << 8) | body[idx + 1]; idx += 2
            info.cipher_suite = f"0x{cipher:04X}"
            cs_info = lookup_cipher_suite(info.cipher_suite)
            if cs_info:
                info.cipher_suite_name = cs_info.name
                info.key_exchange = cs_info.key_exchange
                info.authentication = cs_info.authentication
                info.forward_secrecy = cs_info.forward_secrecy
            idx += 1  # compression method
            negotiated = legacy_version
            if idx + 2 <= len(body):
                ext_total_len = (body[idx] << 8) | body[idx + 1]; idx += 2
                end = idx + ext_total_len
                while idx + 4 <= min(end, len(body)):
                    ext_type = (body[idx] << 8) | body[idx + 1]
                    ext_len = (body[idx + 2] << 8) | body[idx + 3]
                    ext_data = body[idx + 4: idx + 4 + ext_len]
                    if ext_type == 43 and len(ext_data) >= 2:  # supported_versions (server picks one)
                        negotiated = (ext_data[0] << 8) | ext_data[1]
                    idx += 4 + ext_len
            info.tls_version_negotiated = TLS_VERSION_MAP.get(negotiated, hex(negotiated))
        except (IndexError, UnicodeError):
            return

    def parse_certificate_message(body: bytes) -> List[bytes]:
        der_list = []
        try:
            idx = 0
            msg_type = body[idx]; idx += 1
            if msg_type != 11:
                return der_list
            idx += 3  # handshake length
            # TLS 1.3 adds a certificate_request_context length-prefixed field
            if idx < len(body):
                ctx_len = body[idx]
                if ctx_len < 32:  # heuristic: distinguishes TLS1.3 context from cert-list length byte
                    idx += 1 + ctx_len
            cert_list_len = (body[idx] << 8 << 8) | 0
            cert_list_len = (body[idx] << 16) | (body[idx + 1] << 8) | body[idx + 2]
            idx += 3
            end = idx + cert_list_len
            while idx + 3 <= min(end, len(body)):
                cert_len = (body[idx] << 16) | (body[idx + 1] << 8) | body[idx + 2]
                idx += 3
                cert_der = body[idx: idx + cert_len]
                if len(cert_der) < cert_len:
                    break  # truncated
                der_list.append(cert_der)
                idx += cert_len
                # TLS 1.3: each cert entry has trailing extensions (2-byte len)
                if idx + 2 <= len(body):
                    ext_len = (body[idx] << 8) | body[idx + 1]
                    if idx + 2 + ext_len <= end:
                        idx += 2 + ext_len
        except IndexError:
            pass
        return der_list

    for buf, is_client in ((post_starttls_client_bytes, True), (post_starttls_server_bytes, False)):
        for content_type, version, body in iter_records(buf):
            if content_type == 22:  # handshake
                if is_client:
                    parse_client_hello(body)
                else:
                    parse_server_hello(body)
                    if body and body[0] == 11:
                        chain_pos = 0
                        for der in parse_certificate_message(body):
                            try:
                                cert_info = parse_der_certificate(der, chain_pos)
                                info.certificates.append(cert_info)
                                chain_pos += 1
                            except Exception:
                                continue  # malformed cert bytes: skip, never fabricate
                    if body and body[0] == 20:
                        info.handshake_complete = True
            elif content_type == 21:  # alert
                if len(body) >= 2:
                    info.alerts.append({"level": body[0], "description": body[1]})

    if info.certificates:
        evaluate_chain(info.certificates)  # cheap issuer/subject string pass first
        verify_certificate_chain(info.certificates)  # then real cryptographic verification against local trust store

    if info.tls_version_negotiated or info.certificates:
        info.status = "OBSERVED"
    return info
