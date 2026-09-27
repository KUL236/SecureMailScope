"""
Deterministic cryptographic rule engine (section 19).

Each rule is a pure function: (session_context) -> Finding | None.
Rules never guess; if evidence is absent the rule simply does not fire
(the pipeline separately records NOT_OBSERVED status where relevant).
"""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import List, Optional

from app.config import RULE_VERSION

WEAK_RSA_BITS = 2048
LEGACY_SIG_ALGOS = {"md5WithRSAEncryption", "sha1WithRSAEncryption", "md5", "sha1"}
LEGACY_TLS_VERSIONS = {"TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0"}
WEAK_CIPHER_SUBSTRINGS = ("NULL", "EXPORT", "RC4", "DES", "3DES", "MD5")


@dataclass
class RuleFinding:
    rule_id: str
    title: str
    severity: str  # LOW/MEDIUM/HIGH/CRITICAL
    description: str
    observed_value: Optional[str]
    expected_value: Optional[str]
    confidence: float
    recommendation: str
    rule_version: str = RULE_VERSION

    def to_dict(self):
        return asdict(self)


def evaluate_rules(*, email_session=None, tls_info=None, network_session=None, hostname_status: str = None) -> List[RuleFinding]:
    findings: List[RuleFinding] = []

    # ---- Certificate rules ----
    leaf = tls_info.certificates[0] if (tls_info and tls_info.certificates) else None
    if leaf:
        if leaf.status == "EXPIRED":
            findings.append(RuleFinding(
                "CERT_EXPIRED", "Certificate Expired", "CRITICAL",
                "The leaf certificate's validity period had ended at capture time.",
                observed_value=f"not_after={leaf.not_after}", expected_value="not_after in the future",
                confidence=1.0, recommendation="Renew the server certificate immediately.",
            ))
        if leaf.status == "NOT_YET_VALID":
            findings.append(RuleFinding(
                "CERT_NOT_YET_VALID", "Certificate Not Yet Valid", "HIGH",
                "The certificate's not_before date is in the future relative to capture/analysis time.",
                observed_value=f"not_before={leaf.not_before}", expected_value="not_before in the past",
                confidence=1.0, recommendation="Verify server and client clock synchronization and certificate issuance date.",
            ))
        if leaf.status == "SELF_SIGNED":
            findings.append(RuleFinding(
                "CERT_SELF_SIGNED", "Self-Signed Certificate", "MEDIUM",
                "Certificate subject and issuer are identical, indicating a self-signed certificate.",
                observed_value=f"subject=issuer={leaf.subject}", expected_value="issuer is a trusted CA",
                confidence=1.0, recommendation="Use a certificate issued by a trusted CA for production mail servers.",
            ))
        if leaf.status == "CHAIN_ISSUE":
            findings.append(RuleFinding(
                "CERT_CHAIN_INCOMPLETE", "Incomplete Certificate Chain", "HIGH",
                "The issuer of the leaf certificate was not observed among the certificates presented in the "
                "handshake, and no matching trusted root was found locally to verify the signature against.",
                observed_value=f"issuer={leaf.issuer}", expected_value="issuing intermediate/root present in chain",
                confidence=0.9, recommendation="Configure the server to send the full intermediate chain.",
            ))
        if leaf.status == "CHAIN_SIGNATURE_INVALID" or getattr(leaf, "chain_validation_status", None) == "CHAIN_SIGNATURE_INVALID":
            findings.append(RuleFinding(
                "CERT_CHAIN_SIGNATURE_INVALID", "Certificate Chain Signature Verification Failed", "CRITICAL",
                "A certificate's signature did not cryptographically verify against its stated issuer's public "
                "key (either another certificate observed in this handshake, or a matching root in the local "
                "trust store). This is inconsistent with a normal PKI chain and warrants investigation as a "
                "possible interception or certificate substitution.",
                observed_value=f"chain_validation_detail={getattr(leaf, 'chain_validation_detail', None)}",
                expected_value="every signature in the chain verifies against its issuer's public key",
                confidence=0.95, recommendation="Treat this session as untrusted; capture and compare against "
                "the certificate the server presents from a known-clean vantage point.",
            ))
        if getattr(leaf, "chain_validation_status", None) == "CHAIN_SELF_SIGNED_UNTRUSTED_ROOT":
            findings.append(RuleFinding(
                "CERT_UNTRUSTED_ROOT", "Self-Signed Root Not in Trust Store", "MEDIUM",
                "The top-most certificate observed is self-signed and does not match any root in the local "
                "trust store (checked by SHA-256 fingerprint, not just subject name).",
                observed_value=f"subject={leaf.subject}" if leaf.chain_position == 0 else None,
                expected_value="root certificate matches a known, trusted CA",
                confidence=0.85, recommendation="Confirm this is an intentional private/internal CA deployment.",
            ))
        if getattr(leaf, "revocation_status", None) in ("REVOKED_OCSP", "REVOKED_CRL"):
            findings.append(RuleFinding(
                "CERT_REVOKED", "Certificate Revoked", "CRITICAL",
                f"A live revocation check ({getattr(leaf, 'revocation_checked_via', None)}) reported this "
                "certificate as revoked.",
                observed_value=f"revocation_status={leaf.revocation_status}",
                expected_value="revocation status GOOD",
                confidence=0.98, recommendation="Treat this session as compromised; the certificate's issuing "
                "CA has revoked it.",
            ))
        if leaf.public_key_type == "RSA" and leaf.public_key_size and leaf.public_key_size < WEAK_RSA_BITS:
            findings.append(RuleFinding(
                "WEAK_KEY_SIZE", "Weak Public Key Size", "HIGH",
                f"RSA key size of {leaf.public_key_size} bits is below the recommended minimum of {WEAK_RSA_BITS}.",
                observed_value=str(leaf.public_key_size), expected_value=f">= {WEAK_RSA_BITS}",
                confidence=1.0, recommendation="Reissue the certificate with an RSA key >= 2048 bits or move to ECDSA.",
            ))
        sig_algo = (leaf.signature_algorithm or "").lower()
        if any(legacy in sig_algo for legacy in ("md5", "sha1")):
            findings.append(RuleFinding(
                "LEGACY_SIGNATURE_ALGORITHM", "Legacy Signature Algorithm", "HIGH",
                f"Certificate is signed using {leaf.signature_algorithm}, considered cryptographically weak.",
                observed_value=leaf.signature_algorithm, expected_value="sha256WithRSAEncryption or stronger",
                confidence=1.0, recommendation="Reissue the certificate using SHA-256 or stronger.",
            ))

    if hostname_status == "MISMATCH":
        findings.append(RuleFinding(
            "CERT_HOSTNAME_MISMATCH", "Certificate Hostname Mismatch", "HIGH",
            "The SNI hostname requested by the client does not match any SAN/CN entry on the presented certificate.",
            observed_value="SNI vs SAN/CN mismatch", expected_value="SNI present in certificate SAN/CN",
            confidence=0.85, recommendation="Ensure the certificate's SAN list covers all hostnames served.",
        ))

    # ---- TLS rules ----
    if tls_info:
        neg = tls_info.tls_version_negotiated
        if neg in LEGACY_TLS_VERSIONS:
            findings.append(RuleFinding(
                "LEGACY_TLS_VERSION", "Legacy TLS Version Negotiated", "HIGH",
                f"The session negotiated {neg}, which is deprecated.",
                observed_value=neg, expected_value="TLS 1.2 or TLS 1.3",
                confidence=1.0, recommendation="Disable legacy TLS versions on the mail server.",
            ))
        if tls_info.cipher_suite and any(w in tls_info.cipher_suite.upper() for w in WEAK_CIPHER_SUBSTRINGS):
            findings.append(RuleFinding(
                "WEAK_CIPHER", "Weak Cipher Suite Negotiated", "HIGH",
                f"Negotiated cipher suite {tls_info.cipher_suite} is considered weak.",
                observed_value=tls_info.cipher_suite, expected_value="AEAD cipher suite (e.g. AES-GCM, ChaCha20-Poly1305)",
                confidence=0.8, recommendation="Restrict server cipher suite configuration to modern AEAD ciphers.",
            ))
        if tls_info.forward_secrecy is False:
            findings.append(RuleFinding(
                "NO_FORWARD_SECRECY", "No Forward Secrecy", "MEDIUM",
                f"The negotiated cipher suite ({tls_info.cipher_suite_name or tls_info.cipher_suite}) uses "
                f"static key exchange ({tls_info.key_exchange}), so a future compromise of the server's "
                f"private key would let an attacker decrypt this recorded session.",
                observed_value=tls_info.key_exchange, expected_value="ECDHE or DHE (ephemeral key exchange)",
                confidence=0.9, recommendation="Disable static RSA key exchange cipher suites; require ECDHE/DHE-only configuration.",
            ))
        if tls_info.status == "INCOMPLETE" or (tls_info.status == "OBSERVED" and not tls_info.handshake_complete):
            findings.append(RuleFinding(
                "TLS_HANDSHAKE_INCOMPLETE", "TLS Handshake Incomplete", "MEDIUM",
                "The TLS handshake did not reach a Finished message within the captured traffic.",
                observed_value=tls_info.status, expected_value="handshake_complete = True",
                confidence=0.7, recommendation="Recapture with full session duration to confirm handshake outcome.",
            ))
        for alert in (tls_info.alerts or []):
            if alert.get("level") == 2:  # fatal
                findings.append(RuleFinding(
                    "UNEXPECTED_CRYPTO_CONFIGURATION", "Fatal TLS Alert Observed", "MEDIUM",
                    f"A fatal TLS alert (description code {alert.get('description')}) was observed.",
                    observed_value=str(alert), expected_value="no fatal alerts",
                    confidence=0.9, recommendation="Investigate server/client TLS configuration compatibility.",
                ))

    # ---- STARTTLS rules ----
    if email_session:
        if email_session.state.value == "STARTTLS_REJECTED":
            findings.append(RuleFinding(
                "STARTTLS_REJECTED", "STARTTLS Rejected by Server", "HIGH",
                "The client requested STARTTLS but the server rejected the request, leaving the session in plaintext.",
                observed_value="STARTTLS rejected", expected_value="STARTTLS accepted (220 response)",
                confidence=1.0, recommendation="Verify server TLS configuration and certificate availability.",
            ))
        elif email_session.protocol == "SMTP" and not email_session.starttls_offered:
            findings.append(RuleFinding(
                "STARTTLS_NOT_OBSERVED", "STARTTLS Not Offered", "MEDIUM",
                "The server's EHLO response did not advertise STARTTLS capability in the observed session.",
                observed_value="STARTTLS absent from capabilities", expected_value="STARTTLS advertised",
                confidence=0.8, recommendation="Enable STARTTLS on the mail server to support opportunistic encryption.",
            ))

    # ---- Session-level anomaly ----
    if network_session and not network_session.is_complete:
        findings.append(RuleFinding(
            "SESSION_ANOMALY", "Incomplete TCP Capture", "LOW",
            network_session.completeness_note or "TCP stream did not show a complete handshake/teardown.",
            observed_value=network_session.completeness_note, expected_value="complete SYN..FIN/RST sequence",
            confidence=0.6, recommendation="Recapture ensuring the full session lifetime is included.",
        ))

    return findings
