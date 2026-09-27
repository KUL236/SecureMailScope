"""
Cryptographic PKI chain validation (closes the gap flagged in
docs/CERTIFICATE_ANALYSIS.md: evaluate_chain() in tls_x509.py only ever
did issuer/subject *string* matching across observed certificates -- it
never verified a signature and never consulted a root store).

What this module adds, in order of increasing trust:

1. Signature verification between consecutive certificates actually
   observed in the capture (leaf signed by intermediate, intermediate
   signed by the next cert up), using each issuer's real public key --
   not just a name match.
2. If the top-most certificate observed in the capture is NOT
   self-signed, its issuer is looked up by subject name in a local root
   CA trust store (Mozilla's bundle, via `certifi`) and, if found, the
   signature is verified against that root's real public key. This is
   the common real-world case: servers send leaf + intermediate(s) but
   omit the root, exactly as RFC 8446 / RFC 5246 expect them to.
3. If the top-most certificate IS self-signed, we check whether it is
   itself a known root (matched by SHA-256 fingerprint against the
   trust store) rather than just trusting "subject == issuer".

What this module deliberately still does NOT do (see revocation.py for
the separate, explicitly-opt-in revocation piece):
  - OCSP/CRL revocation checking (that's revocation.py)
  - Policy/name-constraint/EKU chain-building beyond simple linear chains
  - Anything that requires network access unless the caller passed a
    trust store; loading the trust store itself is local-file-only.

Every result is a factual, falsifiable statement about what was
cryptographically demonstrated from the bytes actually present (plus,
optionally, the local trust store) -- never an assumption.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("securemailscope.chain_validation")

# Statuses for CertificateInfo.chain_signature_verified / provenance
SOURCE_OBSERVED_IN_CAPTURE = "OBSERVED_IN_CAPTURE"
SOURCE_LOCAL_TRUST_STORE = "LOCAL_TRUST_STORE"
SOURCE_NOT_AVAILABLE = "NOT_AVAILABLE"

# Overall chain-level verdicts (set on the leaf only, mirroring the
# existing evaluate_chain() convention of annotating leaf.status)
CHAIN_VALID_TRUSTED_ROOT = "CHAIN_VALID_TRUSTED_ROOT"
CHAIN_VALID_SELF_SIGNED_ROOT_TRUSTED = "CHAIN_VALID_SELF_SIGNED_ROOT_TRUSTED"
CHAIN_SIGNATURE_INVALID = "CHAIN_SIGNATURE_INVALID"
CHAIN_INCOMPLETE_NO_TRUST_ANCHOR = "CHAIN_INCOMPLETE_NO_TRUST_ANCHOR"
CHAIN_SELF_SIGNED_UNTRUSTED_ROOT = "CHAIN_SELF_SIGNED_UNTRUSTED_ROOT"
CHAIN_VALIDATION_ERROR = "CHAIN_VALIDATION_ERROR"


@dataclass
class TrustStore:
    """Root CAs indexed for lookup. Loaded once from a local PEM bundle
    (never fetched over the network -- see load_default_trust_store)."""
    by_subject: Dict[str, List[x509.Certificate]] = field(default_factory=dict)
    by_fingerprint: Dict[str, x509.Certificate] = field(default_factory=dict)
    source_path: Optional[str] = None
    count: int = 0

    def find_by_subject(self, subject_rfc4514: str) -> List[x509.Certificate]:
        return self.by_subject.get(subject_rfc4514, [])

    def find_by_fingerprint(self, sha256_hex: str) -> Optional[x509.Certificate]:
        return self.by_fingerprint.get(sha256_hex)


_default_trust_store: Optional[TrustStore] = None


def load_default_trust_store() -> TrustStore:
    """Loads Mozilla's root CA bundle shipped by the `certifi` package
    (a static file on disk -- no network access at load time). Cached
    process-wide after first load."""
    global _default_trust_store
    if _default_trust_store is not None:
        return _default_trust_store

    import hashlib
    from cryptography.hazmat.primitives.serialization import Encoding

    store = TrustStore()
    try:
        import certifi
        path = certifi.where()
        with open(path, "rb") as f:
            pem_data = f.read()
        for cert in x509.load_pem_x509_certificates(pem_data):
            subject = cert.subject.rfc4514_string()
            store.by_subject.setdefault(subject, []).append(cert)
            der = cert.public_bytes(encoding=Encoding.DER)
            fp = hashlib.sha256(der).hexdigest()
            store.by_fingerprint[fp] = cert
            store.count += 1
        store.source_path = path
    except Exception:  # pragma: no cover - defensive: app must run without a trust store too
        logger.exception("Failed to load default trust store; chain validation will report NOT_AVAILABLE")
        store = TrustStore()

    _default_trust_store = store
    return store


def _verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Cryptographically verify that `issuer`'s private key produced
    `child`'s signature. Returns False (never raises) on mismatch,
    unsupported algorithm, or any other verification failure -- this is
    a yes/no cryptographic fact, not a best-effort heuristic."""
    try:
        child.verify_directly_issued_by(issuer)
        return True
    except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm):
        return False
    except Exception:  # pragma: no cover
        logger.exception("Unexpected error during signature verification")
        return False


def verify_certificate_chain(certs: List, trust_store: Optional[TrustStore] = None) -> dict:
    """
    Mutates the given list of CertificateInfo objects (chain_position 0 =
    leaf, as produced by tls_x509.parse_der_certificate) in place:

      - each cert gets `.chain_signature_verified` (True/False/None) and
        `.issuer_public_key_source` (one of the SOURCE_* constants)
      - the leaf (chain_position 0) gets `.chain_validation_status` set
        to one of the CHAIN_* constants above, plus `.chain_validation_detail`
        (a dict safe to store as JSON) describing exactly what was checked.

    Returns the same detail dict that's attached to the leaf, for
    convenience. Never raises -- a failure to determine something is
    reported as such, not thrown.
    """
    detail = {
        "links_checked": [],
        "trust_anchor_subject": None,
        "trust_anchor_source": None,
    }
    if not certs:
        return detail

    if trust_store is None:
        trust_store = load_default_trust_store()

    try:
        x509_objs = []
        for c in certs:
            if not getattr(c, "raw_der", None):
                x509_objs.append(None)
                continue
            try:
                x509_objs.append(x509.load_der_x509_certificate(c.raw_der))
            except Exception:
                x509_objs.append(None)

        n = len(certs)

        # 1. Verify each observed link: cert[i] signed by cert[i+1]
        for i in range(n - 1):
            child_x, issuer_x = x509_objs[i], x509_objs[i + 1]
            if child_x is None or issuer_x is None:
                certs[i].chain_signature_verified = None
                certs[i].issuer_public_key_source = SOURCE_NOT_AVAILABLE
                continue
            verified = _verify_signature(child_x, issuer_x)
            certs[i].chain_signature_verified = verified
            certs[i].issuer_public_key_source = SOURCE_OBSERVED_IN_CAPTURE
            detail["links_checked"].append({
                "child_subject": certs[i].subject,
                "issuer_subject": certs[i + 1].subject,
                "source": SOURCE_OBSERVED_IN_CAPTURE,
                "signature_verified": verified,
            })
            if not verified:
                _finalize(certs, detail, CHAIN_SIGNATURE_INVALID)
                return detail

        top = certs[n - 1]
        top_x = x509_objs[n - 1]
        if top_x is None:
            top.chain_signature_verified = None
            top.issuer_public_key_source = SOURCE_NOT_AVAILABLE
            _finalize(certs, detail, CHAIN_VALIDATION_ERROR)
            return detail

        is_self_signed = top.subject == top.issuer

        if is_self_signed:
            # Self-signed top-of-chain: only "trusted" if it matches a
            # known root by fingerprint, never just by subject==issuer.
            anchor = trust_store.find_by_fingerprint(top.sha256_fingerprint)
            self_sig_ok = _verify_signature(top_x, top_x)
            top.chain_signature_verified = self_sig_ok
            top.issuer_public_key_source = SOURCE_OBSERVED_IN_CAPTURE
            if anchor is not None and self_sig_ok:
                detail["trust_anchor_subject"] = top.subject
                detail["trust_anchor_source"] = SOURCE_LOCAL_TRUST_STORE
                detail["links_checked"].append({
                    "child_subject": top.subject, "issuer_subject": top.subject,
                    "source": SOURCE_LOCAL_TRUST_STORE, "signature_verified": self_sig_ok,
                    "note": "self-signed root matched local trust store by SHA-256 fingerprint",
                })
                _finalize(certs, detail, CHAIN_VALID_SELF_SIGNED_ROOT_TRUSTED)
            elif not self_sig_ok:
                _finalize(certs, detail, CHAIN_SIGNATURE_INVALID)
            else:
                _finalize(certs, detail, CHAIN_SELF_SIGNED_UNTRUSTED_ROOT)
            return detail

        # Top of observed chain is NOT self-signed: its issuer is
        # missing from the capture. Look it up in the local trust store.
        candidates = trust_store.find_by_subject(top.issuer)
        matched_root = None
        for candidate in candidates:
            if _verify_signature(top_x, candidate):
                matched_root = candidate
                break

        if matched_root is not None:
            import hashlib
            from cryptography.hazmat.primitives.serialization import Encoding
            top.chain_signature_verified = True
            top.issuer_public_key_source = SOURCE_LOCAL_TRUST_STORE
            root_fp = hashlib.sha256(matched_root.public_bytes(Encoding.DER)).hexdigest()
            detail["trust_anchor_subject"] = matched_root.subject.rfc4514_string()
            detail["trust_anchor_source"] = SOURCE_LOCAL_TRUST_STORE
            detail["links_checked"].append({
                "child_subject": top.subject, "issuer_subject": top.issuer,
                "source": SOURCE_LOCAL_TRUST_STORE, "signature_verified": True,
                "trust_anchor_fingerprint_sha256": root_fp,
            })
            _finalize(certs, detail, CHAIN_VALID_TRUSTED_ROOT)
        elif candidates:
            # A CA with a matching subject name exists locally but the
            # signature didn't verify against it -- that's a real
            # cryptographic mismatch, not just an incomplete chain.
            top.chain_signature_verified = False
            top.issuer_public_key_source = SOURCE_LOCAL_TRUST_STORE
            detail["links_checked"].append({
                "child_subject": top.subject, "issuer_subject": top.issuer,
                "source": SOURCE_LOCAL_TRUST_STORE, "signature_verified": False,
            })
            _finalize(certs, detail, CHAIN_SIGNATURE_INVALID)
        else:
            top.chain_signature_verified = None
            top.issuer_public_key_source = SOURCE_NOT_AVAILABLE
            detail["links_checked"].append({
                "child_subject": top.subject, "issuer_subject": top.issuer,
                "source": SOURCE_NOT_AVAILABLE, "signature_verified": None,
                "note": "issuer not observed in capture and not found in local trust store",
            })
            _finalize(certs, detail, CHAIN_INCOMPLETE_NO_TRUST_ANCHOR)

        return detail

    except Exception:  # pragma: no cover - chain validation must never crash the pipeline
        logger.exception("Unexpected error during chain validation")
        _finalize(certs, detail, CHAIN_VALIDATION_ERROR)
        return detail


def _finalize(certs: List, detail: dict, status: str) -> None:
    leaf = certs[0]
    leaf.chain_validation_status = status
    leaf.chain_validation_detail = detail
    # Keep the legacy coarse `status` field consistent with the richer
    # cryptographic verdict computed here.
    if status in (CHAIN_SIGNATURE_INVALID, CHAIN_INCOMPLETE_NO_TRUST_ANCHOR,
                  CHAIN_SELF_SIGNED_UNTRUSTED_ROOT, CHAIN_VALIDATION_ERROR):
        # A cryptographically broken or untrusted chain should never still
        # read "VALID" -- but don't clobber a more specific date/self-signed
        # finding on the leaf itself with a chain-level one.
        if leaf.status == "VALID":
            leaf.status = "CHAIN_ISSUE" if status == CHAIN_INCOMPLETE_NO_TRUST_ANCHOR else "CHAIN_SIGNATURE_INVALID"
    elif status in (CHAIN_VALID_TRUSTED_ROOT, CHAIN_VALID_SELF_SIGNED_ROOT_TRUSTED):
        # Cryptographic verification succeeded up to a trusted local root,
        # even though the root itself wasn't in the capture (the normal
        # case -- servers omit the root by design). The old string-matching
        # evaluate_chain() may have pessimistically marked this CHAIN_ISSUE;
        # correct that now that we've actually verified the signature.
        if leaf.status == "CHAIN_ISSUE":
            leaf.status = "VALID"
