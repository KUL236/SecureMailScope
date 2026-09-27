"""
Revocation status checking (OCSP + CRL) -- closes the second gap flagged
in docs/CERTIFICATE_ANALYSIS.md.

Design principle, unchanged from before this module existed: a passive
PCAP has NO revocation information in it. `revocation_status` must never
be upgraded to GOOD/REVOKED just because a status byte *looked* fine
somewhere. The only way to genuinely know revocation status is a live
lookup against the CA (OCSP responder or CRL distribution point named in
the certificate itself) -- which is why this is:

  1. Off by default (config.ENABLE_LIVE_REVOCATION_CHECKS), because this
     tool's core design point is "passive-capture-only, no live network
     calls" (see MASTER_PROMPT.md / ARCHITECTURE.md). Turning this on is
     an explicit, separate decision by whoever deploys it.
  2. When on, every outcome is reported as a specific, falsifiable
     status -- GOOD / REVOKED / UNKNOWN from the responder, or one of
     several *_UNAVAILABLE / NO_*_ENDPOINT statuses when a live check
     could not be completed -- never silently coerced into a generic
     "valid" state.
  3. OCSP is tried first (cheaper, real-time); CRL is used as a fallback
     only if OCSP could not be completed (no OCSP URL, or the OCSP
     request failed/timed out).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus, OCSPCertStatus, load_der_ocsp_response
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

logger = logging.getLogger("securemailscope.revocation")

STATUS_DISABLED = "NOT_DETERMINED_FROM_PCAP"  # default / live checks off
STATUS_GOOD_OCSP = "GOOD_OCSP"
STATUS_REVOKED_OCSP = "REVOKED_OCSP"
STATUS_UNKNOWN_OCSP = "UNKNOWN_OCSP"
STATUS_GOOD_CRL = "GOOD_CRL"
STATUS_REVOKED_CRL = "REVOKED_CRL"
STATUS_NO_ENDPOINT = "NO_REVOCATION_ENDPOINT_IN_CERTIFICATE"
STATUS_CHECK_UNAVAILABLE = "REVOCATION_CHECK_UNAVAILABLE"  # both OCSP and CRL attempted/absent and failed
STATUS_ISSUER_UNAVAILABLE = "ISSUER_CERTIFICATE_UNAVAILABLE"  # can't build OCSP request without issuer pubkey

REVOKED_STATUSES = {STATUS_REVOKED_OCSP, STATUS_REVOKED_CRL}


@dataclass
class RevocationResult:
    status: str
    checked_via: Optional[str] = None  # "OCSP" / "CRL" / None
    detail: dict = field(default_factory=dict)


def _get_ocsp_url(cert: x509.Certificate) -> Optional[str]:
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        for desc in aia:
            if desc.access_method == AuthorityInformationAccessOID.OCSP:
                return desc.access_location.value
    except x509.ExtensionNotFound:
        return None
    return None


def _get_crl_urls(cert: x509.Certificate) -> List[str]:
    urls = []
    try:
        cdp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        for point in cdp:
            if point.full_name:
                for name in point.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        urls.append(name.value)
    except x509.ExtensionNotFound:
        pass
    return urls


def _check_ocsp(cert: x509.Certificate, issuer: x509.Certificate, timeout: float) -> Optional[RevocationResult]:
    """Returns None if OCSP couldn't even be attempted (no URL); a
    RevocationResult otherwise (including on network/parse failure)."""
    import httpx

    url = _get_ocsp_url(cert)
    if not url:
        return None

    try:
        builder = OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1())
        req = builder.build()
        req_der = req.public_bytes(Encoding.DER)

        resp = httpx.post(
            url, content=req_der,
            headers={"Content-Type": "application/ocsp-request"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return RevocationResult(STATUS_CHECK_UNAVAILABLE, "OCSP",
                                     {"url": url, "http_status": resp.status_code})

        ocsp_resp = load_der_ocsp_response(resp.content)
        if ocsp_resp.response_status != OCSPResponseStatus.SUCCESSFUL:
            return RevocationResult(STATUS_CHECK_UNAVAILABLE, "OCSP",
                                     {"url": url, "response_status": str(ocsp_resp.response_status)})

        if ocsp_resp.certificate_status == OCSPCertStatus.GOOD:
            return RevocationResult(STATUS_GOOD_OCSP, "OCSP", {"url": url})
        if ocsp_resp.certificate_status == OCSPCertStatus.REVOKED:
            return RevocationResult(STATUS_REVOKED_OCSP, "OCSP", {
                "url": url,
                "revocation_time": str(ocsp_resp.revocation_time) if ocsp_resp.revocation_time else None,
                "revocation_reason": str(ocsp_resp.revocation_reason) if ocsp_resp.revocation_reason else None,
            })
        return RevocationResult(STATUS_UNKNOWN_OCSP, "OCSP", {"url": url})

    except Exception as e:
        logger.info("OCSP check failed/unreachable for %s: %s", url, e)
        return RevocationResult(STATUS_CHECK_UNAVAILABLE, "OCSP", {"url": url, "error": str(e)})


def _check_crl(cert: x509.Certificate, timeout: float) -> Optional[RevocationResult]:
    import httpx

    urls = _get_crl_urls(cert)
    if not urls:
        return None

    for url in urls:
        try:
            resp = httpx.get(url, timeout=timeout)
            if resp.status_code != 200:
                continue
            try:
                crl = x509.load_der_x509_crl(resp.content)
            except ValueError:
                crl = x509.load_pem_x509_crl(resp.content)

            revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
            if revoked is not None:
                return RevocationResult(STATUS_REVOKED_CRL, "CRL", {
                    "url": url, "revocation_date": str(revoked.revocation_date),
                })
            return RevocationResult(STATUS_GOOD_CRL, "CRL", {"url": url})
        except Exception as e:
            logger.info("CRL check failed for %s: %s", url, e)
            continue

    return RevocationResult(STATUS_CHECK_UNAVAILABLE, "CRL", {"urls_tried": urls})


def apply_revocation_checks(certs: List, *, enabled: bool, timeout: float = 5.0) -> None:
    """
    Orchestration helper mirroring chain_validation.verify_certificate_chain's
    shape: mutates the given CertificateInfo list in place, setting
    `.revocation_status`, `.revocation_checked_via`, `.revocation_detail`
    on each cert using its immediate issuer (the next cert up the
    observed chain, if any) as the OCSP issuer certificate.

    Safe to call unconditionally -- when `enabled` is False every cert
    just gets the existing default NOT_DETERMINED_FROM_PCAP status
    without attempting any I/O.
    """
    if not certs:
        return

    x509_objs = []
    for c in certs:
        if not getattr(c, "raw_der", None):
            x509_objs.append(None)
            continue
        try:
            x509_objs.append(x509.load_der_x509_certificate(c.raw_der))
        except Exception:
            x509_objs.append(None)

    for i, cert_info in enumerate(certs):
        child_x = x509_objs[i]
        issuer_x = x509_objs[i + 1] if i + 1 < len(x509_objs) else None
        result = determine_revocation_status(child_x, issuer_x, enabled=enabled, timeout=timeout)
        cert_info.revocation_status = result.status
        cert_info.revocation_checked_via = result.checked_via
        cert_info.revocation_detail = result.detail


def determine_revocation_status(
    leaf_x509: Optional[x509.Certificate],
    issuer_x509: Optional[x509.Certificate],
    *,
    enabled: bool,
    timeout: float = 5.0,
) -> RevocationResult:
    """
    Single entry point used by the pipeline. `enabled` should come from
    config.ENABLE_LIVE_REVOCATION_CHECKS -- this function does not read
    config itself so it stays easy to unit test (see test_revocation.py).
    """
    if not enabled:
        return RevocationResult(STATUS_DISABLED, None, {"reason": "live revocation checks disabled by config"})

    if leaf_x509 is None:
        return RevocationResult(STATUS_DISABLED, None, {"reason": "certificate bytes unavailable"})

    if issuer_x509 is None:
        # OCSP requests are built against (cert, issuer) pairs; without
        # the issuer's public key we cannot construct a valid request.
        # CRL doesn't need the issuer, so fall through to CRL-only.
        crl_result = _check_crl(leaf_x509, timeout)
        if crl_result is not None:
            return crl_result
        return RevocationResult(STATUS_ISSUER_UNAVAILABLE, None,
                                 {"reason": "issuer certificate not observed in capture; OCSP requires it"})

    ocsp_result = _check_ocsp(leaf_x509, issuer_x509, timeout)
    if ocsp_result is not None and ocsp_result.status in (STATUS_GOOD_OCSP, STATUS_REVOKED_OCSP, STATUS_UNKNOWN_OCSP):
        return ocsp_result

    # OCSP absent or failed -> fall back to CRL
    crl_result = _check_crl(leaf_x509, timeout)
    if crl_result is not None:
        if ocsp_result is not None:
            crl_result.detail["ocsp_attempted_first"] = ocsp_result.detail
        return crl_result

    if ocsp_result is not None:
        return ocsp_result  # OCSP was attempted (and unavailable) but no CRL either

    return RevocationResult(STATUS_NO_ENDPOINT, None, {"reason": "no OCSP or CRL endpoint present in certificate"})
