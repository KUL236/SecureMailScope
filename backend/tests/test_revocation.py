"""
Tests for app/parsing/revocation.py. All HTTP is mocked -- these tests
never make a real network call, consistent with the sandboxed/offline
test environment and with the tool's "no live network for core tests"
principle. Live-network behavior is exercised manually / in a deployed
environment with ENABLE_LIVE_REVOCATION_CHECKS=true.
"""
from unittest.mock import patch, MagicMock

from cryptography.x509.ocsp import OCSPResponseBuilder, OCSPCertStatus
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

from app.parsing import revocation
from tests.certgen import make_root_ca, make_leaf_cert


def _make_leaf_with_endpoints():
    root_der, root_key, root_cert = make_root_ca()
    leaf_der, _, leaf_cert = make_leaf_cert(
        "mail.example.com", root_cert, root_key,
        ocsp_url="http://ocsp.example-ca.test/", crl_url="http://crl.example-ca.test/root.crl",
    )
    return root_cert, leaf_cert


def test_disabled_by_default_returns_not_determined():
    root_cert, leaf_cert = _make_leaf_with_endpoints()
    result = revocation.determine_revocation_status(leaf_cert, root_cert, enabled=False)
    assert result.status == revocation.STATUS_DISABLED


def test_no_endpoint_in_certificate_reports_that_explicitly():
    root_der, root_key, root_cert = make_root_ca()
    leaf_der, _, leaf_cert = make_leaf_cert("mail.example.com", root_cert, root_key)  # no ocsp/crl urls
    result = revocation.determine_revocation_status(leaf_cert, root_cert, enabled=True)
    assert result.status == revocation.STATUS_NO_ENDPOINT


def test_ocsp_good_response_is_reported_as_good():
    root_cert, leaf_cert = _make_leaf_with_endpoints()

    with patch("httpx.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Build a real, well-formed OCSP response so load_der_ocsp_response succeeds.
        mock_resp.content = b""  # placeholder, overridden below via side_effect
        mock_post.return_value = mock_resp

        with patch("app.parsing.revocation.load_der_ocsp_response") as mock_load:
            mock_ocsp_resp = MagicMock()
            mock_ocsp_resp.response_status = revocation.OCSPResponseStatus.SUCCESSFUL
            mock_ocsp_resp.certificate_status = OCSPCertStatus.GOOD
            mock_load.return_value = mock_ocsp_resp

            result = revocation.determine_revocation_status(leaf_cert, root_cert, enabled=True)

    assert result.status == revocation.STATUS_GOOD_OCSP
    assert result.checked_via == "OCSP"


def test_ocsp_revoked_response_is_reported_as_revoked():
    root_cert, leaf_cert = _make_leaf_with_endpoints()

    with patch("httpx.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        with patch("app.parsing.revocation.load_der_ocsp_response") as mock_load:
            mock_ocsp_resp = MagicMock()
            mock_ocsp_resp.response_status = revocation.OCSPResponseStatus.SUCCESSFUL
            mock_ocsp_resp.certificate_status = OCSPCertStatus.REVOKED
            mock_ocsp_resp.revocation_time = None
            mock_ocsp_resp.revocation_reason = None
            mock_load.return_value = mock_ocsp_resp

            result = revocation.determine_revocation_status(leaf_cert, root_cert, enabled=True)

    assert result.status == revocation.STATUS_REVOKED_OCSP
    assert result.status in revocation.REVOKED_STATUSES


def test_ocsp_unreachable_falls_back_to_crl():
    root_cert, leaf_cert = _make_leaf_with_endpoints()

    with patch("httpx.post", side_effect=ConnectionError("no route to host")):
        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_get.return_value = mock_resp
            with patch("app.parsing.revocation.x509.load_der_x509_crl") as mock_crl:
                mock_crl_obj = MagicMock()
                mock_crl_obj.get_revoked_certificate_by_serial_number.return_value = None
                mock_crl.return_value = mock_crl_obj

                result = revocation.determine_revocation_status(leaf_cert, root_cert, enabled=True)

    assert result.status == revocation.STATUS_GOOD_CRL
    assert result.checked_via == "CRL"
    assert "ocsp_attempted_first" in result.detail


def test_no_issuer_falls_back_to_crl_only():
    root_cert, leaf_cert = _make_leaf_with_endpoints()

    with patch("httpx.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        with patch("app.parsing.revocation.x509.load_der_x509_crl") as mock_crl:
            mock_crl_obj = MagicMock()
            mock_crl_obj.get_revoked_certificate_by_serial_number.return_value = None
            mock_crl.return_value = mock_crl_obj

            result = revocation.determine_revocation_status(leaf_cert, None, enabled=True)

    assert result.status == revocation.STATUS_GOOD_CRL


def test_both_ocsp_and_crl_unreachable_reports_unavailable_not_good():
    root_cert, leaf_cert = _make_leaf_with_endpoints()

    with patch("httpx.post", side_effect=ConnectionError("timeout")):
        with patch("httpx.get", side_effect=ConnectionError("timeout")):
            result = revocation.determine_revocation_status(leaf_cert, root_cert, enabled=True)

    assert result.status == revocation.STATUS_CHECK_UNAVAILABLE
    assert result.status not in (revocation.STATUS_GOOD_OCSP, revocation.STATUS_GOOD_CRL)
