"""Tests for the urlscan.io existing-scan lookup. Mocks requests.get
rather than hitting the network, but the response shape used here was
pulled from a real API call (page.domain:paypal.com) before writing
these fixtures - see commit message."""
from unittest.mock import MagicMock, patch

from websec_agent import urlscan_lookup as us

_REAL_SHAPED_RESPONSE = {
    "results": [
        {
            "task": {"time": "2026-10-08T17:53:27.669Z", "uuid": "abc-123"},
            "page": {
                "title": "paypal.com",
                "url": "https://www.paypal.com/",
                "status": "200",
                "country": "US",
                "asnname": "FASTLY - Fastly, Inc., US",
                "domainAgeDays": 4944,
                "tlsIssuer": "DigiCert EV RSA CA G2",
            },
            "result": "https://urlscan.io/api/v1/result/abc-123/",
            "screenshot": "https://urlscan.io/screenshots/abc-123.png",
        }
    ]
}


def _mock_response(json_data, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


def test_empty_domain_returns_no_scans():
    assert us.find_existing_scans("") == []


def test_parses_a_real_shaped_response():
    with patch("requests.get", return_value=_mock_response(_REAL_SHAPED_RESPONSE)):
        scans = us.find_existing_scans("paypal.com")
    assert len(scans) == 1
    assert scans[0]["page_title"] == "paypal.com"
    assert scans[0]["country"] == "US"
    assert scans[0]["scan_url"] == "https://urlscan.io/result/abc-123"
    assert scans[0]["screenshot"] == "https://urlscan.io/screenshots/abc-123.png"


def test_no_results_returns_empty_list():
    with patch("requests.get", return_value=_mock_response({"results": []})):
        assert us.find_existing_scans("never-scanned-domain.example") == []


def test_network_failure_returns_empty_list_not_an_exception():
    import requests

    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("boom")):
        assert us.find_existing_scans("paypal.com") == []


def test_plan_restricted_403_returns_empty_list_not_an_exception():
    # The real 403 "Your current plan does not allow..." case for gated
    # fields - this module never queries those fields, but a defensively
    # written caller should still survive any unexpected 403/4xx cleanly.
    resp = _mock_response({"message": "Your current plan does not allow..."}, status=403)
    resp.raise_for_status.side_effect = __import__("requests").exceptions.HTTPError("403")
    with patch("requests.get", return_value=resp):
        assert us.find_existing_scans("paypal.com") == []


def test_respects_the_limit_parameter():
    many_results = {"results": [_REAL_SHAPED_RESPONSE["results"][0] for _ in range(10)]}
    with patch("requests.get", return_value=_mock_response(many_results)):
        scans = us.find_existing_scans("paypal.com", limit=2)
    assert len(scans) == 2
