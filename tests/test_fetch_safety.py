"""Tests for the SSRF guard on the plain (non-rendered) fetch path,
including the redirect-chain bypass that was fixed after being flagged in
README.md -> Limites connues: requests' allow_redirects=True followed a
30x Location header without re-checking it, so a redirect to an internal
address (e.g. the cloud metadata IP) slipped through the initial guard.
"""
from unittest.mock import Mock, patch

import pytest

from websec_agent import web_analysis as wa


def test_rejects_non_http_scheme():
    with pytest.raises(wa.FetchError):
        wa.fetch_html("ftp://example.com")


def test_rejects_url_without_hostname():
    with pytest.raises(wa.FetchError):
        wa.fetch_html("file:///etc/passwd")


def test_ssrf_guard_blocks_loopback():
    with pytest.raises(wa.FetchError):
        wa.fetch_html("http://127.0.0.1:1/x")


def _redirect_response(location: str) -> Mock:
    resp = Mock()
    resp.is_redirect = True
    resp.headers = {"Location": location}
    resp.close = Mock()
    return resp


def _ok_response(url: str) -> Mock:
    resp = Mock()
    resp.is_redirect = False
    resp.url = url
    resp.status_code = 200
    resp.headers = {}
    resp.encoding = "utf-8"
    resp.iter_content = Mock(return_value=[b"<html>ok</html>"])
    return resp


def test_redirect_to_internal_address_is_blocked():
    # First hop looks fine; the server then redirects to the cloud metadata
    # IP. Without re-checking each hop, this would reach it.
    with patch.object(wa.requests, "get", return_value=_redirect_response("http://169.254.169.254/secret")):
        with pytest.raises(wa.FetchError, match="internal/private address"):
            wa.fetch_html("https://example.com/start")


def test_redirect_to_public_address_is_followed():
    calls = [
        _redirect_response("https://example.com/final"),
        _ok_response("https://example.com/final"),
    ]
    with patch.object(wa.requests, "get", side_effect=calls):
        result = wa.fetch_html("https://example.com/start")
    assert result["final_url"] == "https://example.com/final"
    assert result["html"] == "<html>ok</html>"


def test_too_many_redirects_raises():
    infinite_redirect = _redirect_response("https://example.com/next")
    with patch.object(wa.requests, "get", return_value=infinite_redirect):
        with pytest.raises(wa.FetchError, match="too many redirects"):
            wa.fetch_html("https://example.com/start")
