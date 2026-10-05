"""Tests for the SSRF guard on the plain (non-rendered) fetch path,
including:
- the redirect-chain bypass that was fixed after being flagged in
  README.md -> Limites connues: requests' allow_redirects=True followed a
  30x Location header without re-checking it, so a redirect to an internal
  address (e.g. the cloud metadata IP) slipped through the initial guard.
- the DNS-rebinding bypass found by a security review: the guard validated
  a hostname once, then handed the same hostname (not the validated IP) to
  a second, independent resolution at connect time - an attacker running
  authoritative DNS for their own domain could answer those two lookups
  differently. Fixed by pinning the connection to the already-validated IPs.
"""
import socket
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


def test_pin_dns_overrides_resolution_for_the_pinned_hostname():
    real_getaddrinfo = socket.getaddrinfo

    def rebinding_attacker_dns(host, port, *a, **kw):
        # what an attacker's own nameserver would answer *after* the guard
        # already validated a safe IP a moment earlier.
        if host == "rebind.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port or 0))]
        return real_getaddrinfo(host, port, *a, **kw)

    socket.getaddrinfo = rebinding_attacker_dns
    try:
        with wa._pin_dns("rebind.example", ["93.184.216.34"]):
            result = socket.getaddrinfo("rebind.example", 443)
            assert result[0][4][0] == "93.184.216.34"  # pinned IP wins, not the attacker's

        # pin released afterwards - the (simulated attacker) resolver is back
        after = socket.getaddrinfo("rebind.example", 443)
        assert after[0][4][0] == "169.254.169.254"
    finally:
        socket.getaddrinfo = real_getaddrinfo


def test_pin_dns_does_not_affect_other_hostnames():
    with wa._pin_dns("pinned.example", ["10.0.0.1"]):
        result = socket.getaddrinfo("example.com", 443)
        assert result[0][4][0] != "10.0.0.1"


def test_fetch_html_resolves_through_the_pin_during_the_request():
    # Simulates the race directly in requests.get(): while fetch_html's
    # pin is active, anything calling socket.getaddrinfo for this host
    # must see the pinned IP, never a second independent answer.
    captured = {}

    def fake_get(url, **kwargs):
        captured["resolved_ip"] = socket.getaddrinfo("example.com", 443)[0][4][0]
        return _ok_response(url)

    with patch.object(wa.requests, "get", side_effect=fake_get):
        with patch.object(wa, "_guard_ssrf", return_value=["93.184.216.34"]):
            wa.fetch_html("https://example.com/")

    assert captured["resolved_ip"] == "93.184.216.34"
