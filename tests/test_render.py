"""Tests for the headless-browser fetch path. The scheme/SSRF validation
runs before Playwright is even imported, so those cases are tested without
the render extras installed; the actual browser launch is skipped unless
Playwright + its chromium binary are available (requirements-render.txt +
`playwright install chromium`).
"""
import pytest

from websec_agent import render as rnd
from websec_agent import web_analysis as wa


def test_rejects_non_http_scheme():
    with pytest.raises(wa.FetchError):
        rnd.fetch_rendered_html("ftp://example.com")


def test_rejects_url_without_hostname():
    with pytest.raises(wa.FetchError):
        rnd.fetch_rendered_html("file:///etc/passwd")


def test_ssrf_guard_blocks_loopback():
    with pytest.raises(wa.FetchError):
        rnd.fetch_rendered_html("http://127.0.0.1:1/x")


def test_renders_a_real_page():
    pytest.importorskip("playwright", reason="requires requirements-render.txt")
    result = rnd.fetch_rendered_html("https://example.com")
    assert result["status_code"] == 200
    assert "Example Domain" in result["html"]
