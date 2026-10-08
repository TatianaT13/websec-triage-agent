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


def test_screenshot_rejects_non_http_scheme():
    with pytest.raises(wa.FetchError):
        rnd.screenshot_webpage("ftp://example.com")


def test_screenshot_ssrf_guard_blocks_loopback():
    with pytest.raises(wa.FetchError):
        rnd.screenshot_webpage("http://127.0.0.1:1/x")


def test_screenshot_returns_real_png_bytes():
    pytest.importorskip("playwright", reason="requires requirements-render.txt")
    result = rnd.screenshot_webpage("https://example.com")
    assert result["status_code"] == 200
    assert result["png_bytes"][:8] == b"\x89PNG\r\n\x1a\n"  # real PNG magic bytes, not a placeholder
    assert len(result["png_bytes"]) > 1000


def test_host_resolver_pin_has_a_real_effect():
    # Proves --host-resolver-rules isn't silently ignored: pinning a real
    # hostname to a deliberately wrong (unreachable, RFC 5737 test-net) IP
    # must make the navigation fail, not quietly resolve normally. This is
    # the same mechanism fetch_rendered_html uses to close the DNS-rebinding
    # gap (Chromium would otherwise re-resolve independently of Python's
    # _guard_ssrf check, like requests did before web_analysis.py was
    # patched to pin its own connections).
    pytest.importorskip("playwright", reason="requires requirements-render.txt")
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--host-resolver-rules=MAP example.com 203.0.113.1"])
        try:
            page = browser.new_page()
            with pytest.raises(Exception):
                page.goto("https://example.com", timeout=5000)
        finally:
            browser.close()
