"""Headless-browser page fetch (Playwright) for JS-rendered pages that the
plain requests-based fetch_html() can't see - e.g. a credential-harvesting
form injected by client-side JS, or a single-page app that renders empty
without running scripts.

Opt-in: requires requirements-render.txt plus a one-time
`playwright install chromium`. Mirrors web_analysis.fetch_html()'s return
shape and SSRF guard, so callers can treat both the same way.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from . import web_analysis as wa

DEFAULT_TIMEOUT_MS = 15_000


def fetch_rendered_html(url: str, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise wa.FetchError("only http/https URLs are supported")
    if not parts.hostname:
        raise wa.FetchError("URL has no hostname")
    validated_ips = wa._guard_ssrf(parts.hostname)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Rendered fetch requires the render extras: "
            "pip install -r requirements-render.txt && playwright install chromium"
        ) from exc

    def _guard_route(route):
        # Re-checked on every request the page makes, not just the initial
        # navigation: redirects, and any fetch()/XHR/img/script the loaded
        # page issues, could all otherwise reach an internal address -
        # a vector that doesn't even exist for the non-JS fetch_html() path.
        # Note: this check alone has the same DNS-rebinding gap fetch_html()
        # had before being pinned (Chromium resolves independently after
        # this Python-side check) - closed below for the main hostname via
        # --host-resolver-rules, which persists for every connection to
        # that exact hostname for the rest of this browser's lifetime, not
        # just the first one. Other hostnames the page references (a
        # redirect to a different domain, third-party subresources) are
        # still only covered by this per-request check, unpinned.
        host = urlsplit(route.request.url).hostname
        if host:
            try:
                wa._guard_ssrf(host)
            except wa.FetchError:
                route.abort()
                return
        route.continue_()

    launch_args = []
    pinned_ip = next((ip for ip in validated_ips if ipaddress.ip_address(ip).version == 4), None)
    if pinned_ip:
        launch_args.append(f"--host-resolver-rules=MAP {parts.hostname} {pinned_ip}")

    with sync_playwright() as p:
        browser = p.chromium.launch(args=launch_args)
        try:
            page = browser.new_page(user_agent=wa.USER_AGENT)
            page.route("**/*", _guard_route)
            try:
                response = page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001 - surface as our own FetchError
                raise wa.FetchError(f"rendered navigation failed: {exc}") from exc
            if response is None:
                raise wa.FetchError("navigation was blocked (internal/private address)")
            html = page.content()
            final_url = page.url
            status_code = response.status
        finally:
            browser.close()

    return {"final_url": final_url, "status_code": status_code, "html": html}


def screenshot_webpage(url: str, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict:
    """Returns {"final_url": str, "status_code": int, "png_bytes": bytes}
    - a viewport screenshot (1280x800, not full-page: a very tall or
    infinite-scroll page would otherwise produce a huge image for
    little extra signal) via the same SSRF-guarded, DNS-pinned headless
    browser as fetch_rendered_html(). Lets a vision-capable caller (the
    agent itself, via Claude's native vision - no separate API call)
    judge the page's actual visual layout/branding, not just its HTML -
    see mcp_server.screenshot_webpage's tool description for the caveat
    that a copied logo alone proves nothing (that's the whole point of
    a convincing phishing clone)."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise wa.FetchError("only http/https URLs are supported")
    if not parts.hostname:
        raise wa.FetchError("URL has no hostname")
    validated_ips = wa._guard_ssrf(parts.hostname)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Screenshot requires the render extras: "
            "pip install -r requirements-render.txt && playwright install chromium"
        ) from exc

    def _guard_route(route):
        # Same per-request re-validation as fetch_rendered_html - see its
        # _guard_route for the full DNS-rebinding rationale.
        host = urlsplit(route.request.url).hostname
        if host:
            try:
                wa._guard_ssrf(host)
            except wa.FetchError:
                route.abort()
                return
        route.continue_()

    launch_args = []
    pinned_ip = next((ip for ip in validated_ips if ipaddress.ip_address(ip).version == 4), None)
    if pinned_ip:
        launch_args.append(f"--host-resolver-rules=MAP {parts.hostname} {pinned_ip}")

    with sync_playwright() as p:
        browser = p.chromium.launch(args=launch_args)
        try:
            page = browser.new_page(user_agent=wa.USER_AGENT, viewport={"width": 1280, "height": 800})
            page.route("**/*", _guard_route)
            try:
                response = page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001 - surface as our own FetchError
                raise wa.FetchError(f"rendered navigation failed: {exc}") from exc
            if response is None:
                raise wa.FetchError("navigation was blocked (internal/private address)")
            png_bytes = page.screenshot(type="png")
            final_url = page.url
            status_code = response.status
        finally:
            browser.close()

    return {"final_url": final_url, "status_code": status_code, "png_bytes": png_bytes}
