"""Headless-browser page fetch (Playwright) for JS-rendered pages that the
plain requests-based fetch_html() can't see - e.g. a credential-harvesting
form injected by client-side JS, or a single-page app that renders empty
without running scripts.

Opt-in: requires requirements-render.txt plus a one-time
`playwright install chromium`. Mirrors web_analysis.fetch_html()'s return
shape and SSRF guard, so callers can treat both the same way.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from . import web_analysis as wa

DEFAULT_TIMEOUT_MS = 15_000


def fetch_rendered_html(url: str, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise wa.FetchError("only http/https URLs are supported")
    if not parts.hostname:
        raise wa.FetchError("URL has no hostname")
    wa._guard_ssrf(parts.hostname)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Rendered fetch requires the render extras: "
            "pip install -r requirements-render.txt && playwright install chromium"
        ) from exc

    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            page = browser.new_page(user_agent=wa.USER_AGENT)
            try:
                response = page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001 - surface as our own FetchError
                raise wa.FetchError(f"rendered navigation failed: {exc}") from exc
            html = page.content()
            final_url = page.url
            status_code = response.status if response else None
        finally:
            browser.close()

    return {"final_url": final_url, "status_code": status_code, "html": html}
