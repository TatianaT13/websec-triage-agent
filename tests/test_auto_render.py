"""Tests for the auto-render retry in report.build_result(): if a plain
fetch looks suspiciously empty (no forms/links/text - the classic
single-page-app shell), it's supposed to retry through the headless
browser on its own, without the caller (or the agent) needing to notice
and switch tools. No real network/Playwright involved - web_analysis's
fetch and render's fetch are both mocked."""
from websec_agent import render as render_module
from websec_agent import report as rpt
from websec_agent import web_analysis as wa

SPA_SHELL_HTML = '<html><head><title></title></head><body><div id="root"></div></body></html>'
REAL_CONTENT_HTML = (
    "<html><head><title>Example</title></head>"
    '<body><p>Real content here, plenty of visible text.</p><a href="/about">About</a></body></html>'
)


def test_looks_js_rendered_empty_true_for_a_spa_shell():
    structure = wa.analyze_structure(SPA_SHELL_HTML, "https://example.com")
    assert wa.looks_js_rendered_empty(SPA_SHELL_HTML, structure) is True


def test_looks_js_rendered_empty_false_with_real_content():
    structure = wa.analyze_structure(REAL_CONTENT_HTML, "https://example.com")
    assert wa.looks_js_rendered_empty(REAL_CONTENT_HTML, structure) is False


def test_looks_js_rendered_empty_false_when_a_form_is_present():
    html = '<html><body><form><input type="password"></form></body></html>'
    structure = wa.analyze_structure(html, "https://example.com")
    assert wa.looks_js_rendered_empty(html, structure) is False


def test_build_result_auto_renders_when_plain_fetch_looks_empty(monkeypatch):
    monkeypatch.setattr(
        wa, "fetch_html", lambda url: {"final_url": url, "status_code": 200, "html": SPA_SHELL_HTML}
    )
    monkeypatch.setattr(
        render_module,
        "fetch_rendered_html",
        lambda url, **kw: {"final_url": url, "status_code": 200, "html": REAL_CONTENT_HTML},
    )

    result = rpt.build_result("https://example.com")
    assert result["auto_rendered"] is True
    assert result["structure"]["title"] == "Example"


def test_build_result_falls_back_when_render_extras_missing(monkeypatch):
    monkeypatch.setattr(
        wa, "fetch_html", lambda url: {"final_url": url, "status_code": 200, "html": SPA_SHELL_HTML}
    )

    def raise_missing_extras(url, **kw):
        raise RuntimeError("Rendered fetch requires the render extras")

    monkeypatch.setattr(render_module, "fetch_rendered_html", raise_missing_extras)

    result = rpt.build_result("https://example.com")
    assert result["auto_rendered"] is False
    assert result["structure"]["title"] is None


def test_build_result_falls_back_when_rendering_itself_fails(monkeypatch):
    monkeypatch.setattr(
        wa, "fetch_html", lambda url: {"final_url": url, "status_code": 200, "html": SPA_SHELL_HTML}
    )

    def raise_fetch_error(url, **kw):
        raise wa.FetchError("rendered navigation failed: timeout")

    monkeypatch.setattr(render_module, "fetch_rendered_html", raise_fetch_error)

    result = rpt.build_result("https://example.com")
    assert result["auto_rendered"] is False
    assert result["structure"]["title"] is None


def test_build_result_does_not_auto_render_when_plain_fetch_has_content(monkeypatch):
    monkeypatch.setattr(
        wa, "fetch_html", lambda url: {"final_url": url, "status_code": 200, "html": REAL_CONTENT_HTML}
    )

    def fail_if_called(url, **kw):
        raise AssertionError("fetch_rendered_html should not have been called")

    monkeypatch.setattr(render_module, "fetch_rendered_html", fail_if_called)

    result = rpt.build_result("https://example.com")
    assert result["auto_rendered"] is None


def test_build_result_explicit_render_sets_auto_rendered_to_none(monkeypatch):
    monkeypatch.setattr(
        render_module,
        "fetch_rendered_html",
        lambda url, **kw: {"final_url": url, "status_code": 200, "html": REAL_CONTENT_HTML},
    )

    result = rpt.build_result("https://example.com", render=True)
    assert result["auto_rendered"] is None


def test_build_result_from_html_always_has_auto_rendered_none():
    result = rpt.build_result_from_html(REAL_CONTENT_HTML, "https://example.com")
    assert result["auto_rendered"] is None
