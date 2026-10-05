"""Tests for the Markdown report + IOC bundle builders. Exercises the pure
formatting functions directly with a hand-built result dict (same shape as
report.build_result's output) - no network fetch involved."""
from websec_agent.report import build_ioc_bundle, build_markdown_report

SAMPLE_RESULT = {
    "requested_url": "https://wetransfer-smoky.vercel.app/",
    "final_url": "https://wetransfer-smoky.vercel.app/",
    "status_code": 200,
    "fetched_at": "2026-01-01T00:00:00+00:00",
    "structure": {
        "title": "WeTransfer",
        "forms": [],
        "script_src_count": 1,
        "external_scripts": [],
        "link_count": 2,
        "external_link_count": 1,
        "iframes": [],
        "favicon": "https://cdn.other-host.example/favicon.ico",
        "favicon_is_external": True,
        "meta_refresh": False,
    },
    "iocs": {
        "domains": ["wetransfer-smoky.vercel.app", "cdn.other-host.example"],
        "emails": [],
        "punycode_domains": [],
        "shortener_links": [],
        "ip_literal_urls": [],
        "suspicious_tld_domains": [],
    },
    "phishing_heuristic": {
        "score": 4,
        "level": "medium",
        "reasons": [
            "brand 'wetransfer' in page title but site domain is 'wetransfer-smoky.vercel.app'",
            "favicon served from a different domain than the page",
        ],
    },
}


def test_markdown_report_contains_key_sections():
    md = build_markdown_report(SAMPLE_RESULT)
    assert "wetransfer-smoky.vercel.app" in md
    assert "MEDIUM" in md
    assert "brand 'wetransfer'" in md
    assert "cdn.other-host.example" in md


def test_markdown_report_handles_empty_lists():
    result = {**SAMPLE_RESULT, "iocs": {k: [] for k in SAMPLE_RESULT["iocs"]}}
    md = build_markdown_report(result)
    assert "(none)" in md


def test_ioc_bundle_shape():
    bundle = build_ioc_bundle(SAMPLE_RESULT)
    assert bundle["verdict_level"] == "medium"
    assert bundle["verdict_score"] == 4
    types = {i["type"] for i in bundle["indicators"]}
    assert "url" in types
    assert "domain" in types
    domains = {i["value"] for i in bundle["indicators"] if i["type"] == "domain"}
    assert "cdn.other-host.example" in domains
