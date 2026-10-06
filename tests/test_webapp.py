"""Tests for the local web UI (fast mode - no LLM call). Uses FastAPI's
TestClient (in-process, no real server needed)."""
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi", reason="requires requirements-web.txt")

from fastapi.testclient import TestClient

import webapp

client = TestClient(webapp.app)


def test_index_shows_the_form():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "<form" in resp.text
    assert 'name="url"' in resp.text


def test_analyze_benign_shows_green_badge():
    resp = client.post("/analyze", data={"url": "https://example.com"})
    assert resp.status_code == 200
    assert 'class="badge badge-benign"' in resp.text or 'class="badge badge-uncertain"' in resp.text


def test_analyze_blocked_url_shows_error_card():
    resp = client.post("/analyze", data={"url": "http://127.0.0.1:1/"})
    assert resp.status_code == 200
    assert "Erreur" in resp.text
    assert "internal/private address" in resp.text


def test_malicious_page_title_is_escaped_not_executed():
    # A phishing page's own title/content is attacker-controlled - it must
    # never be injected into our HTML unescaped (stored XSS in our own
    # tool, against the analyst viewing the report).
    fake_result = {
        "requested_url": "https://evil.example/",
        "final_url": "https://evil.example/",
        "status_code": 200,
        "fetched_at": "2026-01-01T00:00:00+00:00",
        "structure": {
            "title": "<script>alert(1)</script>",
            "forms": [],
            "external_scripts": [],
            "iframes": [],
            "favicon_is_external": False,
            "meta_refresh": False,
        },
        "iocs": {
            "domains": [], "emails": [], "punycode_domains": [],
            "shortener_links": [], "ip_literal_urls": [], "suspicious_tld_domains": [],
        },
        "phishing_heuristic": {"score": 0, "level": "low", "reasons": []},
        "ml_classifier": None,
        "domain_age": None,
        "virustotal": None,
        "verdict": {"label": "uncertain", "confidence": "heuristic-only (ML classifier unavailable)"},
    }
    with patch.object(webapp.rpt, "build_result", return_value=fake_result):
        resp = client.post("/analyze", data={"url": "https://evil.example/"})
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text
