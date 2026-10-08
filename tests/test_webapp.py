"""Tests for the local web UI (fast mode - no LLM call). Uses FastAPI's
TestClient (in-process, no real server needed)."""
import io
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi", reason="requires requirements-web.txt")

from fastapi.testclient import TestClient

import webapp
from websec_agent import webapp_security as sec


@pytest.fixture(autouse=True)
def _unlimited_rate_limit(monkeypatch):
    # webapp.app's rate_limit dependency shares one module-level counter
    # (websec_agent.webapp_security._limiter) keyed by client IP - and
    # TestClient always reports the same fixed IP ("testclient") for
    # every request, in every test file, within one pytest run. Without
    # this, this file's own ~19 requests already sit right at the
    # default budget (20/60s) - one more test added later and the whole
    # suite starts failing on 429s that have nothing to do with what's
    # actually being tested. Give this file's client an effectively
    # unlimited budget instead; rate limiting itself is covered by
    # test_webapp_security.py's own isolated limiter instances.
    monkeypatch.setattr(sec, "_limiter", sec._FixedWindowLimiter(max_requests=10_000, window_seconds=60))


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


def test_analyze_shows_urlscan_context_without_affecting_verdict(monkeypatch):
    import websec_agent.urlscan_lookup as us_module

    monkeypatch.setattr(
        us_module,
        "find_existing_scans",
        lambda domain, limit=3: [
            {
                "scan_url": "https://urlscan.io/result/abc-123",
                "screenshot": "https://urlscan.io/screenshots/abc-123.png",
                "scanned_at": "2026-10-08T00:00:00Z",
                "page_title": "Example Domain",
                "page_url": "https://example.com/",
                "status_code": "200",
                "country": "US",
                "asn_name": "EXAMPLE-ASN",
                "domain_age_days": 9000,
                "tls_issuer": "Test CA",
            }
        ],
    )
    resp = client.post("/analyze", data={"url": "https://example.com", "check_urlscan": "true"})
    assert resp.status_code == 200
    assert "urlscan.io" in resp.text
    assert "Example Domain" in resp.text
    assert "Contexte de corroboration" in resp.text
    # Benign page, urlscan context present - must not have flipped the
    # verdict, it's informational only (same principle as BIMI above).
    assert 'class="badge badge-benign"' in resp.text or 'class="badge badge-uncertain"' in resp.text


def test_analyze_without_check_urlscan_omits_the_card():
    resp = client.post("/analyze", data={"url": "https://example.com"})
    assert resp.status_code == 200
    assert "<h2>urlscan.io</h2>" not in resp.text


def test_analyze_html_rejects_oversized_paste():
    big_html = "<html><body>" + "a" * (webapp.MAX_PASTED_HTML_CHARS + 1) + "</body></html>"
    resp = client.post("/analyze-html", data={"html": big_html, "url_hint": "https://example.com/"})
    assert resp.status_code == 200
    assert "trop volumineux" in resp.text


def test_analyze_email_rejects_oversized_upload():
    big_content = b"X" * (webapp.MAX_UPLOAD_BYTES + 1)
    resp = client.post(
        "/analyze-email",
        files={"eml_file": ("big.eml", io.BytesIO(big_content), "message/rfc822")},
    )
    assert resp.status_code == 200
    assert "refusé" in resp.text


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


def test_analyze_email_catches_display_name_spoofing_even_without_auth_failure(tmp_path):
    # Real case that motivated this check: displayed as "Vinci|Autoroutes"
    # but sent from a cosmetics-brand domain, with no Authentication-Results
    # header at all - SPF/DKIM/DMARC have nothing to say here, so this is
    # the only signal that catches it.
    eml_path = tmp_path / "vinci.eml"
    _write_eml(eml_path, from_addr="Vinci|Autoroutes <donotreply@marionnaud.fr>")
    with open(eml_path, "rb") as f:
        resp = client.post("/analyze-email", files={"eml_file": ("vinci.eml", f, "message/rfc822")})
    assert resp.status_code == 200
    assert 'class="badge badge-phishing"' in resp.text
    assert "display-name spoofing" in resp.text


def test_analyze_email_shows_independent_dkim_verification_failure(tmp_path, monkeypatch):
    # Mocked at the dkim_verify module level (not real DNS/crypto - that's
    # covered by tests/test_dkim_verify.py) so this test is deterministic
    # and doesn't need requirements-email-verify.txt installed.
    import websec_agent.dkim_verify as dv_module

    monkeypatch.setattr(
        dv_module,
        "verify_dkim_signature",
        lambda raw: {"verified": False, "signing_domain": "evil.example", "detail": "mocked"},
    )
    eml_path = tmp_path / "forged.eml"
    _write_eml(eml_path, from_addr="security@gmail.com")
    with open(eml_path, "rb") as f:
        resp = client.post("/analyze-email", files={"eml_file": ("forged.eml", f, "message/rfc822")})
    assert resp.status_code == 200
    assert 'class="badge badge-phishing"' in resp.text
    assert "vérifié par nous" in resp.text
    assert "evil.example" in resp.text


def test_analyze_email_flags_valid_dkim_signature_from_unaligned_domain(tmp_path, monkeypatch):
    # A valid signature from a domain unrelated to the claimed sender -
    # the gap a prior version of apply_dkim_verification had (it only
    # checked whether the signature validated, never who signed it).
    import websec_agent.dkim_verify as dv_module

    monkeypatch.setattr(
        dv_module,
        "verify_dkim_signature",
        lambda raw: {"verified": True, "signing_domain": "some-saas-mailer.com", "detail": "mocked"},
    )
    eml_path = tmp_path / "misaligned.eml"
    _write_eml(eml_path, from_addr="service@paypal.com")
    with open(eml_path, "rb") as f:
        resp = client.post("/analyze-email", files={"eml_file": ("misaligned.eml", f, "message/rfc822")})
    assert resp.status_code == 200
    assert 'class="badge badge-phishing"' in resp.text
    assert "désalignement DMARC" in resp.text
    assert "some-saas-mailer.com" in resp.text


def test_analyze_email_shows_bimi_info_without_affecting_verdict(tmp_path, monkeypatch):
    import websec_agent.bimi_lookup as bimi_module
    from email.message import EmailMessage

    monkeypatch.setattr(
        bimi_module, "lookup_bimi", lambda domain: {"present": True, "logo_url": "https://x/logo.svg", "has_vmc": True}
    )
    # Deliberately no brand keyword anywhere, so the only thing that could
    # move the verdict here is BIMI itself - isolates the "informational
    # only" claim instead of relying on a brand-mismatch score happening
    # to stay under the phishing threshold.
    msg = EmailMessage()
    msg["Subject"] = "Monthly newsletter"
    msg["From"] = "newsletter@example.com"
    msg.set_content("plain fallback")
    msg.add_alternative("<html><head><title>Newsletter</title></head><body>hi</body></html>", subtype="html")
    eml_path = tmp_path / "bimi.eml"
    eml_path.write_bytes(bytes(msg))

    with open(eml_path, "rb") as f:
        resp = client.post("/analyze-email", files={"eml_file": ("bimi.eml", f, "message/rfc822")})
    assert resp.status_code == 200
    assert "certificat de marque" in resp.text
    assert 'class="badge badge-benign"' in resp.text or 'class="badge badge-uncertain"' in resp.text


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
