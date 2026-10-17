"""Tests for the MCP tool wrappers (websec_agent/mcp_server.py) - previously
at 0% coverage. Each @tool-decorated function is a thin wrapper around an
already-tested module (report.py, web_analysis.py, classifier.py, ...), so
these tests monkeypatch at that boundary rather than re-testing the
underlying logic: the point is catching a broken wrapper (wrong dict key,
args not threaded through, a response envelope that doesn't match what the
SDK expects), not re-verifying heuristics/ML/DKIM behavior covered
elsewhere. No real network/DNS/subprocess calls happen in this file.

A @tool-decorated function becomes an SdkMcpTool instance - call its
.handler(args) coroutine directly, the same way the SDK does internally.
"""
import asyncio
import base64

from websec_agent import mcp_server
from websec_agent import report, web_analysis

from .fixtures import BENIGN_HTML


def run(coro):
    return asyncio.run(coro)


# --- analyze_webpage --------------------------------------------------


def test_analyze_webpage_success_threads_args_and_returns_text(monkeypatch):
    captured = {}

    def fake_build_result(url, rendered, check_vt, check_urlscan):
        captured["args"] = (url, rendered, check_vt, check_urlscan)
        return {"verdict": {"label": "benign"}}

    monkeypatch.setattr(report, "build_result", fake_build_result)
    result = run(mcp_server.analyze_webpage.handler({"url": "https://example.com", "check_virustotal": True}))

    assert captured["args"] == ("https://example.com", False, True, False)
    assert "benign" in result["content"][0]["text"]
    assert "is_error" not in result


def test_analyze_webpage_defaults_virustotal_and_urlscan_to_false(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        report, "build_result", lambda url, rendered, check_vt, check_urlscan: captured.update(vt=check_vt, us=check_urlscan) or {}
    )
    run(mcp_server.analyze_webpage.handler({"url": "https://example.com"}))
    assert captured == {"vt": False, "us": False}


def test_analyze_webpage_fetch_error_is_reported_as_is_error(monkeypatch):
    def raise_fetch_error(*a, **k):
        raise web_analysis.FetchError("blocked: private IP")

    monkeypatch.setattr(report, "build_result", raise_fetch_error)
    result = run(mcp_server.analyze_webpage.handler({"url": "http://127.0.0.1"}))

    assert result["is_error"] is True
    assert "blocked: private IP" in result["content"][0]["text"]


# --- analyze_webpage_rendered -------------------------------------------


def test_analyze_webpage_rendered_forces_rendered_true(monkeypatch):
    captured = {}
    monkeypatch.setattr(report, "build_result", lambda url, rendered: captured.update(rendered=rendered) or {})
    run(mcp_server.analyze_webpage_rendered.handler({"url": "https://example.com"}))
    assert captured["rendered"] is True


def test_analyze_webpage_rendered_runtime_error_is_reported(monkeypatch):
    def raise_runtime_error(*a, **k):
        raise RuntimeError("playwright not installed")

    monkeypatch.setattr(report, "build_result", raise_runtime_error)
    result = run(mcp_server.analyze_webpage_rendered.handler({"url": "https://example.com"}))
    assert result["is_error"] is True
    assert "playwright not installed" in result["content"][0]["text"]


# --- screenshot_webpage --------------------------------------------------


def test_screenshot_webpage_returns_text_and_base64_image(monkeypatch):
    from websec_agent import render

    fake_png = b"\x89PNG-fake-bytes"
    monkeypatch.setattr(
        render,
        "screenshot_webpage",
        lambda url: {"png_bytes": fake_png, "final_url": "https://example.com/", "status_code": 200},
    )
    result = run(mcp_server.screenshot_webpage.handler({"url": "https://example.com"}))

    assert len(result["content"]) == 2
    assert result["content"][0]["type"] == "text"
    assert "https://example.com/" in result["content"][0]["text"]
    image_block = result["content"][1]
    assert image_block["type"] == "image"
    assert image_block["mimeType"] == "image/png"
    assert base64.b64decode(image_block["data"]) == fake_png


def test_screenshot_webpage_fetch_error_is_reported(monkeypatch):
    from websec_agent import render

    def raise_fetch_error(*a, **k):
        raise web_analysis.FetchError("DNS resolution failed")

    monkeypatch.setattr(render, "screenshot_webpage", raise_fetch_error)
    result = run(mcp_server.screenshot_webpage.handler({"url": "https://nonexistent.invalid"}))
    assert result["is_error"] is True
    assert "DNS resolution failed" in result["content"][0]["text"]


# --- analyze_html --------------------------------------------------------


def test_analyze_html_threads_all_args(monkeypatch):
    captured = {}

    def fake(html, url_hint, check_vt, check_urlscan):
        captured.update(html=html, url_hint=url_hint, check_vt=check_vt, check_urlscan=check_urlscan)
        return {"verdict": {"label": "phishing"}}

    monkeypatch.setattr(report, "build_result_from_html", fake)
    result = run(
        mcp_server.analyze_html.handler(
            {"html": BENIGN_HTML, "url_hint": "https://totally-legit.example", "check_urlscan": True}
        )
    )

    assert captured["html"] == BENIGN_HTML
    assert captured["url_hint"] == "https://totally-legit.example"
    assert captured["check_vt"] is False
    assert captured["check_urlscan"] is True
    assert "phishing" in result["content"][0]["text"]


# --- analyze_email --------------------------------------------------------


def _write_eml(path, from_addr="service@paypal.com", subject="hi"):
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg.set_content("plain fallback")
    msg.add_alternative("<html><head><title>PayPal</title></head><body>hi</body></html>", subtype="html")
    path.write_bytes(bytes(msg))


def test_analyze_email_bad_file_path_is_reported_not_raised(tmp_path):
    result = run(mcp_server.analyze_email.handler({"file_path": str(tmp_path / "missing.eml")}))
    assert result["is_error"] is True
    assert "Could not read/parse" in result["content"][0]["text"]


def test_analyze_email_wires_auth_display_name_and_attachments(tmp_path, monkeypatch):
    eml_path = tmp_path / "test.eml"
    _write_eml(eml_path, from_addr="Vinci|Autoroutes <donotreply@marionnaud.fr>")

    from websec_agent import bimi_lookup, dkim_verify

    monkeypatch.setattr(dkim_verify, "verify_dkim_signature", lambda raw: {"verified": None, "signing_domain": None})
    monkeypatch.setattr(bimi_lookup, "lookup_bimi", lambda domain: {"present": False})

    result = run(mcp_server.analyze_email.handler({"file_path": str(eml_path)}))
    text = result["content"][0]["text"]

    # display-name spoofing ("Vinci|Autoroutes" vs marionnaud.fr) should be
    # caught even with no SPF/DKIM auth header at all on this message.
    assert "phishing" in text
    assert "dkim_verification" in text
    assert "bimi" in text


def test_analyze_email_degrades_silently_when_dkim_and_bimi_extras_missing(tmp_path, monkeypatch):
    eml_path = tmp_path / "test.eml"
    _write_eml(eml_path)

    from websec_agent import bimi_lookup, dkim_verify

    monkeypatch.setattr(dkim_verify, "verify_dkim_signature", lambda raw: (_ for _ in ()).throw(RuntimeError("no dkimpy")))
    monkeypatch.setattr(bimi_lookup, "lookup_bimi", lambda domain: (_ for _ in ()).throw(RuntimeError("no dnspython")))

    result = run(mcp_server.analyze_email.handler({"file_path": str(eml_path)}))
    text = result["content"][0]["text"]
    assert "is_error" not in result
    assert "dkim_verification" not in text
    assert "'bimi'" not in text


def test_try_dkim_verification_returns_none_on_runtime_error(tmp_path, monkeypatch):
    from websec_agent import dkim_verify

    eml_path = tmp_path / "test.eml"
    eml_path.write_bytes(b"From: a@b.com\n\nhi")
    monkeypatch.setattr(dkim_verify, "verify_dkim_signature", lambda raw: (_ for _ in ()).throw(RuntimeError()))

    assert run(mcp_server._try_dkim_verification(str(eml_path), "b.com")) is None


def test_try_bimi_lookup_returns_none_on_runtime_error(monkeypatch):
    from websec_agent import bimi_lookup

    monkeypatch.setattr(bimi_lookup, "lookup_bimi", lambda domain: (_ for _ in ()).throw(RuntimeError()))
    assert run(mcp_server._try_bimi_lookup("example.com")) is None


def test_try_dkim_verification_computes_alignment_on_valid_signature(tmp_path, monkeypatch):
    from websec_agent import dkim_verify

    eml_path = tmp_path / "test.eml"
    eml_path.write_bytes(b"From: a@paypal.com\n\nhi")
    monkeypatch.setattr(
        dkim_verify, "verify_dkim_signature", lambda raw: {"verified": True, "signing_domain": "some-saas-mailer.com"}
    )

    result = run(mcp_server._try_dkim_verification(str(eml_path), "paypal.com"))
    assert result["aligned"] is False


# --- analyze_qr_code -------------------------------------------------------


def test_analyze_qr_code_url_content_runs_full_pipeline(monkeypatch):
    from websec_agent import qr_decode

    captured = {}
    monkeypatch.setattr(qr_decode, "decode_qr_file", lambda path: "https://example.com/phish")
    monkeypatch.setattr(
        report,
        "build_result",
        lambda url, rendered, check_vt: captured.update(url=url) or {"verdict": {"label": "phishing"}},
    )

    result = run(mcp_server.analyze_qr_code.handler({"file_path": "/tmp/fake.png"}))
    text = result["content"][0]["text"]

    assert captured["url"] == "https://example.com/phish"
    assert "qr_decoded_content" in text
    assert "https://example.com/phish" in text


def test_analyze_qr_code_non_url_content_is_returned_raw(monkeypatch):
    from websec_agent import qr_decode

    monkeypatch.setattr(qr_decode, "decode_qr_file", lambda path: "WIFI:T:WPA;S:home;P:secret;;")
    result = run(mcp_server.analyze_qr_code.handler({"file_path": "/tmp/fake.png"}))
    assert "non-URL content" in result["content"][0]["text"]
    assert "WIFI:" in result["content"][0]["text"]


def test_analyze_qr_code_decoded_url_fetch_failure_is_reported(monkeypatch):
    from websec_agent import qr_decode

    monkeypatch.setattr(qr_decode, "decode_qr_file", lambda path: "http://127.0.0.1/")

    def raise_fetch_error(*a, **k):
        raise web_analysis.FetchError("blocked: private IP")

    monkeypatch.setattr(report, "build_result", raise_fetch_error)
    result = run(mcp_server.analyze_qr_code.handler({"file_path": "/tmp/fake.png"}))
    assert result["is_error"] is True
    assert "fetch failed" in result["content"][0]["text"]
    assert "127.0.0.1" in result["content"][0]["text"]


def test_analyze_qr_code_decode_error_is_reported(monkeypatch):
    from websec_agent import qr_decode

    def raise_decode_error(path):
        raise qr_decode.QRDecodeError("no QR code found in image")

    monkeypatch.setattr(qr_decode, "decode_qr_file", raise_decode_error)
    result = run(mcp_server.analyze_qr_code.handler({"file_path": "/tmp/fake.png"}))
    assert result["is_error"] is True
    assert "no QR code found" in result["content"][0]["text"]


# --- ask_webpage ------------------------------------------------------------


def test_ask_webpage_success(monkeypatch):
    monkeypatch.setattr(web_analysis, "fetch_html", lambda url: {"html": "<html></html>", "final_url": url})
    monkeypatch.setattr(web_analysis, "ask_webpage_question", lambda html, url, q: "yes, it has a login form")

    result = run(mcp_server.ask_webpage.handler({"url": "https://example.com", "question": "does it have a login form?"}))
    assert "login form" in result["content"][0]["text"]


def test_ask_webpage_fetch_error(monkeypatch):
    def raise_fetch_error(url):
        raise web_analysis.FetchError("blocked")

    monkeypatch.setattr(web_analysis, "fetch_html", raise_fetch_error)
    result = run(mcp_server.ask_webpage.handler({"url": "http://127.0.0.1", "question": "?"}))
    assert result["is_error"] is True


# --- export_report ----------------------------------------------------------


def test_export_report_success_message_format(monkeypatch):
    monkeypatch.setattr(
        report,
        "export",
        lambda url, out_dir, rendered, check_vt: {
            "report_path": f"{out_dir}/report.md",
            "ioc_path": f"{out_dir}/iocs.json",
            "result": {"verdict": {"label": "phishing"}},
        },
    )
    result = run(mcp_server.export_report.handler({"url": "https://example.com", "out_dir": "/tmp/out"}))
    text = result["content"][0]["text"]
    assert "/tmp/out/report.md" in text
    assert "/tmp/out/iocs.json" in text
    assert "phishing" in text


def test_export_report_fetch_error(monkeypatch):
    def raise_fetch_error(*a, **k):
        raise web_analysis.FetchError("blocked")

    monkeypatch.setattr(report, "export", raise_fetch_error)
    result = run(mcp_server.export_report.handler({"url": "http://127.0.0.1", "out_dir": "/tmp/out"}))
    assert result["is_error"] is True


# --- ml_classify_webpage ------------------------------------------------------


def test_ml_classify_webpage_success(monkeypatch):
    from websec_agent import classifier

    monkeypatch.setattr(web_analysis, "fetch_html", lambda url: {"html": "<html></html>", "final_url": url})
    monkeypatch.setattr(
        classifier, "classify_webpage", lambda html, url: {"label": "phishing", "phishing_probability": 0.97}
    )
    result = run(mcp_server.ml_classify_webpage.handler({"url": "https://example.com"}))
    assert "0.97" in result["content"][0]["text"]


def test_ml_classify_webpage_unavailable_model_is_reported(monkeypatch):
    def raise_runtime_error(*a, **k):
        raise RuntimeError("no trained model")

    monkeypatch.setattr(web_analysis, "fetch_html", lambda url: {"html": "<html></html>", "final_url": url})
    from websec_agent import classifier

    monkeypatch.setattr(classifier, "classify_webpage", raise_runtime_error)
    result = run(mcp_server.ml_classify_webpage.handler({"url": "https://example.com"}))
    assert result["is_error"] is True


# --- check_virustotal ----------------------------------------------------------


def test_check_virustotal_success(monkeypatch):
    from websec_agent import virustotal

    monkeypatch.setattr(virustotal, "check_url", lambda url: {"stats": {"malicious": 3}, "source": "fresh scan"})
    result = run(mcp_server.check_virustotal.handler({"url": "https://example.com"}))
    assert "malicious" in result["content"][0]["text"]


def test_check_virustotal_missing_api_key_is_reported(monkeypatch):
    from websec_agent import virustotal

    def raise_runtime_error(url):
        raise RuntimeError("VirusTotal lookup requires the VT_API_KEY environment variable")

    monkeypatch.setattr(virustotal, "check_url", raise_runtime_error)
    result = run(mcp_server.check_virustotal.handler({"url": "https://example.com"}))
    assert result["is_error"] is True
    assert "VT_API_KEY" in result["content"][0]["text"]


# --- server wiring -----------------------------------------------------------


def test_websec_server_is_named_and_sdk_backed():
    assert mcp_server.websec_server["name"] == "websec"
    assert mcp_server.websec_server["type"] == "sdk"


def test_all_ten_tools_have_distinct_names():
    tools = [
        mcp_server.analyze_webpage,
        mcp_server.analyze_webpage_rendered,
        mcp_server.screenshot_webpage,
        mcp_server.analyze_html,
        mcp_server.analyze_email,
        mcp_server.analyze_qr_code,
        mcp_server.ask_webpage,
        mcp_server.export_report,
        mcp_server.ml_classify_webpage,
        mcp_server.check_virustotal,
    ]
    names = {t.name for t in tools}
    assert len(names) == len(tools) == 10
