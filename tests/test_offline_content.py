"""Tests for extracting analyzable HTML from an .eml file saved on disk,
instead of requiring a live URL fetch."""
from email.message import EmailMessage

import pytest

from websec_agent import offline_content as oc


def _write_eml(tmp_path, msg: EmailMessage, name: str = "sample.eml") -> str:
    path = tmp_path / name
    path.write_bytes(bytes(msg))
    return str(path)


def test_extracts_html_part_and_headers(tmp_path):
    msg = EmailMessage()
    msg["Subject"] = "Your file is ready"
    msg["From"] = "no-reply@wetransfer-secure-delivery.com"
    msg["To"] = "victim@example.com"
    msg["Date"] = "Tue, 06 Oct 2026 10:00:00 +0000"
    msg.set_content("plain text fallback")
    msg.add_alternative("<html><head><title>WeTransfer</title></head><body>hi</body></html>", subtype="html")

    path = _write_eml(tmp_path, msg)
    parsed = oc.parse_eml_file(path)

    assert "<title>WeTransfer</title>" in parsed["html"]
    assert parsed["subject"] == "Your file is ready"
    assert parsed["from"] == "no-reply@wetransfer-secure-delivery.com"
    assert parsed["from_domain"] == "wetransfer-secure-delivery.com"


def test_falls_back_to_plain_text_when_no_html_part(tmp_path):
    msg = EmailMessage()
    msg["Subject"] = "plain only"
    msg["From"] = "sender@example.com"
    msg.set_content("just plain text, no html <not-a-tag>")

    path = _write_eml(tmp_path, msg)
    parsed = oc.parse_eml_file(path)

    assert "<html>" in parsed["html"]
    # the literal text must be escaped, not interpreted as markup
    assert "&lt;not-a-tag&gt;" in parsed["html"]


def test_from_domain_is_empty_when_no_from_header(tmp_path):
    msg = EmailMessage()
    msg["Subject"] = "no sender"
    msg.set_content("body")

    path = _write_eml(tmp_path, msg)
    parsed = oc.parse_eml_file(path)

    assert parsed["from_domain"] == ""


def test_guess_url_hint_from_domain():
    assert oc.guess_url_hint("wetransfer-secure-delivery.com") == "https://wetransfer-secure-delivery.com/"


def test_guess_url_hint_falls_back_when_domain_is_empty():
    assert oc.guess_url_hint("") == "https://unknown-sender.invalid/"


def test_parse_eml_file_raises_for_missing_file():
    with pytest.raises(OSError):
        oc.parse_eml_file("/no/such/file.eml")


# --- SPF/DKIM/DMARC parsing ------------------------------------------------

GOOGLE_STYLE_PASS_HEADER = (
    "mx.google.com; "
    "dkim=pass header.i=@example.com header.s=selector1 header.b=abc123; "
    "spf=pass (google.com: domain of sender@example.com designates 1.2.3.4 as "
    "permitted sender) smtp.mailfrom=sender@example.com; "
    "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com"
)

SPOOFED_FAIL_HEADER = (
    "mx.google.com; dkim=none (message not signed); "
    "spf=fail (google.com: domain of service@paypal.com does not designate "
    "203.0.113.9 as permitted sender) smtp.mailfrom=service@paypal.com; "
    "dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com"
)


def test_parses_a_passing_authentication_results_header(tmp_path):
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["Authentication-Results"] = GOOGLE_STYLE_PASS_HEADER
    msg.set_content("body")

    parsed = oc.parse_eml_file(_write_eml(tmp_path, msg))
    assert parsed["auth"] == {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "dkim_signing_domain": None,
        "header_count": 1,
    }


def test_parses_a_failing_authentication_results_header(tmp_path):
    msg = EmailMessage()
    msg["From"] = "service@paypal.com"
    msg["Authentication-Results"] = SPOOFED_FAIL_HEADER
    msg.set_content("body")

    parsed = oc.parse_eml_file(_write_eml(tmp_path, msg))
    assert parsed["auth"]["spf"] == "fail"
    assert parsed["auth"]["dkim"] == "none"
    assert parsed["auth"]["dmarc"] == "fail"


def test_missing_authentication_results_header_is_all_none(tmp_path):
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg.set_content("body")

    parsed = oc.parse_eml_file(_write_eml(tmp_path, msg))
    assert parsed["auth"] == {
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "dkim_signing_domain": None,
        "header_count": 0,
    }


def test_extracts_dkim_signing_domain(tmp_path):
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["DKIM-Signature"] = "v=1; a=rsa-sha256; d=mail-relay.example; s=selector1; b=xxxx"
    msg.set_content("body")

    parsed = oc.parse_eml_file(_write_eml(tmp_path, msg))
    assert parsed["auth"]["dkim_signing_domain"] == "mail-relay.example"


# --- apply_email_auth -------------------------------------------------------

BENIGN_VERDICT = {"label": "benign", "confidence": "both signals agree"}
PHISHING_VERDICT = {"label": "phishing", "confidence": "both signals agree"}
NO_AUTH = {"spf": None, "dkim": None, "dmarc": None}


def test_auth_fail_pushes_benign_verdict_to_phishing():
    result = oc.apply_email_auth(BENIGN_VERDICT, {"spf": "fail", "dkim": "none", "dmarc": "fail"})
    assert result["label"] == "phishing"
    assert "spf" in result["confidence"] and "dmarc" in result["confidence"]
    assert "not independently re-verified" in result["confidence"]


def test_auth_pass_does_not_change_a_benign_verdict():
    # deliberately asymmetric - see apply_email_auth's docstring
    result = oc.apply_email_auth(BENIGN_VERDICT, {"spf": "pass", "dkim": "pass", "dmarc": "pass"})
    assert result == BENIGN_VERDICT


def test_no_auth_headers_does_not_change_the_verdict():
    result = oc.apply_email_auth(BENIGN_VERDICT, NO_AUTH)
    assert result == BENIGN_VERDICT


def test_auth_fail_is_still_visible_when_already_phishing():
    result = oc.apply_email_auth(PHISHING_VERDICT, {"spf": "fail", "dkim": None, "dmarc": "fail"})
    assert result["label"] == "phishing"
    assert "both signals agree" in result["confidence"]
    assert "authentication failed" in result["confidence"]


def test_apply_email_auth_does_not_mutate_the_input():
    original = dict(BENIGN_VERDICT)
    oc.apply_email_auth(BENIGN_VERDICT, {"spf": "fail", "dkim": None, "dmarc": None})
    assert BENIGN_VERDICT == original
