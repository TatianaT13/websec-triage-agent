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
