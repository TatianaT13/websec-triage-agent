"""Tests for report.build_result_from_html() - the no-live-fetch path used
for pasted HTML or content extracted from an .eml (see
test_offline_content.py for the .eml extraction itself)."""
from websec_agent.report import build_markdown_report, build_result_from_html

from .fixtures import BENIGN_HTML, CREDENTIAL_PHISH_HTML


def test_status_code_is_none_nothing_was_fetched():
    result = build_result_from_html(BENIGN_HTML, "https://example.com")
    assert result["status_code"] is None
    assert result["final_url"] == "https://example.com"


def test_heuristic_and_verdict_still_run_without_a_live_fetch():
    result = build_result_from_html(CREDENTIAL_PHISH_HTML, "https://totally-legit-mail.example/")
    assert result["phishing_heuristic"]["level"] == "high"
    reasons = " ".join(result["phishing_heuristic"]["reasons"])
    assert "password field submits to external domain" in reasons
    assert result["verdict"]["label"] == "phishing"


def test_benign_content_is_not_flagged():
    result = build_result_from_html(BENIGN_HTML, "https://example.com")
    assert result["phishing_heuristic"]["level"] == "low"


def test_markdown_report_notes_content_was_not_fetched():
    result = build_result_from_html(BENIGN_HTML, "https://example.com")
    md = build_markdown_report(result)
    assert "non récupéré" in md
