"""Tests for the benign-candidate verification filter in
training/build_dataset.py - see README.md -> Limites connues: Tranco and
PhiUSIIL are third-party rankings/datasets, not hand-verified, so a
malicious or temporarily well-ranked domain could otherwise slip into the
benign (label=0) training class."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from training import build_dataset as bd


def _row(**overrides) -> dict:
    row = {"brand_in_title_mismatch": 0, "brand_in_text_mismatch": 0, "heuristic_score": 0}
    row.update(overrides)
    return row


def test_clean_candidate_is_not_rejected():
    assert bd._reject_reason(_row()) is None


def test_brand_in_title_mismatch_is_rejected():
    assert bd._reject_reason(_row(brand_in_title_mismatch=1)) is not None


def test_brand_in_text_mismatch_is_rejected():
    assert bd._reject_reason(_row(brand_in_text_mismatch=1)) is not None


def test_high_heuristic_score_is_rejected():
    assert bd._reject_reason(_row(heuristic_score=4)) is not None


def test_low_heuristic_score_alone_is_not_rejected():
    assert bd._reject_reason(_row(heuristic_score=3)) is None


def test_collect_with_verify_benign_skips_rejected_candidates(monkeypatch):
    def fake_fetch_html(url):
        return {"final_url": url, "status_code": 200, "html": "<html>x</html>"}

    def fake_extract_features(html, url):
        # the "evil" URL looks like a brand/domain mismatch; the other looks clean.
        return _row(brand_in_title_mismatch=1 if "evil" in url else 0)

    monkeypatch.setattr(bd.wa, "fetch_html", fake_fetch_html)
    monkeypatch.setattr(bd.feat, "extract_features", fake_extract_features)

    rows = bd.collect(
        ["https://evil-lookalike.example", "https://clean.example"],
        label=0,
        max_count=10,
        seen=set(),
        verify_benign=True,
    )

    assert [r["source_url"] for r in rows] == ["https://clean.example"]


def test_collect_without_verify_benign_keeps_everything(monkeypatch):
    def fake_fetch_html(url):
        return {"final_url": url, "status_code": 200, "html": "<html>x</html>"}

    def fake_extract_features(html, url):
        return _row(brand_in_title_mismatch=1 if "evil" in url else 0)

    monkeypatch.setattr(bd.wa, "fetch_html", fake_fetch_html)
    monkeypatch.setattr(bd.feat, "extract_features", fake_extract_features)

    rows = bd.collect(
        ["https://evil-lookalike.example", "https://clean.example"],
        label=0,
        max_count=10,
        seen=set(),
        verify_benign=False,
    )

    assert len(rows) == 2
