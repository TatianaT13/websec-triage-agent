"""Tests for the trained-model inference wrapper. Assertions check shape
and value ranges, not exact labels/probabilities: the model gets
periodically retrained on a growing dataset (training/build_dataset.py),
so pinning an exact prediction here would make this test flaky by design
every time the dataset grows - that risk is covered instead by the
heuristic-rule tests in test_heuristics.py, which don't depend on a
trained model.
"""
import pytest

pytest.importorskip("sklearn", reason="requires requirements-mlops.txt")
pytest.importorskip("joblib", reason="requires requirements-mlops.txt")

from websec_agent import classifier as clf

from .fixtures import BENIGN_HTML, CREDENTIAL_PHISH_HTML

pytestmark = pytest.mark.skipif(
    not clf.MODEL_PATH.exists(), reason="no trained model - run training/build_dataset.py + train.py first"
)


def _assert_valid_result(result: dict) -> None:
    assert result["label"] in ("phishing", "benign")
    assert 0.0 <= result["phishing_probability"] <= 1.0
    assert result["source_url"]


def test_classify_benign_returns_valid_shape():
    result = clf.classify_webpage(BENIGN_HTML, "https://example.com")
    _assert_valid_result(result)


def test_classify_credential_phish_returns_valid_shape():
    result = clf.classify_webpage(CREDENTIAL_PHISH_HTML, "https://totally-legit-mail.example/")
    _assert_valid_result(result)


def test_classify_is_deterministic_for_same_input():
    a = clf.classify_webpage(CREDENTIAL_PHISH_HTML, "https://totally-legit-mail.example/")
    b = clf.classify_webpage(CREDENTIAL_PHISH_HTML, "https://totally-legit-mail.example/")
    assert a == b
