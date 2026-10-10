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
    assert isinstance(result["explanation"], list)
    for item in result["explanation"]:
        assert item["feature"]
        assert isinstance(item["contribution"], float)


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


# --- per-prediction explanation (feature ablation, not SHAP) --------------


def test_explanation_is_non_empty_for_a_real_model():
    # Only meaningful if the loaded model card actually has
    # benign_feature_means - true for any model trained after this
    # feature was added, which train.py always populates.
    result = clf.classify_webpage(CREDENTIAL_PHISH_HTML, "https://totally-legit-mail.example/")
    assert len(result["explanation"]) > 0


def test_explanation_respects_top_n():
    from websec_agent import features as feat

    row = feat.extract_features(CREDENTIAL_PHISH_HTML, "https://totally-legit-mail.example/")
    assert len(clf.explain_prediction(row, top_n=2)) <= 2
    assert len(clf.explain_prediction(row, top_n=5)) <= 5


def test_explanation_is_sorted_by_absolute_contribution():
    from websec_agent import features as feat

    row = feat.extract_features(CREDENTIAL_PHISH_HTML, "https://totally-legit-mail.example/")
    explanation = clf.explain_prediction(row, top_n=10)
    magnitudes = [abs(item["contribution"]) for item in explanation]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_explanation_empty_without_benign_feature_means(monkeypatch):
    from websec_agent import features as feat

    clf._load()  # ensure the real model is loaded first
    monkeypatch.setattr(clf, "_benign_feature_means", None)
    row = feat.extract_features(CREDENTIAL_PHISH_HTML, "https://totally-legit-mail.example/")
    assert clf.explain_prediction(row) == []
