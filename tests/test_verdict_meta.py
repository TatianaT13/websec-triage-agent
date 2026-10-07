"""Tests for the learned meta-model path in combine_verdicts(). Uses a
fake bundle with fixed, hand-picked coefficients (not the real trained
artifact in models/verdict_meta_model.joblib) so these stay deterministic
regardless of what a future retrain learns - test_verdict.py covers the
hand-coded fallback the same way, for the same reason.
"""
import numpy as np
import pytest

sklearn = pytest.importorskip("sklearn", reason="requires requirements-mlops.txt")

from websec_agent import verdict as vd

LOW = {"score": 0, "level": "low", "reasons": []}
HIGH = {"score": 10, "level": "high", "reasons": ["some reason"]}


def _ml(prob):
    return {"label": "phishing" if prob >= 0.5 else "benign", "phishing_probability": prob, "model_version": "x"}


class _FakeScaler:
    """Identity scaler - keeps the fake bundle's math easy to reason
    about instead of needing a real fitted StandardScaler."""

    def transform(self, X):
        return np.asarray(X)


class _FakeMetaModel:
    """predict_proba returns a fixed probability regardless of input -
    enough to test the thresholding/wiring in combine_verdicts, which is
    what this file is actually responsible for testing (not sklearn's
    LogisticRegression, which has its own test suite upstream)."""

    def __init__(self, phishing_probability: float):
        self._p = phishing_probability

    def predict_proba(self, X):
        return np.array([[1 - self._p, self._p]])


@pytest.fixture
def fake_meta_model(monkeypatch):
    def _install(phishing_probability: float):
        bundle = {"model": _FakeMetaModel(phishing_probability), "scaler": _FakeScaler()}
        monkeypatch.setattr(vd, "_load_meta_model", lambda: bundle)

    return _install


def test_meta_model_high_probability_is_phishing(fake_meta_model):
    fake_meta_model(0.9)
    result = vd.combine_verdicts(LOW, _ml(0.5))
    assert result["label"] == "phishing"
    assert result["meta_probability"] == pytest.approx(0.9)
    assert "learned meta-model" in result["confidence"]


def test_meta_model_low_probability_is_benign(fake_meta_model):
    fake_meta_model(0.1)
    result = vd.combine_verdicts(HIGH, _ml(0.5))
    assert result["label"] == "benign"


def test_meta_model_mid_probability_is_uncertain(fake_meta_model):
    fake_meta_model(0.5)
    result = vd.combine_verdicts(LOW, _ml(0.5))
    assert result["label"] == "uncertain"


def test_meta_model_overrides_the_hand_coded_thresholds(fake_meta_model):
    # same inputs as test_verdict.py's
    # test_heuristic_high_overrides_low_ml_probability, which asserts
    # "phishing" via the fallback - here the meta-model's own (fake, low)
    # probability wins instead, proving it's actually consulted first.
    fake_meta_model(0.2)
    result = vd.combine_verdicts(HIGH, _ml(0.4))
    assert result["label"] == "benign"


def test_meta_model_is_skipped_when_ml_is_none(fake_meta_model):
    fake_meta_model(0.9)
    result = vd.combine_verdicts(HIGH, None)
    assert result["meta_probability"] is None
    assert result["label"] == "phishing"  # heuristic-only fallback, not the fake 0.9


def test_meta_model_unavailable_falls_back_cleanly(monkeypatch):
    monkeypatch.setattr(vd, "_load_meta_model", lambda: None)
    result = vd.combine_verdicts(HIGH, _ml(0.4))
    assert result["meta_probability"] is None
    assert result["label"] == "phishing"  # the hand-coded rule's answer


def test_virustotal_still_overrides_the_meta_models_verdict(fake_meta_model):
    fake_meta_model(0.1)  # meta-model says benign
    vt = {"source": "cached", "url": "x", "stats": {"malicious": 5, "suspicious": 0, "harmless": 50}}
    result = vd.combine_verdicts(LOW, _ml(0.1), vt_result=vt)
    assert result["label"] == "phishing"
    assert "VirusTotal" in result["confidence"]
