"""Inference wrapper around the trained model (models/phishing_classifier.joblib).
Lazily imports scikit-learn/joblib so the base install (requirements.txt)
never needs the training stack - only requirements-mlops.txt does.
"""
from __future__ import annotations

from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "phishing_classifier.joblib"
META_PATH = Path(__file__).resolve().parent.parent / "models" / "phishing_classifier.meta.json"

_bundle = None
_model_version = None


def _load():
    global _bundle, _model_version
    if _bundle is None:
        if not MODEL_PATH.exists():
            raise RuntimeError(
                f"No trained model at {MODEL_PATH}. Run training/build_dataset.py then "
                "training/train.py first (requires requirements-mlops.txt)."
            )
        try:
            import joblib
        except ImportError as exc:
            raise RuntimeError(
                "Classifier inference requires the MLOps extras: pip install -r requirements-mlops.txt"
            ) from exc
        _bundle = joblib.load(MODEL_PATH)
        if META_PATH.exists():
            import json

            _model_version = json.loads(META_PATH.read_text())["trained_at"]
    return _bundle


def classify_webpage(html: str, url: str) -> dict:
    """Run the trained classifier on a fetched page. Complements, but does
    not replace, the hand-tuned heuristic score in web_analysis.score_phishing."""
    import pandas as pd

    from . import features as feat

    bundle = _load()
    row = feat.extract_features(html, url)
    X = pd.DataFrame([[row[name] for name in feat.FEATURE_NAMES]], columns=feat.FEATURE_NAMES)
    X_scaled = bundle["scaler"].transform(X)
    proba = float(bundle["model"].predict_proba(X_scaled)[0][1])
    label = "phishing" if proba >= 0.5 else "benign"

    return {
        "label": label,
        "phishing_probability": round(proba, 4),
        "model_version": _model_version,
        "source_url": url,
    }
