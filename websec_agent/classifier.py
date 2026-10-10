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
_benign_feature_means: dict | None = None


def _load():
    global _bundle, _model_version, _benign_feature_means
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

            meta = json.loads(META_PATH.read_text())
            _model_version = meta["trained_at"]
            _benign_feature_means = meta.get("benign_feature_means")  # absent for models trained before this existed
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
        "explanation": explain_prediction(row),
    }


def explain_prediction(row: dict, top_n: int = 3) -> list[dict]:
    """Up to top_n features that most influenced THIS specific prediction,
    via feature ablation: replace each feature's value, one at a time,
    with the training set's benign-class mean (the stored
    "what a typical benign page looks like" baseline), and measure how
    much the predicted phishing probability drops. A feature whose
    ablation drops the probability a lot was doing a lot of work for
    THIS page - not just globally important across all predictions, but
    important HERE, which is what an analyst looking at one specific
    verdict actually wants to know.

    Deliberately not SHAP: that would add a new, fairly heavy dependency
    (C extensions) for something this simpler, more auditable
    approximation already covers reasonably well for a model this small
    - one extra forward pass per feature (cheap on a few hundred trees),
    each holding every OTHER feature fixed at this page's actual value.

    [] if the loaded model predates benign_feature_means being saved
    (older model card) - explanation is a bonus, not something that
    should break classify_webpage() for models trained before this."""
    bundle = _load()
    if not _benign_feature_means:
        return []

    import pandas as pd

    from . import features as feat

    model, scaler = bundle["model"], bundle["scaler"]
    base_values = [row[name] for name in feat.FEATURE_NAMES]
    # float from the start - ablated values (benign-class means) are
    # floats regardless of whether the original feature is an int count,
    # and assigning a float into an int64 column later would otherwise
    # warn/degrade under newer pandas versions.
    base_df = pd.DataFrame([base_values], columns=feat.FEATURE_NAMES, dtype=float)
    base_proba = float(model.predict_proba(scaler.transform(base_df))[0][1])

    contributions = []
    for i, name in enumerate(feat.FEATURE_NAMES):
        if name not in _benign_feature_means:
            continue
        ablated_df = base_df.copy()
        ablated_df.iloc[0, i] = _benign_feature_means[name]
        ablated_proba = float(model.predict_proba(scaler.transform(ablated_df))[0][1])
        contributions.append({
            "feature": name,
            "value": base_values[i],
            "contribution": round(base_proba - ablated_proba, 4),
        })

    contributions.sort(key=lambda c: abs(c["contribution"]), reverse=True)
    return contributions[:top_n]
