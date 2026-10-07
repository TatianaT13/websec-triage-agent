"""Train a small "meta-model" that replaces the hand-coded thresholds in
websec_agent/verdict.py (PHISHING_PROB_HIGH, YOUNG_DOMAIN_DAYS, etc.) for
combining the heuristic score + ML probability + domain age into one
verdict - a learned weighting instead of numbers we picked by eye.

This is classic two-level stacking: the inputs are three *upstream*
signals (not raw page features), so the out-of-fold ML probability is
computed with cross_val_predict() to avoid leaking each row's own label
into its own meta-feature (a model's prediction on a row it was trained
on is systematically more confident than on unseen data - training the
meta-model on those would teach it to over-trust the base model).

VirusTotal is deliberately NOT a meta-model input: build_dataset.py
never queried VT for historical rows (that's the whole point of keeping
VT out of the training pipeline - see its module docstring), so there's
no VT-labeled training data to learn from, and "trust a real vendor
flagging malicious" doesn't really need learning anyway. It stays the
separate hard override already in verdict.py.

Usage:
    python training/train_verdict_meta.py [data/dataset.csv]
"""
import json
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

warnings.filterwarnings("ignore", category=RuntimeWarning, module="sklearn")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import cross_val_predict, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler

from websec_agent.features import FEATURE_NAMES

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
META_FEATURE_NAMES = ["heuristic_score", "ml_probability", "domain_age_days", "domain_age_unknown"]


def _reconstruct_heuristic_score(row: pd.Series) -> float:
    """Approximates web_analysis.score_phishing()'s aggregate score from
    the granular boolean/count features already stored for this row -
    used only for historical rows collected before heuristic_score was
    added as its own column (see features.py). One known imprecision:
    urgency_word_count was stored as a 0/1 "did any urgency reason fire"
    flag, not the real min(len(hits), 3) - so this under-counts by up to
    2 points on the (rare) rows with 2-3 urgency phrases matched."""
    score = 0
    if row["brand_in_title_mismatch"]:
        score += 3
    elif row["brand_in_text_mismatch"]:
        score += 1
    if row["has_external_password_action"]:
        score += 4
    elif row["has_non_https_password_action"]:
        score += 2
    if row["favicon_is_external"]:
        score += 1
    if row["meta_refresh"]:
        score += 1
    if row["punycode_domain_count"] > 0:
        score += 3
    if row["ip_literal_url_count"] > 0:
        score += 2
    if row["suspicious_tld_domain_count"] > 0:
        score += 1
    if row["urgency_word_count"] > 0:
        score += 1
    return score


def _heuristic_level(score: float) -> str:
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _should_promote(new_f1: float, baseline_f1: float) -> bool:
    """Strictly greater-than, not >=: on a tie, keep whatever's already on
    disk rather than take the cost (and noise) of swapping files for no
    measurable gain."""
    return new_f1 > baseline_f1


def _baseline_hand_coded_label(heuristic_score, ml_prob, domain_age_days, domain_age_unknown) -> str:
    """Re-implements verdict.py's current if/elif thresholds, so we can
    honestly compare the learned meta-model against what's already
    shipped on the exact same rows - "we trained something" isn't the
    same claim as "it's actually better"."""
    level = _heuristic_level(heuristic_score)
    if level == "high" or ml_prob >= 0.75:
        label = "phishing"
    elif level == "low" and ml_prob <= 0.25:
        label = "benign"
    else:
        label = "uncertain"
        if not domain_age_unknown:
            if domain_age_days < 30:
                label = "phishing"
            elif domain_age_days > 365:
                label = "benign"
    return label


def main() -> None:
    data_path = sys.argv[1] if len(sys.argv) > 1 else "data/dataset.csv"
    df = pd.read_csv(data_path)
    y = df["label"]

    if "heuristic_score" in df.columns:
        df["heuristic_score"] = df["heuristic_score"].where(
            df["heuristic_score"].notna(), df.apply(_reconstruct_heuristic_score, axis=1)
        )
    else:
        df["heuristic_score"] = df.apply(_reconstruct_heuristic_score, axis=1)

    # Out-of-fold ML probability: the same model class/features as the
    # primary classifier (training/train.py), but predictions on data
    # each fold never trained on - a fair meta-feature, not a leak.
    X_base = df[FEATURE_NAMES]
    scaler = StandardScaler().fit(X_base)
    X_base_scaled = scaler.transform(X_base)
    base_model = LogisticRegression(max_iter=1000, class_weight="balanced")
    df["ml_probability"] = cross_val_predict(base_model, X_base_scaled, y, cv=5, method="predict_proba")[:, 1]

    X_meta = df[META_FEATURE_NAMES]
    X_train, X_test, y_train, y_test = train_test_split(X_meta, y, test_size=0.25, stratify=y, random_state=42)

    meta_scaler = StandardScaler().fit(X_train)
    meta_model = LogisticRegression(max_iter=1000, class_weight="balanced")
    meta_model.fit(meta_scaler.transform(X_train), y_train)

    preds = meta_model.predict(meta_scaler.transform(X_test))
    proba = meta_model.predict_proba(meta_scaler.transform(X_test))[:, 1]
    metrics = {
        "accuracy": accuracy_score(y_test, preds),
        "precision": precision_score(y_test, preds, zero_division=0),
        "recall": recall_score(y_test, preds, zero_division=0),
        "f1": f1_score(y_test, preds, zero_division=0),
        "roc_auc": roc_auc_score(y_test, proba),
    }
    cv_f1 = cross_val_score(meta_model, meta_scaler.transform(X_meta), y, cv=5, scoring="f1")

    # Honest baseline comparison: hand-coded thresholds on the SAME test
    # rows, scored as a binary call (its "uncertain" counts as a miss on
    # whichever side the true label is - same all-or-nothing standard the
    # learned model is held to above).
    baseline_preds = [
        1 if _baseline_hand_coded_label(hs, ml, da, dau) == "phishing" else 0
        for hs, ml, da, dau in zip(
            X_test["heuristic_score"], X_test["ml_probability"], X_test["domain_age_days"], X_test["domain_age_unknown"]
        )
    ]
    baseline_f1 = f1_score(y_test, baseline_preds, zero_division=0)
    baseline_acc = accuracy_score(y_test, baseline_preds)

    print(f"Learned meta-model: {metrics} | cv_f1={cv_f1.mean():.3f}+-{cv_f1.std():.3f}")
    print(f"Hand-coded baseline (same test rows): accuracy={baseline_acc:.3f} f1={baseline_f1:.3f}")
    print("Meta-model coefficients:", dict(zip(META_FEATURE_NAMES, meta_model.coef_[0].round(3))))

    card = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": str(data_path),
        "n_samples": len(df),
        "feature_names": META_FEATURE_NAMES,
        "metrics": metrics,
        "cv_f1_mean": cv_f1.mean(),
        "cv_f1_std": cv_f1.std(),
        "baseline_hand_coded_accuracy": baseline_acc,
        "baseline_hand_coded_f1": baseline_f1,
        "coefficients": dict(zip(META_FEATURE_NAMES, meta_model.coef_[0].tolist())),
    }

    # Promote only if it actually beats the hand-coded thresholds on this
    # same test split - "we trained something" isn't "it's better" (see
    # docstring above). If not, both files are left exactly as they were
    # (an older, better-performing model and ITS OWN meta.json describing
    # it) rather than overwritten with this run's worse attempt -
    # combine_verdicts() keeps using whichever model is actually on disk,
    # or falls back to the hand-coded thresholds if there's none yet.
    card["promoted"] = _should_promote(metrics["f1"], baseline_f1)
    if card["promoted"]:
        MODELS_DIR.mkdir(exist_ok=True)
        joblib.dump({"model": meta_model, "scaler": meta_scaler}, MODELS_DIR / "verdict_meta_model.joblib")
        with open(MODELS_DIR / "verdict_meta_model.meta.json", "w", encoding="utf-8") as f:
            json.dump(card, f, indent=2)
        print(f"\nf1 {metrics['f1']:.3f} > baseline {baseline_f1:.3f} - saved to {MODELS_DIR / 'verdict_meta_model.joblib'}")
    else:
        print(
            f"\nf1 {metrics['f1']:.3f} <= baseline {baseline_f1:.3f} on this run - NOT promoted "
            "(existing model file and meta.json, if any, left untouched; combine_verdicts() keeps "
            "using whichever model is actually on disk, or falls back to the hand-coded thresholds)"
        )


if __name__ == "__main__":
    main()
