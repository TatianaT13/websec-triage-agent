"""Train a phishing/benign classifier on the engineered features, track the
run with MLflow (local file store, no server needed), and promote the best
model to models/phishing_classifier.joblib + a small JSON model card.

This is a small research-scale dataset (tens of samples per class) - the
metrics below are indicative, not production-grade. See README.md -> MLOps.

Usage:
    python training/train.py [data/dataset.csv]
"""
import json
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

# lbfgs can emit benign overflow/divide-by-zero warnings while optimizing
# coefficients on small, near-separable datasets; inputs are verified
# NaN/Inf-free in training/build_dataset.py's output.
warnings.filterwarnings("ignore", category=RuntimeWarning, module="sklearn")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib
import mlflow
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler

from websec_agent.features import FEATURE_NAMES

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
MLFLOW_DB = PROJECT_ROOT / "mlflow.db"

CANDIDATES = {
    "logistic_regression": LogisticRegression(max_iter=1000, class_weight="balanced"),
    "random_forest": RandomForestClassifier(n_estimators=200, max_depth=6, class_weight="balanced", random_state=42),
}


def main() -> None:
    data_path = sys.argv[1] if len(sys.argv) > 1 else "data/dataset.csv"
    df = pd.read_csv(data_path)
    X = df[FEATURE_NAMES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=42
    )

    mlflow.set_tracking_uri(f"sqlite:///{MLFLOW_DB}")
    mlflow.set_experiment("phishing-triage-classifier")

    best_name, best_model, best_scaler, best_f1 = None, None, None, -1.0
    results = {}

    for name, model in CANDIDATES.items():
        with mlflow.start_run(run_name=name):
            scaler = StandardScaler().fit(X_train)
            X_train_s = scaler.transform(X_train)
            X_test_s = scaler.transform(X_test)

            model.fit(X_train_s, y_train)
            preds = model.predict(X_test_s)
            proba = model.predict_proba(X_test_s)[:, 1]

            metrics = {
                "accuracy": accuracy_score(y_test, preds),
                "precision": precision_score(y_test, preds, zero_division=0),
                "recall": recall_score(y_test, preds, zero_division=0),
                "f1": f1_score(y_test, preds, zero_division=0),
                "roc_auc": roc_auc_score(y_test, proba),
            }
            cv_f1 = cross_val_score(model, scaler.transform(X), y, cv=5, scoring="f1")

            mlflow.log_param("model_type", name)
            mlflow.log_param("n_train", len(X_train))
            mlflow.log_param("n_test", len(X_test))
            mlflow.log_metrics(metrics)
            mlflow.log_metric("cv_f1_mean", cv_f1.mean())
            mlflow.log_metric("cv_f1_std", cv_f1.std())
            mlflow.sklearn.log_model(
                model, name="model", serialization_format=mlflow.sklearn.SERIALIZATION_FORMAT_PICKLE
            )

            results[name] = {**metrics, "cv_f1_mean": cv_f1.mean(), "cv_f1_std": cv_f1.std()}
            print(f"{name}: {metrics} | cv_f1={cv_f1.mean():.3f}+-{cv_f1.std():.3f}")

            if metrics["f1"] > best_f1:
                best_name, best_model, best_scaler, best_f1 = name, model, scaler, metrics["f1"]

    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump({"model": best_model, "scaler": best_scaler}, MODELS_DIR / "phishing_classifier.joblib")

    # Benign-class feature means - used at inference time by
    # classifier.explain_prediction() as the "what a typical benign page
    # looks like" baseline for per-prediction feature ablation (see that
    # function's docstring for why this isn't SHAP).
    benign_feature_means = {name: float(X[y == 0][name].mean()) for name in FEATURE_NAMES}

    model_card = {
        "model_type": best_name,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": str(data_path),
        "n_samples": len(df),
        "n_phish": int((y == 1).sum()),
        "n_benign": int((y == 0).sum()),
        "feature_names": FEATURE_NAMES,
        "metrics": results[best_name],
        "all_candidates": results,
        "benign_feature_means": benign_feature_means,
    }
    with open(MODELS_DIR / "phishing_classifier.meta.json", "w", encoding="utf-8") as f:
        json.dump(model_card, f, indent=2)

    print(f"\nPromoted '{best_name}' (f1={best_f1:.3f}) to {MODELS_DIR / 'phishing_classifier.joblib'}")


if __name__ == "__main__":
    main()
