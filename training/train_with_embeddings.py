"""Honest comparison: does concatenating a frozen MarkupLM embedding onto
the existing structural/heuristic feature vector (websec_agent/features.py)
actually improve the classifier, or is it not worth the extra complexity
and compute cost? See websec_agent/markuplm_embeddings.py's module
docstring for why this is kept as a separate, additive experiment rather
than baked into the primary classifier (training/train.py).

Embeddings can only be captured at collection time
(training/build_dataset.py --with-embeddings), because that's the only
point the raw HTML is still available - the dataset deliberately never
stores it (see build_dataset.py's module docstring: "nothing malicious is
stored"). Historical rows collected without that flag simply have an
empty markuplm_embedding column; this script only trains/evaluates on
rows that actually have one. Growing that subset means running
build_dataset.py --with-embeddings again, not reprocessing old rows.

768 embedding dimensions against a dataset of a few hundred rows is a
real overfitting risk for a plain logistic regression, so the embedding
is first reduced with PCA (fit on the training fold only, to avoid
leakage) before being concatenated with the structural features.

Usage:
    python training/train_with_embeddings.py [data/dataset.csv] [pca_components]
"""
import json
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=RuntimeWarning, module="sklearn")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from websec_agent.features import FEATURE_NAMES
from websec_agent.markuplm_embeddings import EMBEDDING_DIM

# Below this many embedded rows per class, a train/test split is too noisy
# to mean anything - the script refuses to pretend otherwise.
MIN_ROWS_PER_CLASS = 10


def _parse_embedding(raw) -> list[float] | None:
    """None for missing/blank/malformed - never raises, since this runs
    over historical rows that were never given an embedding at all."""
    if raw is None or raw == "" or (isinstance(raw, float) and np.isnan(raw)):
        return None
    try:
        values = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(values, list) or len(values) != EMBEDDING_DIM:
        return None
    return values


def load_embedded_subset(df: pd.DataFrame) -> pd.DataFrame:
    """The strict subset of rows that actually have a usable embedding -
    see module docstring for why most historical rows won't."""
    if "markuplm_embedding" not in df.columns:
        return df.iloc[0:0].copy()
    parsed = df["markuplm_embedding"].apply(_parse_embedding)
    mask = parsed.notna()
    subset = df[mask].copy()
    subset["_embedding"] = parsed[mask]
    return subset


def _fit_eval(pipeline, X_train, y_train, X_test, y_test) -> dict:
    pipeline.fit(X_train, y_train)
    preds = pipeline.predict(X_test)
    proba = pipeline.predict_proba(X_test)[:, 1]
    return {
        "accuracy": accuracy_score(y_test, preds),
        "precision": precision_score(y_test, preds, zero_division=0),
        "recall": recall_score(y_test, preds, zero_division=0),
        "f1": f1_score(y_test, preds, zero_division=0),
        "roc_auc": roc_auc_score(y_test, proba) if len(set(y_test)) > 1 else float("nan"),
    }


def _make_pipeline() -> Pipeline:
    return Pipeline(
        [("scale", StandardScaler()), ("clf", LogisticRegression(max_iter=1000, class_weight="balanced"))]
    )


def main() -> None:
    data_path = sys.argv[1] if len(sys.argv) > 1 else "data/dataset.csv"
    pca_components = int(sys.argv[2]) if len(sys.argv) > 2 else 20

    df = pd.read_csv(data_path)
    subset = load_embedded_subset(df)
    n_phish = int((subset["label"] == 1).sum()) if len(subset) else 0
    n_benign = int((subset["label"] == 0).sum()) if len(subset) else 0
    print(f"Rows with a usable MarkupLM embedding: {len(subset)} ({n_phish} phish, {n_benign} benign)")

    if n_phish < MIN_ROWS_PER_CLASS or n_benign < MIN_ROWS_PER_CLASS:
        print(
            f"Not enough embedded rows yet (need >= {MIN_ROWS_PER_CLASS} per class) - run:\n"
            f"  python training/build_dataset.py <n> {data_path} --with-embeddings"
        )
        sys.exit(1)

    y = subset["label"]
    X_struct = subset[FEATURE_NAMES].to_numpy()
    X_emb = np.vstack(subset["_embedding"].to_list())

    Xs_train, Xs_test, Xe_train, Xe_test, y_train, y_test = train_test_split(
        X_struct, X_emb, y, test_size=0.3, stratify=y, random_state=42
    )

    baseline_metrics = _fit_eval(_make_pipeline(), Xs_train, y_train, Xs_test, y_test)

    # min(..., len(Xe_train) - 1) - PCA can't produce more components than
    # training samples minus one; relevant on a still-small embedded subset.
    n_components = max(1, min(pca_components, len(Xe_train) - 1, EMBEDDING_DIM))
    pca = PCA(n_components=n_components, random_state=42).fit(Xe_train)
    Xe_train_r = pca.transform(Xe_train)
    Xe_test_r = pca.transform(Xe_test)

    X_train_combined = np.hstack([Xs_train, Xe_train_r])
    X_test_combined = np.hstack([Xs_test, Xe_test_r])
    extended_metrics = _fit_eval(_make_pipeline(), X_train_combined, y_train, X_test_combined, y_test)

    print(f"Structural features only:              {baseline_metrics}")
    print(f"+ MarkupLM embedding (PCA={n_components} of {EMBEDDING_DIM}):   {extended_metrics}")

    verdict = (
        "embeddings help on this dataset size"
        if extended_metrics["f1"] > baseline_metrics["f1"]
        else "no improvement over structural features alone on this dataset size"
    )
    print(f"\n{verdict} (f1 {baseline_metrics['f1']:.3f} -> {extended_metrics['f1']:.3f})")


if __name__ == "__main__":
    main()
