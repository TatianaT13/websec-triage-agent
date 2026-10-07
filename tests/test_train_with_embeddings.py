"""Tests for the pure helper functions in training/train_with_embeddings.py -
the parsing/filtering logic that decides which dataset rows actually have a
usable MarkupLM embedding, kept separate from the model-training I/O so it
can be tested without a real transformer or network access."""
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("sklearn", reason="requires requirements-mlops.txt")
pandas = pytest.importorskip("pandas", reason="requires requirements-mlops.txt")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from training import train_with_embeddings as twe

pd = pandas

DIM = twe.EMBEDDING_DIM


def test_parses_a_valid_embedding():
    raw = json.dumps([0.1] * DIM)
    assert twe._parse_embedding(raw) == [0.1] * DIM


def test_blank_string_is_not_a_valid_embedding():
    assert twe._parse_embedding("") is None


def test_none_is_not_a_valid_embedding():
    assert twe._parse_embedding(None) is None


def test_nan_is_not_a_valid_embedding():
    assert twe._parse_embedding(float("nan")) is None


def test_malformed_json_is_not_a_valid_embedding():
    assert twe._parse_embedding("not json") is None


def test_wrong_length_is_not_a_valid_embedding():
    assert twe._parse_embedding(json.dumps([0.1] * (DIM - 1))) is None


def test_non_list_json_is_not_a_valid_embedding():
    assert twe._parse_embedding(json.dumps({"not": "a list"})) is None


def test_load_embedded_subset_keeps_only_rows_with_a_valid_embedding():
    df = pd.DataFrame(
        {
            "label": [1, 0, 1],
            "markuplm_embedding": [json.dumps([0.2] * DIM), "", json.dumps([0.3] * DIM)],
        }
    )
    subset = twe.load_embedded_subset(df)
    assert len(subset) == 2
    assert list(subset["label"]) == [1, 1]
    assert subset["_embedding"].iloc[0] == [0.2] * DIM


def test_load_embedded_subset_handles_missing_column():
    df = pd.DataFrame({"label": [1, 0]})
    subset = twe.load_embedded_subset(df)
    assert len(subset) == 0


def test_fit_eval_returns_the_expected_metric_keys():
    import numpy as np

    rng = np.random.RandomState(0)
    X_train = rng.rand(20, 3)
    y_train = pd.Series([0, 1] * 10)
    X_test = rng.rand(10, 3)
    y_test = pd.Series([0, 1] * 5)

    metrics = twe._fit_eval(twe._make_pipeline(), X_train, y_train, X_test, y_test)
    assert set(metrics) == {"accuracy", "precision", "recall", "f1", "roc_auc"}
