"""Tests for websec_agent/markuplm_embeddings.py. The pooling math (mean
over real tokens, ignoring padding) is tested against a fake
processor/model pair - no real transformer weights, no network - since
what actually needs checking is "does this average the right rows",
not "does the real MarkupLM encoder produce good embeddings"."""
import sys

import pytest

torch = pytest.importorskip("torch", reason="requires requirements-ml.txt")

from websec_agent import markuplm_embeddings as me


@pytest.fixture(autouse=True)
def reset_pipeline_cache():
    me._pipeline = None
    yield
    me._pipeline = None


def test_embed_html_requires_the_ml_extras(monkeypatch):
    monkeypatch.setitem(sys.modules, "transformers", None)
    with pytest.raises(RuntimeError, match="requirements-ml.txt"):
        me.embed_html("<html></html>")


def test_embed_html_mean_pools_over_real_tokens_only(monkeypatch):
    # Rows 0-1 are "real" tokens, rows 2-3 are padding (attention_mask=0) -
    # the pooled result must be the mean of rows 0-1 only.
    hidden = torch.tensor(
        [[[1.0, 1.0, 1.0], [3.0, 3.0, 3.0], [9.0, 9.0, 9.0], [9.0, 9.0, 9.0]]]
    )
    attention_mask = torch.tensor([[1, 1, 0, 0]])

    class FakeOutputs:
        last_hidden_state = hidden

    class FakeModel:
        def __call__(self, **kwargs):
            return FakeOutputs()

    class FakeProcessor:
        def __call__(self, html, return_tensors=None, truncation=None, max_length=None):
            return {"attention_mask": attention_mask}

    monkeypatch.setattr(me, "_load_pipeline", lambda: (FakeProcessor(), FakeModel()))

    result = me.embed_html("<html></html>")
    assert result == pytest.approx([2.0, 2.0, 2.0])


def test_embed_html_returns_a_plain_list_of_floats(monkeypatch):
    hidden = torch.tensor([[[5.0, 6.0]]])
    attention_mask = torch.tensor([[1]])

    class FakeOutputs:
        last_hidden_state = hidden

    class FakeModel:
        def __call__(self, **kwargs):
            return FakeOutputs()

    class FakeProcessor:
        def __call__(self, html, return_tensors=None, truncation=None, max_length=None):
            return {"attention_mask": attention_mask}

    monkeypatch.setattr(me, "_load_pipeline", lambda: (FakeProcessor(), FakeModel()))

    result = me.embed_html("<html></html>")
    assert isinstance(result, list)
    assert all(isinstance(v, float) for v in result)
