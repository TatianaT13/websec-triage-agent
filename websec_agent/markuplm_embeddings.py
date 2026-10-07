"""Frozen MarkupLM embeddings as an optional extra feature source for the
trained classifier (see README.md -> MLOps: v2 "embeddings MarkupLM gelés
comme features"). "Frozen" means the transformer's weights are never
fine-tuned here - it's used purely as a fixed feature extractor, the same
way a pretrained CNN is sometimes used for transfer learning.

This is deliberately a separate, additive track from the primary
classifier (websec_agent/classifier.py): it does not replace the
heuristic/structural feature vector (websec_agent/features.py), and
nothing in the default analyze_webpage pipeline depends on this module.
See training/train_with_embeddings.py for the honest comparison against
the features-only baseline before deciding whether this is worth keeping
wired in.

Uses microsoft/markuplm-base (the plain pretrained encoder, NOT the
-finetuned-websrc QA checkpoint already used by ask_webpage_question in
web_analysis.py - a QA head's fine-tuned representation isn't what we
want for a generic feature vector). Same pickle-scan requirement applies:
this checkpoint also ships only as pytorch_model.bin, confirmed via the
Hugging Face Hub API.
"""
from __future__ import annotations

EMBEDDING_DIM = 768
_REPO_ID = "microsoft/markuplm-base"

_pipeline = None


def _load_pipeline():
    global _pipeline
    if _pipeline is None:
        try:
            from transformers import MarkupLMModel, MarkupLMProcessor
        except ImportError as exc:
            raise RuntimeError(
                "MarkupLM embeddings require the ML extras: pip install -r requirements-ml.txt"
            ) from exc

        from . import model_security as ms

        ms.verify_pickle_safe(_REPO_ID, ["pytorch_model.bin"])
        processor = MarkupLMProcessor.from_pretrained(_REPO_ID)
        processor.parse_html = True
        model = MarkupLMModel.from_pretrained(_REPO_ID)
        model.eval()
        _pipeline = (processor, model)
    return _pipeline


def embed_html(html: str) -> list[float]:
    """A fixed-size (EMBEDDING_DIM) embedding summarizing the page's DOM
    structure and text, for use as extra classifier input - mean-pooled
    over real (non-padding) tokens rather than the [CLS]/pooler output,
    which is trained for MarkupLM's own pretraining objective, not for
    "a good generic summary vector" that a downstream linear model can
    make sense of without fine-tuning."""
    import torch

    processor, model = _load_pipeline()
    encoding = processor(html, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model(**encoding)

    hidden = outputs.last_hidden_state[0]  # (seq_len, hidden_dim)
    mask = encoding["attention_mask"][0].unsqueeze(-1).float()  # (seq_len, 1)
    pooled = (hidden * mask).sum(dim=0) / mask.sum().clamp(min=1.0)
    return pooled.tolist()
