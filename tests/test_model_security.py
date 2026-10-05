"""Tests for the pickle-malware scan that runs before any Hugging Face
checkpoint is deserialized. Proves both ends: a genuinely malicious pickle
is actually caught by the underlying scanner (not just our wrapper saying
so), and our wrapper correctly turns scanner output into a hard refusal.
"""
import os
import pickle

import pytest

pytest.importorskip("picklescan", reason="requires requirements-ml.txt")
pytest.importorskip("huggingface_hub", reason="requires requirements-ml.txt")

from websec_agent import model_security as ms


class _ReduceExploit:
    """Classic pickle RCE gadget: __reduce__ tells the unpickler to call
    an arbitrary callable with arbitrary args on load."""

    def __reduce__(self):
        return (os.system, ("echo pwned",))


def test_picklescan_detects_a_real_malicious_pickle(tmp_path):
    from picklescan.scanner import scan_file_path

    path = tmp_path / "malicious.bin"
    path.write_bytes(pickle.dumps(_ReduceExploit()))

    result = scan_file_path(str(path))

    assert result.infected_files == 1
    assert any(g.safety.value == "dangerous" for g in result.globals)


def test_verify_pickle_safe_raises_for_a_malicious_file(tmp_path, monkeypatch):
    path = tmp_path / "malicious.bin"
    path.write_bytes(pickle.dumps(_ReduceExploit()))

    monkeypatch.setattr(ms, "hf_hub_download", lambda repo_id, filename: str(path))

    with pytest.raises(ms.UnsafeModelError, match="refusing to load"):
        ms.verify_pickle_safe("some/repo", ["malicious.bin"])


def test_verify_pickle_safe_passes_for_a_clean_file(tmp_path, monkeypatch):
    # An ordinary, boring pickle - a plain dict - must not be flagged.
    path = tmp_path / "clean.bin"
    path.write_bytes(pickle.dumps({"a": 1, "b": [1, 2, 3]}))

    monkeypatch.setattr(ms, "hf_hub_download", lambda repo_id, filename: str(path))

    ms.verify_pickle_safe("some/repo", ["clean.bin"])  # must not raise


def test_verify_pickle_safe_requires_the_ml_extras(monkeypatch):
    monkeypatch.setattr(ms, "hf_hub_download", None)
    monkeypatch.setattr(ms, "scan_file_path", None)

    with pytest.raises(RuntimeError, match="requirements-ml.txt"):
        ms.verify_pickle_safe("some/repo", ["file.bin"])
