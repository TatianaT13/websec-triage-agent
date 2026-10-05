"""Pickle-malware scanning for third-party model checkpoints pulled from
Hugging Face, run *before* anything deserializes them - which is also the
moment a malicious pickle's payload would execute, so scanning after
loading is already too late.

Why this exists: the MarkupLM checkpoint this project uses
(microsoft/markuplm-base-finetuned-websrc) ships only as a legacy
`pytorch_model.bin` (pickle), not the inherently-safe `safetensors`
format - confirmed via the Hugging Face Hub API. Pickle deserialization
can execute arbitrary code (CWE-502); there is real precedent for
malicious models distributed this way on public hubs. This checkpoint
scanned clean when checked, but that's a point-in-time fact about one
file, not a property of the pickle format - so the check is automated
and re-run on every load, not just noted in a comment once.
"""
from __future__ import annotations

try:
    from huggingface_hub import hf_hub_download
    from picklescan.scanner import scan_file_path
except ImportError:
    hf_hub_download = None
    scan_file_path = None


class UnsafeModelError(RuntimeError):
    """Subclasses RuntimeError so it's caught wherever callers already
    catch RuntimeError for 'missing optional extras' (e.g. mcp_server.py's
    ask_webpage tool) - this failure deserves the same clean surfacing."""


def verify_pickle_safe(repo_id: str, filenames: list[str]) -> None:
    """Downloads each file into the normal huggingface_hub cache (so a
    subsequent from_pretrained() call reuses it - this does not trigger a
    second download) and scans it with picklescan before anything is
    allowed to deserialize it. Raises UnsafeModelError if picklescan finds
    a non-innocuous global or fails to scan the file cleanly."""
    if hf_hub_download is None or scan_file_path is None:
        raise RuntimeError(
            "Model security scanning requires: pip install picklescan huggingface_hub "
            "(included in requirements-ml.txt)"
        )

    for filename in filenames:
        path = hf_hub_download(repo_id=repo_id, filename=filename)
        result = scan_file_path(path)
        if result.scan_err or result.infected_files > 0:
            raise UnsafeModelError(
                f"{repo_id}/{filename} failed the pickle security scan "
                f"({result.issues_count} issue(s), {result.infected_files} infected file(s)) - refusing to load it"
            )
        dangerous = [g for g in result.globals if g.safety.value != "innocuous"]
        if dangerous:
            flagged = [(g.module, g.name, g.safety.value) for g in dangerous]
            raise UnsafeModelError(
                f"{repo_id}/{filename} contains non-innocuous pickle globals: {flagged} - refusing to load it"
            )
