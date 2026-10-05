"""VirusTotal lookup: a corroborating signal from 70+ real security
vendors, instead of relying only on our own small heuristic/ML models.

Opt-in (costs quota - the free tier is 4 requests/minute, 500/day) and
only wired into the interactive analysis path (report.build_result), not
into training/build_dataset.py's feature extraction: a fresh submission
can take up to a minute to finish scanning, far too slow to run per
training sample, and would burn through the daily quota in minutes.

Note: VirusTotal states that any URL submitted for scanning is added to
their dataset and becomes visible to the community - expected and fine
for the phishing samples this tool analyzes, but worth knowing.
"""
from __future__ import annotations

import os
import time

DEFAULT_MAX_WAIT_S = 30
DEFAULT_POLL_INTERVAL_S = 5


def _get_api_key() -> str | None:
    return os.environ.get("VT_API_KEY")


def check_url(
    url: str,
    api_key: str | None = None,
    max_wait_s: int = DEFAULT_MAX_WAIT_S,
    poll_interval_s: int = DEFAULT_POLL_INTERVAL_S,
) -> dict:
    """{"source": "cached"|"fresh"|"timeout", "stats": dict|None, "url": str}.
    "cached" means VirusTotal already had a report for this URL (instant).
    "fresh" means we submitted it for scanning and waited for a verdict.
    "timeout" means we gave up waiting within max_wait_s - stats is None.
    Raises RuntimeError if the vt-py extra isn't installed or no API key
    is available (env VT_API_KEY, or pass api_key explicitly)."""
    try:
        import vt
    except ImportError as exc:
        raise RuntimeError(
            "VirusTotal lookup requires: pip install -r requirements-threatintel.txt"
        ) from exc

    key = api_key or _get_api_key()
    if not key:
        raise RuntimeError("VirusTotal lookup requires the VT_API_KEY environment variable (a free account's API key)")

    with vt.Client(key) as client:
        try:
            obj = client.get_object(f"/urls/{vt.url_id(url)}")
            return {"source": "cached", "stats": _plain_dict(obj.get("last_analysis_stats")), "url": url}
        except vt.APIError as exc:
            if exc.code != "NotFoundError":
                raise

        analysis = client.scan_url(url, wait_for_completion=False)
        deadline = time.monotonic() + max_wait_s
        while time.monotonic() < deadline:
            analysis = client.get_object("/analyses/{}", analysis.id)
            if analysis.get("status") == "completed":
                return {"source": "fresh", "stats": _plain_dict(analysis.get("stats")), "url": url}
            time.sleep(poll_interval_s)

    return {"source": "timeout", "stats": None, "url": url}


def _plain_dict(value):
    """vt-py returns its own WhistleBlowerDict (a dict subclass used to
    track in-place mutations), which json.dump() can't serialize - strip
    it down to a plain dict so callers can always json-dump a check_url()
    result without knowing that detail."""
    return dict(value) if value is not None else None
