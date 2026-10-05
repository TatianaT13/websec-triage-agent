"""Build a small labeled dataset (features + label) for the phishing
classifier: label=1 from the public OpenPhish feed (live samples, fetched
and turned into features on the spot - nothing malicious is stored, only
the numeric feature vector + the source URL for traceability), label=0
from a curated list of well-known legitimate sites across different
categories (so the model doesn't just learn "has a CDN").

This is a small-scale research dataset (tens to ~100 samples per class),
not a production training set - see README.md -> MLOps.

Usage:
    python training/build_dataset.py [max_per_class] [out_csv]
"""
import csv
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests

from websec_agent import features as feat
from websec_agent import web_analysis as wa

OPENPHISH_FEED = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"

BENIGN_URLS = [
    "https://example.com", "https://en.wikipedia.org/wiki/Phishing", "https://www.python.org",
    "https://www.mozilla.org", "https://github.com", "https://www.gnu.org", "https://httpbin.org",
    "https://www.gov.uk", "https://www.bbc.com/news", "https://www.nasa.gov", "https://www.who.int",
    "https://www.un.org", "https://www.w3.org", "https://www.apache.org", "https://www.debian.org",
    "https://www.kernel.org", "https://www.cloudflare.com", "https://www.wikipedia.org",
    "https://www.archive.org", "https://www.un.org/en/", "https://www.ietf.org", "https://www.iso.org",
    "https://www.ecosia.org", "https://www.duckduckgo.com", "https://www.openstreetmap.org",
    "https://www.creativecommons.org", "https://www.eff.org", "https://www.owasp.org",
    "https://www.readthedocs.org", "https://www.rust-lang.org", "https://nodejs.org",
    "https://golang.org", "https://www.ruby-lang.org", "https://www.php.net", "https://www.postgresql.org",
    "https://www.mysql.com", "https://www.docker.com", "https://kubernetes.io", "https://www.terraform.io",
    "https://www.ansible.com",
]


def fetch_openphish_urls(limit: int) -> list[str]:
    resp = requests.get(OPENPHISH_FEED, timeout=15, headers={"User-Agent": "websec-agent-dataset-builder/0.1"})
    resp.raise_for_status()
    return [line.strip() for line in resp.text.splitlines() if line.strip()][:limit]


def collect(urls: list[str], label: int, max_count: int) -> list[dict]:
    rows = []
    for url in urls:
        if len(rows) >= max_count:
            break
        try:
            fetched = wa.fetch_html(url)
            if fetched["status_code"] != 200 or not fetched["html"].strip():
                continue
            row = feat.extract_features(fetched["html"], fetched["final_url"])
            row["label"] = label
            row["source_url"] = fetched["final_url"]
            rows.append(row)
            print(f"[{'phish' if label else 'benign'}] ok: {url}")
        except Exception as exc:  # noqa: BLE001 - best-effort data collection
            print(f"[{'phish' if label else 'benign'}] skip ({exc}): {url}")
        time.sleep(0.2)
    return rows


def main() -> None:
    max_per_class = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    out_csv = sys.argv[2] if len(sys.argv) > 2 else "data/dataset.csv"

    phish_candidates = fetch_openphish_urls(limit=max_per_class * 4)
    phish_rows = collect(phish_candidates, label=1, max_count=max_per_class)
    benign_rows = collect(BENIGN_URLS, label=0, max_count=max_per_class)

    rows = phish_rows + benign_rows
    if not rows:
        print("No rows collected - aborting.")
        sys.exit(1)

    Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    fieldnames = feat.FEATURE_NAMES + ["label", "source_url"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nWrote {len(rows)} rows ({len(phish_rows)} phish, {len(benign_rows)} benign) to {out_csv}")


if __name__ == "__main__":
    main()
