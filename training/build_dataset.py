"""Build/grow a labeled dataset (features + label) for the phishing
classifier: label=1 from the public OpenPhish feed (live samples, fetched
and turned into features on the spot - nothing malicious is stored, only
the numeric feature vector + the source URL for traceability), label=0
from a curated list of well-known legitimate sites, a random sample from
the Tranco research-oriented top-sites list, and (if a Kaggle API token is
available) a sample of the real, non-mega-site legitimate URLs in the
PhiUSIIL dataset - for benign-class diversity beyond hand-picked tech
sites and top-ranked domains.

Note on PhiUSIIL: it is a 2024 snapshot, so its *phishing* URLs are almost
all dead by now (phishing infrastructure gets taken down in days/weeks) -
not useful for live refetching. Its *legitimate* URLs (label == "1" in the
source data) are still a good source of real-world site diversity, so
that's the only part this script uses from it.

Idempotent/cumulative: re-running this script does NOT overwrite the
existing dataset - it skips URLs already present (by source_url) and
appends newly-collected rows. Run it again whenever you want to grow the
dataset (the OpenPhish feed rotates, so a later run picks up new URLs).

This is a small-scale research dataset (tens to a few hundred samples per
class), not a production training set - see README.md -> MLOps.

Usage:
    python training/build_dataset.py [max_new_per_class] [out_csv]

Optional: set KAGGLE_API_TOKEN (or put the token in ~/.kaggle/access_token)
to also pull from PhiUSIIL.
"""
import csv
import io
import os
import random
import sys
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests

from websec_agent import features as feat
from websec_agent import web_analysis as wa

OPENPHISH_FEED = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
TRANCO_LIST = "https://tranco-list.eu/top-1m.csv.zip"
KAGGLE_PHIUSIIL_DATASET = "ndarvind/phiusiil-phishing-url-dataset"
KAGGLE_CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / ".cache"

BENIGN_URLS = [
    "https://example.com", "https://en.wikipedia.org/wiki/Phishing", "https://www.python.org",
    "https://www.mozilla.org", "https://github.com", "https://www.gnu.org", "https://httpbin.org",
    "https://www.gov.uk", "https://www.bbc.com/news", "https://www.nasa.gov", "https://www.who.int",
    "https://www.un.org", "https://www.w3.org", "https://www.apache.org", "https://www.debian.org",
    "https://www.kernel.org", "https://www.cloudflare.com", "https://www.wikipedia.org",
    "https://www.archive.org", "https://www.ietf.org", "https://www.iso.org",
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


def fetch_tranco_sample(n: int, rank_min: int = 1000, rank_max: int = 500_000, seed: int = 42) -> list[str]:
    """Random domains from Tranco (a research-oriented top-sites list) for
    benign-class diversity beyond hand-picked tech sites. Ranks below
    rank_min are skipped (mega-sites like google.com/facebook.com are
    over-represented already); ranks above rank_max are often dead/parked."""
    resp = requests.get(TRANCO_LIST, timeout=30, headers={"User-Agent": "websec-agent-dataset-builder/0.1"})
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        with zf.open(zf.namelist()[0]) as f:
            lines = f.read().decode("utf-8", errors="replace").splitlines()

    candidates = []
    for line in lines:
        rank_str, domain = line.split(",", 1)
        rank = int(rank_str)
        if rank_min <= rank <= rank_max:
            candidates.append(domain.strip())

    random.Random(seed).shuffle(candidates)
    return [f"https://{d}" for d in candidates[: n * 3]]  # oversample, attrition expected


def _get_kaggle_token() -> str | None:
    token = os.getenv("KAGGLE_API_TOKEN")
    if token:
        return token
    token_file = Path.home() / ".kaggle" / "access_token"
    if token_file.exists():
        return token_file.read_text().strip()
    return None


def fetch_phiusiil_benign_sample(n: int, seed: int = 42) -> list[str]:
    """Real, non-mega-site legitimate URLs from the PhiUSIIL dataset
    (label == "1" in the source data = legitimate - see module docstring).
    Returns [] silently if no Kaggle token is configured, so this source
    stays optional."""
    token = _get_kaggle_token()
    if not token:
        print("[phiusiil] no KAGGLE_API_TOKEN / ~/.kaggle/access_token found - skipping this source")
        return []

    KAGGLE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_csv = KAGGLE_CACHE_DIR / "phiusiil.csv"
    if not cache_csv.exists():
        print("[phiusiil] downloading dataset from Kaggle (cached afterwards)...")
        resp = requests.get(
            f"https://www.kaggle.com/api/v1/datasets/download/{KAGGLE_PHIUSIIL_DATASET}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=120,
        )
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            name = zf.namelist()[0]
            cache_csv.write_bytes(zf.read(name))

    urls = []
    with open(cache_csv, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("label") == "1":  # PhiUSIIL: 1 = legitimate
                urls.append(row["URL"])

    random.Random(seed).shuffle(urls)
    return urls[: n * 3]  # oversample, attrition expected (2024 snapshot)


def load_existing(out_csv: str) -> tuple[list[dict], set[str]]:
    path = Path(out_csv)
    if not path.exists():
        return [], set()
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return rows, {r["source_url"] for r in rows}


def collect(urls: list[str], label: int, max_count: int, seen: set[str]) -> list[dict]:
    rows = []
    for url in urls:
        if len(rows) >= max_count:
            break
        if url in seen:
            continue
        try:
            fetched = wa.fetch_html(url)
            if fetched["final_url"] in seen:
                continue
            if fetched["status_code"] != 200 or not fetched["html"].strip():
                continue
            row = feat.extract_features(fetched["html"], fetched["final_url"])
            row["label"] = label
            row["source_url"] = fetched["final_url"]
            rows.append(row)
            seen.add(fetched["final_url"])
            print(f"[{'phish' if label else 'benign'}] ok: {url}")
        except Exception as exc:  # noqa: BLE001 - best-effort data collection
            print(f"[{'phish' if label else 'benign'}] skip ({exc}): {url}")
        time.sleep(0.2)
    return rows


def main() -> None:
    max_new_per_class = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    out_csv = sys.argv[2] if len(sys.argv) > 2 else "data/dataset.csv"

    existing_rows, seen = load_existing(out_csv)
    print(f"Existing dataset: {len(existing_rows)} rows ({len(seen)} unique URLs)")

    phish_candidates = fetch_openphish_urls(limit=max_new_per_class * 6)
    new_phish = collect(phish_candidates, label=1, max_count=max_new_per_class, seen=seen)

    benign_candidates = (
        BENIGN_URLS + fetch_tranco_sample(max_new_per_class) + fetch_phiusiil_benign_sample(max_new_per_class)
    )
    new_benign = collect(benign_candidates, label=0, max_count=max_new_per_class, seen=seen)

    new_rows = new_phish + new_benign
    all_rows = existing_rows + new_rows
    if not all_rows:
        print("No rows collected - aborting.")
        sys.exit(1)

    Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    fieldnames = feat.FEATURE_NAMES + ["label", "source_url"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    n_phish = sum(1 for r in all_rows if str(r["label"]) == "1")
    n_benign = len(all_rows) - n_phish
    print(
        f"\nAdded {len(new_phish)} phish + {len(new_benign)} benign this run. "
        f"Dataset now: {len(all_rows)} rows ({n_phish} phish, {n_benign} benign) -> {out_csv}"
    )


if __name__ == "__main__":
    main()
