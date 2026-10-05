"""Standalone CLI: run the heuristic pipeline on a URL and write report.md +
iocs.json, without going through the LLM agent (free, deterministic).

Usage:
    python scripts/export_report.py https://example.com [out_dir]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from websec_agent import report


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    url = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "out"

    outcome = report.export(url, out_dir)
    print(f"Rapport : {outcome['report_path']}")
    print(f"IOC     : {outcome['ioc_path']}")
    print(f"Verdict : {outcome['result']['verdict']['label']} ({outcome['result']['verdict']['confidence']})")


if __name__ == "__main__":
    main()
