"""Standalone CLI: run the heuristic pipeline on a URL and write report.md +
iocs.json, without going through the LLM agent (free, deterministic).

Usage:
    python scripts/export_report.py https://example.com [out_dir] [--render] [--check-virustotal]

--render fetches through a headless browser (requires requirements-render.txt
and `playwright install chromium`) so JS-injected content is visible.

--check-virustotal also queries VirusTotal (requires requirements-threatintel.txt
and a free VT_API_KEY env var) - costs quota (4 req/min, 500/day) and can take
up to ~30s for a URL VT hasn't seen before.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from websec_agent import report

FLAGS = {"--render", "--check-virustotal"}


def main() -> None:
    args = [a for a in sys.argv[1:] if a not in FLAGS]
    render = "--render" in sys.argv[1:]
    check_virustotal = "--check-virustotal" in sys.argv[1:]
    if len(args) < 1:
        print(__doc__)
        sys.exit(1)
    url = args[0]
    out_dir = args[1] if len(args) > 1 else "out"

    outcome = report.export(url, out_dir, render=render, check_virustotal=check_virustotal)
    print(f"Rapport : {outcome['report_path']}")
    print(f"IOC     : {outcome['ioc_path']}")
    print(f"Verdict : {outcome['result']['verdict']['label']} ({outcome['result']['verdict']['confidence']})")


if __name__ == "__main__":
    main()
