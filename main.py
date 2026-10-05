"""Entry point: a Claude Agent SDK agent specialized in defensive web-security triage.

Usage:
    python main.py "Analyse https://example.com et dis-moi si ca ressemble a du phishing"

Only point this at pages you are authorized to inspect (your own sites, reported
phishing samples, CTF/lab targets). See README.md for scope and safety notes.
"""
import asyncio
import os
import sys

from claude_agent_sdk import ClaudeAgentOptions, query

from websec_agent.mcp_server import websec_server

SYSTEM_PROMPT = (
    "You are a defensive web-security triage assistant. Given a URL, use the "
    "analyze_webpage tool to fetch it safely and report structural anomalies, "
    "extracted IOCs, the heuristic and ML signals, and the combined verdict. "
    "If analyze_webpage comes back suspiciously empty (no forms/links/text) for "
    "a page that should have content, retry with analyze_webpage_rendered - it "
    "runs a headless browser so JS-injected content (e.g. a client-side login "
    "form) becomes visible. If the verdict is uncertain and the user wants more "
    "confidence, offer analyze_webpage with check_virustotal=true (or the "
    "standalone check_virustotal tool) for a real vendor-backed signal - mention "
    "it costs quota and extra setup (VT_API_KEY), so don't use it by default. "
    "Use ask_webpage for follow-up questions about page content. Never claim "
    "certainty that a page is malicious from heuristics alone - present evidence "
    "and a confidence level. Assume all targets are authorized for inspection "
    "(reported phishing, CTF labs, or the user's own assets)."
)


async def main(prompt: str) -> None:
    options = ClaudeAgentOptions(
        model=os.environ.get("CLAUDE_AGENT_MODEL", "sonnet"),
        system_prompt=SYSTEM_PROMPT,
        mcp_servers={"websec": websec_server},
        allowed_tools=[
            "mcp__websec__analyze_webpage",
            "mcp__websec__analyze_webpage_rendered",
            "mcp__websec__ask_webpage",
            "mcp__websec__export_report",
            "mcp__websec__ml_classify_webpage",
            "mcp__websec__check_virustotal",
        ],
        permission_mode="acceptEdits",
    )
    async for message in query(prompt=prompt, options=options):
        print(message)


if __name__ == "__main__":
    user_prompt = " ".join(sys.argv[1:]) or "Analyze https://example.com"
    asyncio.run(main(user_prompt))
