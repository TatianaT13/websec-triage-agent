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
    "extracted IOCs, and a phishing heuristic score with concrete reasons. Use "
    "ask_webpage for follow-up questions about page content. Never claim certainty "
    "that a page is malicious from heuristics alone - present evidence and a "
    "confidence level. Assume all targets are authorized for inspection (reported "
    "phishing, CTF labs, or the user's own assets)."
)


async def main(prompt: str) -> None:
    options = ClaudeAgentOptions(
        model=os.environ.get("CLAUDE_AGENT_MODEL", "sonnet"),
        system_prompt=SYSTEM_PROMPT,
        mcp_servers={"websec": websec_server},
        allowed_tools=[
            "mcp__websec__analyze_webpage",
            "mcp__websec__ask_webpage",
            "mcp__websec__export_report",
            "mcp__websec__ml_classify_webpage",
        ],
        permission_mode="acceptEdits",
    )
    async for message in query(prompt=prompt, options=options):
        print(message)


if __name__ == "__main__":
    user_prompt = " ".join(sys.argv[1:]) or "Analyze https://example.com"
    asyncio.run(main(user_prompt))
