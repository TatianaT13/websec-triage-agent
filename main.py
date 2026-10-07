"""Entry point: a Claude Agent SDK agent specialized in defensive web-security triage.

Usage:
    python main.py "Analyse https://example.com et dis-moi si ca ressemble a du phishing"

Only point this at pages you are authorized to inspect (your own sites, reported
phishing samples, CTF/lab targets). See README.md for scope and safety notes.
"""
import asyncio
import os
import sys

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    query,
)

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
    "If the user has HTML they already saved (e.g. the live page is now down) "
    "or a local .eml file, use analyze_html or analyze_email instead of trying "
    "to fetch a dead URL - both need a url_hint (analyze_email defaults it to "
    "the sender's domain) since the domain/brand-mismatch checks need "
    "something to compare the content against. If the user has a QR code "
    "image (quishing - a malicious QR pasted over a legitimate one), use "
    "analyze_qr_code to decode it and triage the URL it points to. "
    "Use ask_webpage for follow-up questions about page content. Never claim "
    "certainty that a page is malicious from heuristics alone - present evidence "
    "and a confidence level. Assume all targets are authorized for inspection "
    "(reported phishing, CTF labs, or the user's own assets)."
)


def _print_message(message) -> None:
    """Only the parts a human actually wants to see: the agent's own text,
    and which tool it's calling. Everything else (SystemMessage's tool/MCP
    inventory, RateLimitEvent, ThinkingBlock, raw ToolResultBlock payloads)
    is SDK/protocol plumbing the raw `print(message)` dumped unfiltered."""
    if isinstance(message, AssistantMessage):
        for block in message.content:
            if isinstance(block, TextBlock) and block.text:
                print(block.text)
            elif isinstance(block, ToolUseBlock):
                name = block.name.rsplit("__", 1)[-1] if "__" in block.name else block.name
                args = ", ".join(f"{k}={v!r}" for k, v in block.input.items())
                print(f"\n🔧 {name}({args})")
    elif isinstance(message, ResultMessage):
        print(f"\n— {message.duration_ms / 1000:.1f}s · ${message.total_cost_usd:.3f} —")


async def main(prompt: str) -> None:
    options = ClaudeAgentOptions(
        model=os.environ.get("CLAUDE_AGENT_MODEL", "sonnet"),
        system_prompt=SYSTEM_PROMPT,
        mcp_servers={"websec": websec_server},
        allowed_tools=[
            "mcp__websec__analyze_webpage",
            "mcp__websec__analyze_webpage_rendered",
            "mcp__websec__analyze_html",
            "mcp__websec__analyze_email",
            "mcp__websec__analyze_qr_code",
            "mcp__websec__ask_webpage",
            "mcp__websec__export_report",
            "mcp__websec__ml_classify_webpage",
            "mcp__websec__check_virustotal",
        ],
        permission_mode="acceptEdits",
    )
    async for message in query(prompt=prompt, options=options):
        _print_message(message)


if __name__ == "__main__":
    user_prompt = " ".join(sys.argv[1:]) or "Analyze https://example.com"
    asyncio.run(main(user_prompt))
