"""MCP tool definitions exposed to the Claude Agent SDK agent."""
from claude_agent_sdk import create_sdk_mcp_server, tool

from . import classifier as clf
from . import report as rpt
from . import web_analysis as wa


@tool(
    "analyze_webpage",
    "Fetch a URL and run a full defensive-security triage: page structure, "
    "extracted IOCs (domains, emails, punycode/IP links), the heuristic "
    "phishing score with reasons, the trained ML classifier's probability "
    "(when available), and one combined verdict reconciling the two.",
    {"url": str},
)
async def analyze_webpage(args):
    try:
        result = rpt.build_result(args["url"])
    except wa.FetchError as exc:
        return {"content": [{"type": "text", "text": f"Fetch blocked or failed: {exc}"}], "is_error": True}
    return {"content": [{"type": "text", "text": str(result)}]}


@tool(
    "ask_webpage",
    "Fetch a URL and answer a natural-language question about its content "
    "using MarkupLM (document QA over HTML). Requires the ML extras installed.",
    {"url": str, "question": str},
)
async def ask_webpage(args):
    try:
        fetched = wa.fetch_html(args["url"])
        answer = wa.ask_webpage_question(fetched["html"], fetched["final_url"], args["question"])
    except (wa.FetchError, RuntimeError) as exc:
        return {"content": [{"type": "text", "text": str(exc)}], "is_error": True}
    return {"content": [{"type": "text", "text": str(answer)}]}


@tool(
    "export_report",
    "Fetch a URL, run the triage pipeline, and write a Markdown report plus "
    "a JSON IOC bundle to disk (e.g. for a SOC ticket). Deterministic, no "
    "extra LLM call - the report is generated straight from the heuristics.",
    {"url": str, "out_dir": str},
)
async def export_report(args):
    try:
        outcome = rpt.export(args["url"], args["out_dir"])
    except wa.FetchError as exc:
        return {"content": [{"type": "text", "text": f"Fetch blocked or failed: {exc}"}], "is_error": True}
    text = (
        f"Report written to {outcome['report_path']}\n"
        f"IOC bundle written to {outcome['ioc_path']}\n"
        f"Verdict: {outcome['result']['verdict']['label']}"
    )
    return {"content": [{"type": "text", "text": text}]}


@tool(
    "ml_classify_webpage",
    "Fetch a URL and score it with the trained phishing/benign classifier "
    "(logistic regression on structural+IOC features, trained on real "
    "OpenPhish samples). Complements analyze_webpage's rule-based score with "
    "a learned probability. Requires the MLOps extras and a trained model.",
    {"url": str},
)
async def ml_classify_webpage(args):
    try:
        fetched = wa.fetch_html(args["url"])
        result = clf.classify_webpage(fetched["html"], fetched["final_url"])
    except (wa.FetchError, RuntimeError) as exc:
        return {"content": [{"type": "text", "text": str(exc)}], "is_error": True}
    return {"content": [{"type": "text", "text": str(result)}]}


websec_server = create_sdk_mcp_server(
    name="websec",
    version="0.1.0",
    tools=[analyze_webpage, ask_webpage, export_report, ml_classify_webpage],
)
