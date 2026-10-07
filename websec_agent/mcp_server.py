"""MCP tool definitions exposed to the Claude Agent SDK agent."""
import asyncio

from claude_agent_sdk import create_sdk_mcp_server, tool

from . import classifier as clf
from . import report as rpt
from . import web_analysis as wa


@tool(
    "analyze_webpage",
    "Fetch a URL and run a full defensive-security triage: page structure, "
    "extracted IOCs (domains, emails, punycode/IP links), the heuristic "
    "phishing score with reasons, the trained ML classifier's probability "
    "(when available), the domain's registration age via RDAP, and one "
    "combined verdict reconciling all of it. Set check_virustotal=true to "
    "also query VirusTotal (70+ security vendors) - slower (up to ~30s for "
    "a URL VT hasn't seen before) and costs quota (requires VT_API_KEY and "
    "requirements-threatintel.txt), so it's off by default.",
    {"url": str, "check_virustotal": bool},
)
async def analyze_webpage(args):
    try:
        result = await asyncio.to_thread(
            rpt.build_result, args["url"], False, args.get("check_virustotal", False)
        )
    except wa.FetchError as exc:
        return {"content": [{"type": "text", "text": f"Fetch blocked or failed: {exc}"}], "is_error": True}
    return {"content": [{"type": "text", "text": str(result)}]}


@tool(
    "analyze_webpage_rendered",
    "Like analyze_webpage, but renders the page in a headless browser first "
    "(Playwright) so JS-injected content is visible - e.g. a login form "
    "built client-side that never appears in the raw HTML. Slower and "
    "heavier: use it when analyze_webpage comes back looking suspiciously "
    "empty (no forms/links/text) for a page that should have content. "
    "Requires requirements-render.txt and a one-time `playwright install "
    "chromium`.",
    {"url": str},
)
async def analyze_webpage_rendered(args):
    try:
        result = await asyncio.to_thread(rpt.build_result, args["url"], True)
    except (wa.FetchError, RuntimeError) as exc:
        return {"content": [{"type": "text", "text": str(exc)}], "is_error": True}
    return {"content": [{"type": "text", "text": str(result)}]}


@tool(
    "analyze_html",
    "Run the full triage pipeline (same signals as analyze_webpage) on "
    "HTML content you already have - pasted directly - instead of fetching "
    "a live URL. Use this when the page is already offline/taken down but "
    "you have its saved source. url_hint is the URL this content is "
    "claimed or known to be associated with (even if it's dead now) - "
    "required, since the brand/domain-mismatch checks need a domain to "
    "compare against.",
    {"html": str, "url_hint": str, "check_virustotal": bool},
)
async def analyze_html(args):
    result = await asyncio.to_thread(
        rpt.build_result_from_html, args["html"], args["url_hint"], args.get("check_virustotal", False)
    )
    return {"content": [{"type": "text", "text": str(result)}]}


@tool(
    "analyze_email",
    "Run the full triage pipeline on an .eml file saved on disk - extracts "
    "its HTML body (falling back to the plain-text body if there is no "
    "HTML part) and analyzes it like analyze_html. If url_hint isn't "
    "given, defaults to the sender address's domain, repurposing the "
    "brand/domain-mismatch heuristic to catch a spoofed sender ('PayPal' "
    "branding sent from a domain that isn't paypal.com).",
    {"file_path": str, "url_hint": str, "check_virustotal": bool},
)
async def analyze_email(args):
    from . import offline_content as oc

    try:
        parsed = oc.parse_eml_file(args["file_path"])
    except (OSError, ValueError) as exc:
        return {"content": [{"type": "text", "text": f"Could not read/parse the .eml file: {exc}"}], "is_error": True}

    url_hint = args.get("url_hint") or oc.guess_url_hint(parsed["from_domain"])
    result = await asyncio.to_thread(
        rpt.build_result_from_html, parsed["html"], url_hint, args.get("check_virustotal", False)
    )
    result["email"] = {k: parsed[k] for k in ("subject", "from", "to", "date")}
    return {"content": [{"type": "text", "text": str(result)}]}


@tool(
    "analyze_qr_code",
    "Decode a QR code image file and run the full triage pipeline on the "
    "URL it encodes (quishing: a malicious QR code pasted over a "
    "legitimate one on a poster, parking meter, invoice, etc.). If the QR "
    "code encodes something other than an http(s) URL, returns the raw "
    "decoded text instead - not everything a QR code encodes is a URL. "
    "Requires requirements-qr.txt.",
    {"file_path": str, "check_virustotal": bool},
)
async def analyze_qr_code(args):
    from urllib.parse import urlsplit

    from . import qr_decode as qr

    try:
        decoded = await asyncio.to_thread(qr.decode_qr_file, args["file_path"])
    except (qr.QRDecodeError, RuntimeError) as exc:
        return {"content": [{"type": "text", "text": str(exc)}], "is_error": True}

    if urlsplit(decoded).scheme not in ("http", "https"):
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"QR code decoded to non-URL content (not analyzed as a webpage): {decoded!r}",
                }
            ]
        }

    try:
        result = await asyncio.to_thread(
            rpt.build_result, decoded, False, args.get("check_virustotal", False)
        )
    except wa.FetchError as exc:
        return {
            "content": [{"type": "text", "text": f"QR code decoded to {decoded!r}; fetch failed: {exc}"}],
            "is_error": True,
        }
    result["qr_decoded_content"] = decoded
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
    "extra LLM call - the report is generated straight from the heuristics. "
    "Set check_virustotal=true to also include a VirusTotal verdict (see "
    "analyze_webpage's description for the cost/latency tradeoff).",
    {"url": str, "out_dir": str, "check_virustotal": bool},
)
async def export_report(args):
    try:
        outcome = await asyncio.to_thread(
            rpt.export, args["url"], args["out_dir"], False, args.get("check_virustotal", False)
        )
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


@tool(
    "check_virustotal",
    "Check a URL against VirusTotal (70+ security vendors) on its own, "
    "without the rest of the triage pipeline. Up to ~30s for a URL VT "
    "hasn't seen before (it submits and waits for a verdict); instant if "
    "VT already has a report. Requires requirements-threatintel.txt and a "
    "free VT_API_KEY (quota: 4 requests/minute, 500/day).",
    {"url": str},
)
async def check_virustotal(args):
    try:
        from . import virustotal as vt

        result = await asyncio.to_thread(vt.check_url, args["url"])
    except RuntimeError as exc:
        return {"content": [{"type": "text", "text": str(exc)}], "is_error": True}
    return {"content": [{"type": "text", "text": str(result)}]}


websec_server = create_sdk_mcp_server(
    name="websec",
    version="0.1.0",
    tools=[
        analyze_webpage,
        analyze_webpage_rendered,
        analyze_html,
        analyze_email,
        analyze_qr_code,
        ask_webpage,
        export_report,
        ml_classify_webpage,
        check_virustotal,
    ],
)
