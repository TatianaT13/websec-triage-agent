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
    "combined verdict reconciling all of it. If the plain fetch comes back "
    "looking suspiciously empty (no forms/links/text - e.g. a single-page "
    "app whose content is JS-injected), this automatically retries through "
    "a headless browser on its own (result['auto_rendered'] says whether "
    "that happened) - no need to manually switch to "
    "analyze_webpage_rendered for that specific case, only use that one "
    "directly if you want rendering forced from the start. Set "
    "check_virustotal=true to also query VirusTotal (70+ security vendors) "
    "- slower (up to ~30s for a URL VT hasn't seen before) and costs quota "
    "(requires VT_API_KEY and requirements-threatintel.txt), so it's off "
    "by default. Set check_urlscan=true to also look up existing public "
    "urlscan.io scans of this domain (free, no API key) - corroborating "
    "context only (screenshot, hosting ASN/country, TLS cert age), NOT a "
    "second malicious/benign vote like VirusTotal: urlscan.io's own "
    "malicious-verdict field is gated behind a paid plan even to query, "
    "so this never claims to replicate it.",
    {"url": str, "check_virustotal": bool, "check_urlscan": bool},
)
async def analyze_webpage(args):
    try:
        result = await asyncio.to_thread(
            rpt.build_result,
            args["url"],
            False,
            args.get("check_virustotal", False),
            args.get("check_urlscan", False),
        )
    except wa.FetchError as exc:
        return {"content": [{"type": "text", "text": f"Fetch blocked or failed: {exc}"}], "is_error": True}
    return {"content": [{"type": "text", "text": str(result)}]}


@tool(
    "analyze_webpage_rendered",
    "Like analyze_webpage, but always renders the page in a headless "
    "browser first (Playwright) so JS-injected content is visible - e.g. "
    "a login form built client-side that never appears in the raw HTML. "
    "analyze_webpage already does this automatically when its plain fetch "
    "looks suspiciously empty, so prefer this tool only when you want "
    "rendering forced unconditionally (e.g. you already know the page "
    "needs it, or the auto-retry's heuristic missed a case where content "
    "is JS-injected but the page isn't textually empty). Slower and "
    "heavier. Requires requirements-render.txt and a one-time `playwright "
    "install chromium`.",
    {"url": str},
)
async def analyze_webpage_rendered(args):
    try:
        result = await asyncio.to_thread(rpt.build_result, args["url"], True)
    except (wa.FetchError, RuntimeError) as exc:
        return {"content": [{"type": "text", "text": str(exc)}], "is_error": True}
    return {"content": [{"type": "text", "text": str(result)}]}


@tool(
    "screenshot_webpage",
    "Take a screenshot of a live page through the same SSRF-guarded, "
    "DNS-pinned headless browser as analyze_webpage_rendered, and return "
    "it as an image for you to look at directly with your own vision - "
    "no separate API call. Use this for visual brand-impersonation "
    "judgment the HTML/text-based tools can't do: does the page's actual "
    "layout and visual design genuinely resemble the brand it claims to "
    "be? IMPORTANT CAVEAT, explain this if asked: a phishing page "
    "commonly copies the real brand's logo pixel-for-pixel on purpose, "
    "so 'the logo looks exactly right' is NOT evidence of legitimacy by "
    "itself - the domain is still what matters most. What a screenshot "
    "CAN catch that a copied logo alone can't fake: broken/inconsistent "
    "styling, a login form in a visually unusual place, layout that "
    "doesn't match the real site's actual design despite the right logo. "
    "Treat your own visual read as one more heuristic signal, same "
    "caveat as every other tool here - never claim certainty from it "
    "alone. Requires requirements-render.txt and a one-time `playwright "
    "install chromium`.",
    {"url": str},
)
async def screenshot_webpage(args):
    import base64

    from . import render as rnd

    try:
        result = await asyncio.to_thread(rnd.screenshot_webpage, args["url"])
    except (wa.FetchError, RuntimeError) as exc:
        return {"content": [{"type": "text", "text": str(exc)}], "is_error": True}

    b64 = base64.b64encode(result["png_bytes"]).decode("ascii")
    return {
        "content": [
            {"type": "text", "text": f"Screenshot of {result['final_url']} (HTTP {result['status_code']}):"},
            {"type": "image", "data": b64, "mimeType": "image/png"},
        ]
    }


@tool(
    "analyze_html",
    "Run the full triage pipeline (same signals as analyze_webpage) on "
    "HTML content you already have - pasted directly - instead of fetching "
    "a live URL. Use this when the page is already offline/taken down but "
    "you have its saved source. url_hint is the URL this content is "
    "claimed or known to be associated with (even if it's dead now) - "
    "required, since the brand/domain-mismatch checks need a domain to "
    "compare against. check_urlscan=true adds existing-scan context from "
    "urlscan.io for url_hint's domain - see analyze_webpage's description "
    "for what that does and doesn't mean.",
    {"html": str, "url_hint": str, "check_virustotal": bool, "check_urlscan": bool},
)
async def analyze_html(args):
    result = await asyncio.to_thread(
        rpt.build_result_from_html,
        args["html"],
        args["url_hint"],
        args.get("check_virustotal", False),
        args.get("check_urlscan", False),
    )
    return {"content": [{"type": "text", "text": str(result)}]}


@tool(
    "analyze_email",
    "Run the full triage pipeline on an .eml file saved on disk - extracts "
    "its HTML body (falling back to the plain-text body if there is no "
    "HTML part) and analyzes it like analyze_html. If url_hint isn't "
    "given, defaults to the sender address's domain, repurposing the "
    "brand/domain-mismatch heuristic to catch a spoofed sender ('PayPal' "
    "branding sent from a domain that isn't paypal.com). Also parses "
    "SPF/DKIM/DMARC from the Authentication-Results header: an explicit "
    "fail pushes the verdict toward phishing (a pass is NOT treated as "
    "reassuring - see offline_content.apply_email_auth's docstring for "
    "why). This is the receiving mail system's self-reported verdict, not "
    "independently re-verified by this tool - say so if asked how solid "
    "the auth signal is. Also checks for display-name spoofing: if the "
    "From header's display name (e.g. 'Vinci|Autoroutes') doesn't share a "
    "single word with the actual sending domain, that also pushes toward "
    "phishing - this needs no brand list, so it catches impersonation of "
    "any organization, not just the handful of global brands "
    "BRAND_LEGITIMATE_DOMAINS enumerates (web_analysis.py). Noisier than "
    "the auth check though: can false-positive on a legitimate "
    "personal-name sender - see offline_content.display_name_domain_mismatch. "
    "If requirements-email-verify.txt is installed, also independently "
    "re-verifies the DKIM signature cryptographically against the signing "
    "domain's public DNS key (not just reading the self-reported header "
    "like the SPF/DKIM/DMARC check above) - an invalid signature is much "
    "stronger evidence than a self-reported fail, and pushes the verdict "
    "to phishing. Also independently checks DMARC-style identifier "
    "alignment: a VALID signature from a domain that doesn't match the "
    "From: header (e.g. signed by some unrelated mailer while claiming to "
    "be a known brand) also pushes to phishing - a valid signature alone "
    "proves authenticity of the signer, not that the signer is who the "
    "message claims to be. Missing extras degrade silently to the "
    "self-reported check only. Also looks up a BIMI record "
    "(default._bimi.<domain>) for "
    "the sender's domain, shown as result['email']['bimi'] - purely "
    "informational, never affects the verdict either way: presence just "
    "means the domain enforces DMARC and chose to display a logo, not "
    "that it's the brand it resembles (nothing stops a phishing domain "
    "from publishing its own BIMI record) - explain this if asked whether "
    "a BIMI logo proves authenticity. "
    "Also inspects attachments (result['email']['attachments']) - metadata "
    "only, nothing is ever extracted/decompressed/executed. Flags a "
    "dangerous executable extension, a double extension disguising one "
    "('facture.pdf.exe'), or (for a .zip attachment) a dangerous file "
    "inside it - the zip's internal listing is read from its own central "
    "directory, which doesn't require decompressing or even the password "
    "if it's protected. Any of these push the verdict to phishing.",
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
    result["email"]["auth"] = parsed["auth"]
    result["email"]["attachments"] = parsed["attachments"]
    result["verdict"] = oc.apply_email_auth(result["verdict"], parsed["auth"])
    result["verdict"] = oc.apply_display_name_mismatch(
        result["verdict"], parsed["display_name"], parsed["from_domain"]
    )
    result["verdict"] = oc.apply_dangerous_attachments(result["verdict"], parsed["attachments"])

    try:
        from . import dkim_verify as dv

        with open(args["file_path"], "rb") as f:
            raw_bytes = f.read()
        dkim_result = await asyncio.to_thread(dv.verify_dkim_signature, raw_bytes)
        if dkim_result.get("verified") is True:
            dkim_result["aligned"] = oc.dkim_domain_aligned(dkim_result.get("signing_domain"), parsed["from_domain"])
        result["email"]["dkim_verification"] = dkim_result
        result["verdict"] = oc.apply_dkim_verification(result["verdict"], dkim_result, parsed["from_domain"])
    except RuntimeError:
        pass  # DKIM verify extras not installed - degrade to the self-reported check only

    try:
        from . import bimi_lookup as bl

        result["email"]["bimi"] = await asyncio.to_thread(bl.lookup_bimi, parsed["from_domain"])
    except RuntimeError:
        pass  # dnspython not installed - BIMI is purely informational, never required

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
    "(structural+IOC features, trained on real OpenPhish samples - "
    "models/phishing_classifier.meta.json says which algorithm is "
    "currently promoted). Complements analyze_webpage's rule-based score "
    "with a learned probability. The result also includes "
    "result['explanation']: up to 3 features that most drove THIS "
    "specific prediction (not just globally important features) via "
    "feature ablation - each one's actual value on this page and how "
    "much removing it (replacing it with a typical-benign-page value) "
    "would have shifted the phishing probability. Useful for explaining "
    "*why* the model called it, not just the number. Requires the MLOps "
    "extras and a trained model.",
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
        screenshot_webpage,
        analyze_html,
        analyze_email,
        analyze_qr_code,
        ask_webpage,
        export_report,
        ml_classify_webpage,
        check_virustotal,
    ],
)
