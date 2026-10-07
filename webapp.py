"""Minimal local web UI for the triage pipeline - fast mode: calls
websec_agent.report.build_result() directly, no LLM/agent call, so it's
free and near-instant (aside from the fetch itself, and optionally the
headless render or VirusTotal, which have their own latency).

For the conversational mode (natural-language explanation via Claude),
use main.py instead - this UI is specifically the "just show me the
signals" fast path.

Run:
    pip install -r requirements-web.txt
    uvicorn webapp:app --reload

Then open http://127.0.0.1:8000 - binds to localhost only by default via
uvicorn; do not expose this on a network interface without adding auth,
since it will fetch whatever URL a visitor submits (same trust model as
the CLI: a local tool for an operator who already controls the input).
"""
import asyncio
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from websec_agent import offline_content as oc
from websec_agent import report as rpt
from websec_agent import web_analysis as wa

app = FastAPI()
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(
    request: Request,
    url: str = Form(...),
    render: bool = Form(False),
    check_virustotal: bool = Form(False),
):
    try:
        result = await asyncio.to_thread(rpt.build_result, url, render, check_virustotal)
    except wa.FetchError as exc:
        return templates.TemplateResponse(request, "result.html", {"error": str(exc)})
    return templates.TemplateResponse(request, "result.html", {"result": result})


@app.post("/analyze-html", response_class=HTMLResponse)
async def analyze_html(
    request: Request,
    html: str = Form(...),
    url_hint: str = Form(...),
    check_virustotal: bool = Form(False),
):
    result = await asyncio.to_thread(rpt.build_result_from_html, html, url_hint, check_virustotal)
    return templates.TemplateResponse(request, "result.html", {"result": result})


@app.post("/analyze-email", response_class=HTMLResponse)
async def analyze_email(
    request: Request,
    eml_file: UploadFile = File(...),
    check_virustotal: bool = Form(False),
):
    content = await eml_file.read()
    with tempfile.NamedTemporaryFile(suffix=".eml") as tmp:
        tmp.write(content)
        tmp.flush()
        try:
            parsed = oc.parse_eml_file(tmp.name)
        except (OSError, ValueError) as exc:
            return templates.TemplateResponse(
                request, "result.html", {"error": f"Impossible de lire ce fichier .eml : {exc}"}
            )

    url_hint = oc.guess_url_hint(parsed["from_domain"])
    result = await asyncio.to_thread(rpt.build_result_from_html, parsed["html"], url_hint, check_virustotal)
    result["email"] = {k: parsed[k] for k in ("subject", "from", "to", "date")}
    result["email"]["auth"] = parsed["auth"]
    result["verdict"] = oc.apply_email_auth(result["verdict"], parsed["auth"])
    return templates.TemplateResponse(request, "result.html", {"result": result})


@app.post("/analyze-qr", response_class=HTMLResponse)
async def analyze_qr(
    request: Request,
    qr_file: UploadFile = File(...),
    check_virustotal: bool = Form(False),
):
    try:
        from websec_agent import qr_decode as qr
    except ImportError:
        return templates.TemplateResponse(
            request,
            "result.html",
            {"error": "Le décodage QR nécessite : pip install -r requirements-qr.txt"},
        )

    content = await qr_file.read()
    suffix = Path(qr_file.filename or "").suffix or ".png"
    with tempfile.NamedTemporaryFile(suffix=suffix) as tmp:
        tmp.write(content)
        tmp.flush()
        try:
            decoded = await asyncio.to_thread(qr.decode_qr_file, tmp.name)
        except (qr.QRDecodeError, RuntimeError) as exc:
            return templates.TemplateResponse(request, "result.html", {"error": str(exc)})

    if urlsplit(decoded).scheme not in ("http", "https"):
        return templates.TemplateResponse(
            request,
            "result.html",
            {"error": f"Le QR code encode un contenu non-URL (pas analysé comme une page web) : {decoded!r}"},
        )

    try:
        result = await asyncio.to_thread(rpt.build_result, decoded, False, check_virustotal)
    except wa.FetchError as exc:
        return templates.TemplateResponse(
            request, "result.html", {"error": f"QR décodé en {decoded!r} ; récupération échouée : {exc}"}
        )
    result["qr_decoded_content"] = decoded
    return templates.TemplateResponse(request, "result.html", {"result": result})
