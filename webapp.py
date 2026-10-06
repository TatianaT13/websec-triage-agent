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

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

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
