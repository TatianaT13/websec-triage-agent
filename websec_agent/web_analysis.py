"""Heuristic web page analysis for defensive security use (phishing triage, IOC
extraction, structural audit).

Intended for pages you are authorized to inspect (your own sites, reported
phishing samples, CTF targets, etc.). Fetches run through an SSRF guard that
blocks private/loopback/link-local targets.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

USER_AGENT = "websec-agent/0.1 (+defensive security research tool)"
MAX_BYTES = 2_000_000
TIMEOUT_S = 10

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "work"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
BRAND_KEYWORDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix", "bank",
    "facebook", "instagram", "outlook", "office365", "wellsfargo", "chase",
]
URGENCY_WORDS = [
    "verify your account", "suspended", "urgent", "immediately", "click here",
    "confirm your identity", "unusual activity", "limited time", "act now",
]


class FetchError(Exception):
    pass


def _guard_ssrf(hostname: str) -> None:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise FetchError(f"cannot resolve host: {hostname}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise FetchError(f"refusing to fetch internal/private address: {ip}")


def fetch_html(url: str) -> dict:
    """Fetch a URL with an SSRF guard and a response-size cap."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchError("only http/https URLs are supported")
    if not parts.hostname:
        raise FetchError("URL has no hostname")
    _guard_ssrf(parts.hostname)

    resp = requests.get(
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=TIMEOUT_S,
        stream=True,
        allow_redirects=True,
    )
    content = b""
    for chunk in resp.iter_content(8192):
        content += chunk
        if len(content) > MAX_BYTES:
            break
    return {
        "final_url": resp.url,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "html": content.decode(resp.encoding or "utf-8", errors="replace"),
    }


def _domain_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _registrable_domain(hostname: str) -> str:
    """Rough eTLD+1 approximation (last two labels) - good enough for heuristics."""
    labels = hostname.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname


def analyze_structure(html: str, base_url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    base_domain = _registrable_domain(_domain_of(base_url))

    forms = []
    for form in soup.find_all("form"):
        action = urljoin(base_url, form.get("action") or "")
        has_password = bool(form.find("input", {"type": "password"}))
        action_domain = _domain_of(action)
        forms.append({
            "action": action,
            "method": (form.get("method") or "get").lower(),
            "has_password_field": has_password,
            "action_domain": action_domain,
            "action_is_external": bool(action_domain) and _registrable_domain(action_domain) != base_domain,
        })

    scripts_external = [urljoin(base_url, s.get("src")) for s in soup.find_all("script", src=True)]
    links = [urljoin(base_url, a.get("href")) for a in soup.find_all("a", href=True)]
    iframes = [urljoin(base_url, f.get("src")) for f in soup.find_all("iframe", src=True)]
    favicon_tag = soup.find("link", rel=lambda v: v and "icon" in v.lower())
    favicon = urljoin(base_url, favicon_tag.get("href")) if favicon_tag and favicon_tag.get("href") else None

    return {
        "title": soup.title.string.strip() if soup.title and soup.title.string else None,
        "forms": forms,
        "script_src_count": len(scripts_external),
        "external_scripts": [u for u in scripts_external if _registrable_domain(_domain_of(u)) != base_domain],
        "link_count": len(links),
        "external_link_count": sum(1 for u in links if _registrable_domain(_domain_of(u)) != base_domain),
        "iframes": iframes,
        "favicon": favicon,
        "favicon_is_external": bool(favicon) and _registrable_domain(_domain_of(favicon)) != base_domain,
        "meta_refresh": bool(soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})),
    }


EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
IP_URL_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}")


def extract_iocs(html: str, base_url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    for tag, attr in [("a", "href"), ("script", "src"), ("img", "src"), ("form", "action"), ("iframe", "src")]:
        for el in soup.find_all(tag):
            v = el.get(attr)
            if v:
                urls.add(urljoin(base_url, v))

    domains = sorted({_domain_of(u) for u in urls if _domain_of(u)})
    punycode_domains = [d for d in domains if "xn--" in d]
    shortener_hits = [u for u in urls if _domain_of(u) in URL_SHORTENERS]
    ip_literal_urls = [u for u in urls if IP_URL_RE.match(u)]
    suspicious_tld_domains = [d for d in domains if d.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS]
    emails = sorted(set(EMAIL_RE.findall(html)))

    return {
        "domains": domains,
        "emails": emails,
        "punycode_domains": punycode_domains,
        "shortener_links": shortener_hits,
        "ip_literal_urls": ip_literal_urls,
        "suspicious_tld_domains": suspicious_tld_domains,
    }


def score_phishing(html: str, structure: dict, iocs: dict, base_url: str) -> dict:
    reasons: list[str] = []
    score = 0
    lower_html = html.lower()
    title = (structure.get("title") or "").lower()
    base_domain = _registrable_domain(_domain_of(base_url))

    for brand in BRAND_KEYWORDS:
        if brand in title or brand in lower_html[:5000]:
            if brand not in base_domain:
                score += 2
                reasons.append(f"brand keyword '{brand}' present but not in site domain ({base_domain})")
            break

    for form in structure.get("forms", []):
        if form["has_password_field"] and form["action_is_external"]:
            score += 4
            reasons.append(f"password field submits to external domain: {form['action_domain']}")
        elif form["has_password_field"] and form["action"] and not form["action"].startswith("https:"):
            score += 2
            reasons.append("password field submits over a non-HTTPS action")

    if structure.get("favicon_is_external"):
        score += 1
        reasons.append("favicon served from a different domain than the page")

    if structure.get("meta_refresh"):
        score += 1
        reasons.append("meta-refresh redirect present")

    if iocs.get("punycode_domains"):
        score += 3
        reasons.append(f"punycode domain(s) found: {iocs['punycode_domains']} (possible homograph attack)")

    if iocs.get("ip_literal_urls"):
        score += 2
        reasons.append("links/resources pointing directly at IP addresses")

    if iocs.get("suspicious_tld_domains"):
        score += 1
        reasons.append(f"resources on commonly-abused TLDs: {iocs['suspicious_tld_domains']}")

    hits = [w for w in URGENCY_WORDS if w in lower_html]
    if hits:
        score += min(len(hits), 3)
        reasons.append(f"urgency/social-engineering language: {hits}")

    level = "low"
    if score >= 8:
        level = "high"
    elif score >= 4:
        level = "medium"

    return {"score": score, "level": level, "reasons": reasons}


_markuplm_pipeline = None


def ask_webpage_question(html: str, url: str, question: str) -> dict:
    """Answer a question about page content using MarkupLM (WebSRC-style QA).

    Lazily imports transformers/torch - install requirements-ml.txt first.
    This is a document-understanding backbone, not a phishing classifier: use
    it to query page content, and use score_phishing()/extract_iocs() for triage.
    """
    global _markuplm_pipeline
    if _markuplm_pipeline is None:
        try:
            from transformers import MarkupLMForQuestionAnswering, MarkupLMProcessor
        except ImportError as exc:
            raise RuntimeError(
                "MarkupLM QA requires the ML extras: pip install -r requirements-ml.txt"
            ) from exc
        processor = MarkupLMProcessor.from_pretrained("microsoft/markuplm-base-finetuned-websrc")
        model = MarkupLMForQuestionAnswering.from_pretrained("microsoft/markuplm-base-finetuned-websrc")
        _markuplm_pipeline = (processor, model)

    import torch

    processor, model = _markuplm_pipeline
    encoding = processor(html, questions=[question], return_tensors="pt", truncation=True)
    with torch.no_grad():
        outputs = model(**encoding)
    start = int(outputs.start_logits.argmax())
    end = int(outputs.end_logits.argmax())
    tokens = encoding["input_ids"][0][start : end + 1]
    answer = processor.decode(tokens, skip_special_tokens=True)
    return {"question": question, "answer": answer, "source_url": url}
