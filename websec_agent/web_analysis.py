"""Heuristic web page analysis for defensive security use (phishing triage, IOC
extraction, structural audit).

Intended for pages you are authorized to inspect (your own sites, reported
phishing samples, CTF targets, etc.). Fetches run through an SSRF guard that
blocks private/loopback/link-local targets.
"""
from __future__ import annotations

import contextlib
import ipaddress
import re
import socket
from urllib.parse import urljoin, urlsplit

import requests
import tldextract
from bs4 import BeautifulSoup

USER_AGENT = "websec-agent/0.1 (+defensive security research tool)"
MAX_BYTES = 2_000_000
TIMEOUT_S = 10

# include_psl_private_domains so random subdomains of vercel.app, pages.dev,
# github.io etc. are treated as their own site, not as "the same domain" as
# every other tenant on that host.
_TLD_EXTRACT = tldextract.TLDExtract(include_psl_private_domains=True)

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "work"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
BRAND_KEYWORDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix", "bank",
    "facebook", "instagram", "outlook", "office365", "wellsfargo", "chase",
    "wetransfer", "dropbox", "docusign", "linkedin", "coinbase", "binance",
    "roblox", "steam", "adobe", "icloud", "hsbc", "barclays", "dhl", "fedex",
    "ups", "usps", "irs", "booking.com", "airbnb", "spotify", "zoom",
    "github", "discord", "whatsapp", "telegram", "ebay", "wells fargo",
]
URGENCY_WORDS = [
    "verify your account", "suspended", "urgent", "immediately", "click here",
    "confirm your identity", "unusual activity", "limited time", "act now",
]


class FetchError(Exception):
    pass


def _guard_ssrf(hostname: str) -> list[str]:
    """Resolve + validate, returning the validated IPs so the caller can
    pin the connection to them (see _pin_dns) - a hostname string alone
    isn't enough to prevent a second, independent resolution later."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise FetchError(f"cannot resolve host: {hostname}") from exc
    validated_ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise FetchError(f"refusing to fetch internal/private address: {ip}")
        validated_ips.append(str(ip))
    if not validated_ips:
        raise FetchError(f"no addresses resolved for host: {hostname}")
    return validated_ips


def _sockaddr_info(ip: str, port: int) -> tuple:
    addr = ipaddress.ip_address(ip)
    if addr.version == 6:
        return (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port, 0, 0))
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))


@contextlib.contextmanager
def _pin_dns(hostname: str, validated_ips: list[str]):
    """Force every socket.getaddrinfo() call for this exact hostname, for
    the duration of the single request that follows, to return only the
    IPs _guard_ssrf already validated - instead of letting requests/urllib3
    resolve it again independently at connect time.

    Without this, the guard only proves the hostname was safe a few
    milliseconds ago: an attacker running authoritative DNS for their own
    domain (the normal case here - the thing being fetched is often a live
    phishing sample) can answer the guard's lookup with a public IP and the
    real connection's lookup with an internal one (DNS rebinding),
    bypassing the check entirely.

    Process-global and not thread-safe - fine as long as fetch_html() is
    only ever called synchronously from one thread at a time, which is the
    case everywhere in this codebase today."""
    real_getaddrinfo = socket.getaddrinfo

    def _pinned(host, port, family=0, type=0, proto=0, flags=0):
        if host != hostname:
            return real_getaddrinfo(host, port, family, type, proto, flags)
        port_num = port if isinstance(port, int) else 0
        return [_sockaddr_info(ip, port_num) for ip in validated_ips]

    socket.getaddrinfo = _pinned
    try:
        yield
    finally:
        socket.getaddrinfo = real_getaddrinfo


MAX_REDIRECTS = 5


def fetch_html(url: str) -> dict:
    """Fetch a URL with an SSRF guard re-checked (and DNS-pinned) on every
    redirect hop.

    requests' own allow_redirects=True would follow a 30x Location header
    without re-validating it - a page (or an attacker controlling one hop
    of a redirect chain) could point at an internal/private address and
    bypass the guard entirely. We disable automatic redirects and walk the
    chain ourselves, re-running the same hostname check at each step - and
    pin each hop's connection to the IPs that check just validated (see
    _pin_dns), so a second, independently-resolved DNS answer can't
    substitute an internal address after the check passes."""
    current_url = url
    for _ in range(MAX_REDIRECTS + 1):
        parts = urlsplit(current_url)
        if parts.scheme not in ("http", "https"):
            raise FetchError("only http/https URLs are supported")
        if not parts.hostname:
            raise FetchError("URL has no hostname")
        validated_ips = _guard_ssrf(parts.hostname)

        try:
            with _pin_dns(parts.hostname, validated_ips):
                resp = requests.get(
                    current_url,
                    headers={"User-Agent": USER_AGENT},
                    timeout=TIMEOUT_S,
                    stream=True,
                    allow_redirects=False,
                )

            if resp.is_redirect:
                location = resp.headers.get("Location")
                resp.close()
                if not location:
                    raise FetchError("redirect response had no Location header")
                current_url = urljoin(current_url, location)
                continue

            content = b""
            for chunk in resp.iter_content(8192):
                content += chunk
                if len(content) > MAX_BYTES:
                    break
        except requests.exceptions.RequestException as exc:
            # A reset/refused/timed-out connection, a bad TLS handshake,
            # etc. - some sites (link shorteners, anti-bot protection)
            # actively reject non-browser clients. Surface it as our own
            # FetchError like every other failure mode here, instead of
            # letting a raw requests exception escape to the caller.
            raise FetchError(f"network error fetching {current_url}: {exc}") from exc

        return {
            "final_url": resp.url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "html": content.decode(resp.encoding or "utf-8", errors="replace"),
        }

    raise FetchError(f"too many redirects (>{MAX_REDIRECTS})")


def _domain_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _registrable_domain(hostname: str) -> str:
    """Public-suffix-aware eTLD+1 (handles multi-label suffixes like .co.uk,
    .com.mu, and PaaS hosts like vercel.app/pages.dev where each tenant
    subdomain is effectively its own site)."""
    if not hostname:
        return ""
    result = _TLD_EXTRACT(hostname)
    return result.top_domain_under_public_suffix or hostname


def _domain_label(hostname: str) -> str:
    """The registrable label itself, stripped of its public suffix - e.g.
    'wetransfer-smoky' for wetransfer-smoky.vercel.app, 'roblox' for
    roblox.com.mu. Used to tell 'is the real brand's domain' apart from
    'merely contains the brand name' (classic lookalike-domain phishing)."""
    if not hostname:
        return ""
    return _TLD_EXTRACT(hostname).domain.lower()


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
    base_domain = _registrable_domain(_domain_of(base_url))
    domain_label = _domain_label(_domain_of(base_url)).replace("-", "")
    title = (structure.get("title") or "").lower()
    # Visible text only (not script/style/tag/attribute content) to avoid
    # matching brand names that only appear in unrelated markup or JS.
    visible_text = BeautifulSoup(html, "html.parser").get_text(" ", strip=True).lower()[:5000]

    for brand in BRAND_KEYWORDS:
        # Exact match on the domain's own label (hyphen-insensitive), not a
        # substring check - "wetransfer-smoky" must NOT be treated as "is
        # wetransfer's domain" just because it contains the brand name.
        is_real_brand_domain = brand.replace(" ", "") == domain_label
        pattern = re.compile(r"\b" + re.escape(brand) + r"\b")
        if pattern.search(title) and not is_real_brand_domain:
            score += 3
            reasons.append(f"brand '{brand}' in page title but site domain is '{base_domain}'")
            break
        if pattern.search(visible_text) and not is_real_brand_domain:
            score += 1
            reasons.append(f"brand '{brand}' mentioned in page text but site domain is '{base_domain}'")
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

    hits = [w for w in URGENCY_WORDS if w in visible_text]
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

        from . import model_security as ms

        repo_id = "microsoft/markuplm-base-finetuned-websrc"
        ms.verify_pickle_safe(repo_id, ["pytorch_model.bin"])
        processor = MarkupLMProcessor.from_pretrained(repo_id)
        model = MarkupLMForQuestionAnswering.from_pretrained(repo_id)
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
