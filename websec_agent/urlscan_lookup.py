"""urlscan.io - corroborating threat-intel context for a URL: has anyone
already publicly scanned this exact domain, and if so, what did that
scan see (page title, screenshot, hosting ASN/country, TLS cert age,
domain age)?

Deliberately complements VirusTotal rather than duplicating it: this
module does NOT compute its own malicious/benign verdict from urlscan.io
data. The field that would let us filter by that (verdicts.overall.malicious)
is gated behind a paid urlscan.io plan even just to search by - confirmed
empirically: an anonymous search on that field returns a 403 "Your
current plan does not allow you to search field...". What IS available
anonymously, and all this module uses, is read-only search over already-
public scans (no API key, no submission, no verdict scoring) - genuinely
useful corroborating context (a screenshot, hosting info, confirmation
something has/hasn't been scanned before), honestly short of a second
malicious/benign vote.

Field reference confirmed against real scans before writing this:
page.domain: (the scanned page's own domain - NOT "domain:", which
matches any domain merely *contacted* during a scan, a much noisier and
wrong field for "has this exact site been scanned before").
"""
from __future__ import annotations

import requests

_SEARCH_URL = "https://urlscan.io/api/v1/search/"
_TIMEOUT_S = 15


def find_existing_scans(domain: str, limit: int = 3) -> list[dict]:
    """Up to `limit` most recent public urlscan.io scans of this exact
    domain (page.domain, not the noisier "domains contacted" field) -
    [] if urlscan.io has never seen it, or on any request failure
    (treated the same as "no prior scan", never raises)."""
    if not domain:
        return []
    try:
        resp = requests.get(
            _SEARCH_URL,
            params={"q": f"page.domain:{domain}", "size": limit},
            timeout=_TIMEOUT_S,
            headers={"User-Agent": "websec-agent/0.1 (+defensive security research tool)"},
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.exceptions.RequestException, ValueError):
        return []

    scans = []
    for r in data.get("results", [])[:limit]:
        page = r.get("page", {})
        scans.append({
            "scan_url": r.get("result", "").replace("/api/v1/result/", "/result/").rstrip("/") or None,
            "screenshot": r.get("screenshot"),
            "scanned_at": r.get("task", {}).get("time"),
            "page_title": page.get("title"),
            "page_url": page.get("url"),
            "status_code": page.get("status"),
            "country": page.get("country"),
            "asn_name": page.get("asnname"),
            "domain_age_days": page.get("domainAgeDays"),
            "tls_issuer": page.get("tlsIssuer"),
        })
    return scans
