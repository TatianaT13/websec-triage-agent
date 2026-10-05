"""Domain registration age via RDAP (the structured, JSON successor to
WHOIS) - a classic phishing signal we didn't have: a domain registered a
few days ago is far more likely to be throwaway phishing infrastructure
than an established site.

Not meaningful for PaaS-hosted subdomains (vercel.app, netlify.app,
pages.dev, github.io, ...): RDAP would return the *platform's* own
registration date, not the specific tenant subdomain's - which tells us
nothing about how old the page we're actually looking at is. Detected via
the ICANN-vs-private-suffix split and reported as such rather than
returning a misleading age.
"""
from __future__ import annotations

from datetime import datetime, timezone

import requests
import tldextract

_ICANN_ONLY = tldextract.TLDExtract(include_psl_private_domains=False)
_PRIVATE_AWARE = tldextract.TLDExtract(include_psl_private_domains=True)

_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_TIMEOUT_S = 8
_bootstrap_cache: dict[str, str] | None = None
_lookup_cache: dict[str, dict] = {}


def _load_bootstrap() -> dict[str, str]:
    global _bootstrap_cache
    if _bootstrap_cache is None:
        resp = requests.get(_BOOTSTRAP_URL, timeout=_TIMEOUT_S)
        resp.raise_for_status()
        cache: dict[str, str] = {}
        for tlds, servers in resp.json()["services"]:
            if servers:
                for tld in tlds:
                    cache[tld] = servers[0].rstrip("/")
        _bootstrap_cache = cache
    return _bootstrap_cache


def lookup_domain_age(hostname: str) -> dict:
    """{"registrable_domain", "is_platform_hosted", "age_days", "registered_at"}.
    age_days/registered_at stay None when the domain is platform-hosted,
    the RDAP lookup fails, or the record has no registration event -
    absence of this signal should never break the rest of the pipeline."""
    icann_domain = _ICANN_ONLY(hostname).top_domain_under_public_suffix
    private_domain = _PRIVATE_AWARE(hostname).top_domain_under_public_suffix

    result = {
        "registrable_domain": private_domain,
        "is_platform_hosted": icann_domain != private_domain,
        "age_days": None,
        "registered_at": None,
    }
    if result["is_platform_hosted"] or not icann_domain or "." not in icann_domain:
        return result

    if icann_domain in _lookup_cache:
        cached = _lookup_cache[icann_domain]
        result["age_days"] = cached["age_days"]
        result["registered_at"] = cached["registered_at"]
        return result

    tld = icann_domain.rsplit(".", 1)[-1]
    try:
        base = _load_bootstrap().get(tld)
        if not base:
            return result
        resp = requests.get(f"{base}/domain/{icann_domain}", timeout=_TIMEOUT_S)
        if resp.status_code != 200:
            return result
        for event in resp.json().get("events", []):
            if event.get("eventAction") == "registration":
                registered_at = event["eventDate"]
                dt = datetime.fromisoformat(registered_at.replace("Z", "+00:00"))
                result["age_days"] = (datetime.now(timezone.utc) - dt).days
                result["registered_at"] = registered_at
                break
    except (requests.RequestException, ValueError, KeyError, TypeError):
        pass  # best-effort signal - network hiccups shouldn't break triage

    _lookup_cache[icann_domain] = {"age_days": result["age_days"], "registered_at": result["registered_at"]}
    return result
