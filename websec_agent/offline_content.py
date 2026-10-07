"""Extract analyzable HTML from content you already have on disk -
an .eml file - instead of requiring a live URL to fetch. Common real
case: the phishing site is already taken down by the time you look at
it, but you saved the email.

Uses only Python's standard library email module - no new dependency.
"""
from __future__ import annotations

import html as html_module
from email import message_from_bytes, policy
from email.utils import parseaddr
from urllib.parse import urlsplit


def parse_eml_file(path: str) -> dict:
    """{"html", "subject", "from", "to", "date", "from_domain"}.
    from_domain is the sender address's domain (e.g. "secure-paypal-
    verify.com" from "noreply@secure-paypal-verify.com") - a reasonable
    default url_hint for build_result_from_html(): an email's claimed
    sending domain is exactly the kind of thing our brand/domain-mismatch
    heuristic is designed to catch, repurposed from "page domain" to
    "sender domain"."""
    with open(path, "rb") as f:
        msg = message_from_bytes(f.read(), policy=policy.default)

    html_part, text_part = None, None
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == "text/html" and html_part is None:
            html_part = part.get_content()
        elif content_type == "text/plain" and text_part is None:
            text_part = part.get_content()

    if html_part is None:
        body = html_module.escape(text_part or "")
        html_part = f"<html><body><pre>{body}</pre></body></html>"

    from_header = msg.get("from", "") or ""
    _, from_addr = parseaddr(from_header)
    from_domain = from_addr.split("@", 1)[1] if "@" in from_addr else ""

    return {
        "html": html_part,
        "subject": msg.get("subject", "") or "",
        "from": from_header,
        "to": msg.get("to", "") or "",
        "date": msg.get("date", "") or "",
        "from_domain": from_domain,
    }


def guess_url_hint(from_domain: str) -> str:
    """A placeholder URL built from a sender domain, so the existing
    domain/brand-mismatch heuristics have something to compare against."""
    if not from_domain or not urlsplit(f"//{from_domain}").hostname:
        return "https://unknown-sender.invalid/"
    return f"https://{from_domain}/"
