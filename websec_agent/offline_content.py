"""Extract analyzable HTML from content you already have on disk -
an .eml file - instead of requiring a live URL to fetch. Common real
case: the phishing site is already taken down by the time you look at
it, but you saved the email.

Also parses SPF/DKIM/DMARC results from the Authentication-Results
header - see parse_eml_file()'s docstring for the trust-boundary caveat
that makes this genuinely different from "the page's own HTML looks
suspicious": this is a claim made by whichever mail system added the
header, not something this tool independently re-verifies.

Uses only Python's standard library email module - no new dependency.
"""
from __future__ import annotations

import html as html_module
import re
from email import message_from_bytes, policy
from email.utils import parseaddr
from urllib.parse import urlsplit

# Matches "spf=pass", "dkim = FAIL", etc. inside an Authentication-Results
# header. The method=result token itself is never inside the header's
# parenthetical free-text comments per RFC 8601 (comments follow the
# result, e.g. "spf=fail (explanation...)"), so this doesn't need to
# parse the full header grammar to stay accurate.
_AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)")
_DKIM_SIGNING_DOMAIN_RE = re.compile(r"\bd=([^;\s]+)")


def _parse_authentication_results(raw_headers: list[str]) -> dict:
    """Extracts spf=/dkim=/dmarc= verdicts from Authentication-Results
    header(s). Headers are listed topmost-first by the email module,
    which corresponds to the most recently added one - normally the
    final/trust-boundary mail system you'd actually want (an earlier,
    upstream hop's header could have been added - or forged - before
    reaching anything you trust). We take the first header that mentions
    a given method, not an OR/AND across all of them, since mixing
    verdicts from different hops has no well-defined meaning.

    CAVEAT, and the whole reason this is "self-reported, not verified":
    there is no cryptographic binding between this header and the
    sender's actual infrastructure. Whoever assembled the raw .eml file -
    including an attacker who crafted one by hand, or a forwarding step
    that stripped/rewrote headers - could put absolutely anything here.
    Only trust this as far as you trust whatever produced the .eml file."""
    result = {"spf": None, "dkim": None, "dmarc": None}
    for raw in raw_headers:
        for method, verdict in _AUTH_RESULT_RE.findall(raw):
            method = method.lower()
            if result.get(method) is None:
                result[method] = verdict.lower()
        if all(v is not None for v in result.values()):
            break
    return result


def parse_eml_file(path: str) -> dict:
    """{"html", "subject", "from", "to", "date", "from_domain", "auth"}.
    from_domain is the sender address's domain (e.g. "secure-paypal-
    verify.com" from "noreply@secure-paypal-verify.com") - a reasonable
    default url_hint for build_result_from_html(): an email's claimed
    sending domain is exactly the kind of thing our brand/domain-mismatch
    heuristic is designed to catch, repurposed from "page domain" to
    "sender domain".

    auth = {"spf", "dkim", "dmarc": "pass"/"fail"/"softfail"/.../None,
    "dkim_signing_domain": str | None, "header_count": int} - see
    _parse_authentication_results()'s docstring for the trust caveat."""
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

    auth_headers = msg.get_all("authentication-results") or []
    auth = _parse_authentication_results(auth_headers)
    dkim_sig = msg.get("dkim-signature")
    dkim_match = _DKIM_SIGNING_DOMAIN_RE.search(dkim_sig) if dkim_sig else None
    auth["dkim_signing_domain"] = dkim_match.group(1) if dkim_match else None
    auth["header_count"] = len(auth_headers)

    return {
        "html": html_part,
        "subject": msg.get("subject", "") or "",
        "from": from_header,
        "to": msg.get("to", "") or "",
        "date": msg.get("date", "") or "",
        "from_domain": from_domain,
        "auth": auth,
    }


def apply_email_auth(verdict: dict, auth: dict) -> dict:
    """Only ever pushes toward "phishing" on an explicit SPF/DKIM/DMARC
    *fail* for the claimed sender - deliberately asymmetric. A "pass"
    is NOT used to push toward "benign": it only shows that whoever
    actually sent/signed the message controlled its own domain's DNS,
    which a legitimate bulk-mail relay (SendGrid, Mailchimp, ...) abused
    by an attacker would also show while the *content* is still
    phishing - "pass" proves authenticity of the relay, not innocence of
    the message. "fail" is much harder to get by accident or via a
    legitimate relay, so it's treated as real signal; "none"/missing is
    just absence of information, not evidence either way.

    Does not touch verdict["label"] if it's already "phishing" - same
    reasoning as the VirusTotal override in verdict.py: a corroborating
    signal shouldn't silently disappear just because the label didn't
    need to change."""
    fails = [k for k in ("spf", "dkim", "dmarc") if auth.get(k) == "fail"]
    if not fails:
        return verdict

    note = (
        f"email authentication failed: {', '.join(fails)} "
        "(as reported by the receiving mail system in Authentication-Results - "
        "not independently re-verified by this tool, see offline_content.py)"
    )
    new_verdict = dict(verdict)
    if verdict["label"] == "phishing":
        new_verdict["confidence"] = f"{verdict['confidence']}; {note}"
    else:
        new_verdict["label"] = "phishing"
        new_verdict["confidence"] = note
    return new_verdict


def guess_url_hint(from_domain: str) -> str:
    """A placeholder URL built from a sender domain, so the existing
    domain/brand-mismatch heuristics have something to compare against."""
    if not from_domain or not urlsplit(f"//{from_domain}").hostname:
        return "https://unknown-sender.invalid/"
    return f"https://{from_domain}/"
