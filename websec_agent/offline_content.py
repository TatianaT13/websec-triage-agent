"""Extract analyzable HTML from content you already have on disk -
an .eml file - instead of requiring a live URL to fetch. Common real
case: the phishing site is already taken down by the time you look at
it, but you saved the email.

Also parses SPF/DKIM/DMARC results from the Authentication-Results
header - see parse_eml_file()'s docstring for the trust-boundary caveat
that makes this genuinely different from "the page's own HTML looks
suspicious": this is a claim made by whichever mail system added the
header, not something this tool independently re-verifies.

Parsing itself uses only Python's standard library email module - no
new dependency. apply_dkim_verification() is the one exception: it
consumes the output of websec_agent.dkim_verify, which does an actual
independent cryptographic re-check (optional extras, see that module).
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

_DANGEROUS_ATTACHMENT_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
    "jar", "msi", "ps1", "psm1", "wsf", "hta", "cpl", "lnk", "gadget",
}
_PLAUSIBLE_DECOY_EXTENSIONS = {"pdf", "docx", "doc", "xlsx", "xls", "jpg", "jpeg", "png", "txt", "csv", "ppt", "pptx"}
# Declared-size threshold for flagging a zip bomb - checked from the
# archive's OWN recorded uncompressed size (central directory metadata),
# never by actually decompressing. 100 uncompressed MB from an email
# attachment is already implausible for anything legitimate.
_ZIP_BOMB_SIZE_THRESHOLD_BYTES = 100_000_000


def _file_extension(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def _has_double_extension(filename: str) -> bool:
    """"facture.pdf.exe" - a classic malware-delivery disguise: a
    benign-looking extension immediately followed by the real
    (dangerous) one, so a quick glance at the filename shows "pdf" while
    the OS actually runs it as an executable."""
    parts = filename.split(".")
    if len(parts) < 3:
        return False
    return parts[-1].lower() in _DANGEROUS_ATTACHMENT_EXTENSIONS and parts[-2].lower() in _PLAUSIBLE_DECOY_EXTENSIONS


def _inspect_zip_contents(zip_bytes: bytes) -> list[dict] | None:
    """Lists a zip's internal filenames and their DECLARED (uncompressed)
    size - entirely from the archive's central directory metadata, which
    zipfile reads without decompressing or extracting a single byte.
    This also works on a password-protected zip: only the file CONTENTS
    are encrypted in the standard zip format, not the central directory
    listing, so the names/sizes are still readable without the password
    (we never attempt to read/decompress the actual content - that would
    both need the password and risk a zip-bomb-style decompression, so
    it's deliberately never attempted here). Returns None if the bytes
    aren't a valid/readable zip at all."""
    import io
    import zipfile

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            infos = zf.infolist()
    except zipfile.BadZipFile:
        return None

    return [
        {
            "filename": info.filename,
            "dangerous_extension": _file_extension(info.filename) in _DANGEROUS_ATTACHMENT_EXTENSIONS,
            "declared_size_bytes": info.file_size,
            "likely_zip_bomb": info.file_size > _ZIP_BOMB_SIZE_THRESHOLD_BYTES,
        }
        for info in infos
    ]


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
    """{"html", "subject", "from", "to", "date", "from_domain",
    "display_name", "auth", "attachments"}. from_domain is the sender
    address's domain (e.g. "secure-paypal-verify.com" from
    "noreply@secure-paypal-verify.com") - a reasonable default url_hint
    for build_result_from_html(): an email's claimed sending domain is
    exactly the kind of thing our brand/domain-mismatch heuristic is
    designed to catch, repurposed from "page domain" to "sender domain".
    display_name is the From header's free-text name part (e.g.
    "Vinci|Autoroutes" from "Vinci|Autoroutes <donotreply@marionnaud.fr>")
    - see display_name_domain_mismatch().

    auth = {"spf", "dkim", "dmarc": "pass"/"fail"/"softfail"/.../None,
    "dkim_signing_domain": str | None, "header_count": int} - see
    _parse_authentication_results()'s docstring for the trust caveat.

    attachments = [{"filename", "content_type", "size_bytes",
    "dangerous_extension", "double_extension", "archive_contents"}, ...]
    - metadata only, nothing is ever extracted/decompressed/executed.
    archive_contents is the zip's internal file listing (see
    _inspect_zip_contents) for a .zip attachment, else None - this is
    the one place a real phishing delivery mechanism (not just a
    phishing link in the body) gets looked at, see
    apply_dangerous_attachments()."""
    with open(path, "rb") as f:
        msg = message_from_bytes(f.read(), policy=policy.default)

    html_part, text_part, attachments = None, None, []
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == "text/html" and html_part is None:
            html_part = part.get_content()
        elif content_type == "text/plain" and text_part is None:
            text_part = part.get_content()

        if part.get_content_disposition() == "attachment":
            filename = part.get_filename() or "(unnamed)"
            payload = part.get_payload(decode=True) or b""
            ext = _file_extension(filename)
            archive_contents = _inspect_zip_contents(payload) if ext == "zip" else None
            attachments.append({
                "filename": filename,
                "content_type": content_type,
                "size_bytes": len(payload),
                "dangerous_extension": ext in _DANGEROUS_ATTACHMENT_EXTENSIONS,
                "double_extension": _has_double_extension(filename),
                "archive_contents": archive_contents,
            })

    if html_part is None:
        body = html_module.escape(text_part or "")
        html_part = f"<html><body><pre>{body}</pre></body></html>"

    from_header = msg.get("from", "") or ""
    display_name, from_addr = parseaddr(from_header)
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
        "display_name": display_name,
        "auth": auth,
        "attachments": attachments,
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


_GENERIC_DISPLAY_NAME_WORDS = {
    "team", "support", "service", "services", "noreply", "notification", "notifications",
    "info", "contact", "mail", "customer", "care", "security", "account", "accounts", "alert", "alerts",
    "update", "updates", "news", "newsletter", "admin", "administrator", "help", "helpdesk", "reply",
    "sales", "marketing", "billing", "orders", "order", "confirm", "confirmation", "online", "direct",
}


def _display_name_tokens(display_name: str) -> list[str]:
    """Significant words from a From header's display name - splits on
    anything non-alphanumeric (handles separators like "Vinci|Autoroutes"),
    drops short/generic words ("no-reply", "team"...) that would make
    almost any domain look like a mismatch."""
    raw = re.split(r"[^\w]+", display_name, flags=re.UNICODE)
    return [t for t in raw if len(t) >= 3 and t.lower() not in _GENERIC_DISPLAY_NAME_WORDS]


def display_name_domain_mismatch(display_name: str, from_domain: str) -> bool:
    """True if the From header's display name doesn't share a single
    significant word with the actual sending domain - e.g. "Vinci|
    Autoroutes <donotreply@marionnaud.fr>": neither "vinci" nor
    "autoroutes" appears anywhere in marionnaud.fr, a real case this
    caught that BRAND_LEGITIMATE_DOMAINS (web_analysis.py) missed, since
    that list only covers the handful of global brands we happened to
    enumerate. This needs no such list - it generalizes to any
    impersonated organization, at the cost of being noisier.

    KNOWN FALSE-POSITIVE MODE: a legitimate personal-name sender whose
    name happens to share no word with their employer's domain (e.g.
    "John Dupont <j.dupont@some-corp.fr>") will also trigger this. That
    tradeoff is deliberate and consistent with the rest of this project
    (see README.md -> Limites connues): lean toward flagging for human
    review rather than silently missing a real impersonation."""
    tokens = _display_name_tokens(display_name)
    if not tokens:
        return False
    domain_lower = from_domain.lower()
    return not any(tok.lower() in domain_lower for tok in tokens)


def apply_display_name_mismatch(verdict: dict, display_name: str, from_domain: str) -> dict:
    """Pushes toward "phishing" when the sender's display name names an
    organization absent from the actual sending domain - classic
    display-name spoofing (free email service, or a throwaway domain,
    dressed up with a trusted-looking name). Unlike apply_email_auth,
    this is symmetric with itself (no "pass" case to stay neutral on):
    either it fires or it doesn't. See display_name_domain_mismatch's
    docstring for the false-positive tradeoff."""
    if not display_name_domain_mismatch(display_name, from_domain):
        return verdict

    note = (
        f"sender display name ({display_name!r}) does not name the actual sending domain "
        f"({from_domain}) - possible display-name spoofing (heuristic: can also trigger on a "
        "legitimate personal-name sender, see offline_content.py)"
    )
    new_verdict = dict(verdict)
    if verdict["label"] == "phishing":
        new_verdict["confidence"] = f"{verdict['confidence']}; {note}"
    else:
        new_verdict["label"] = "phishing"
        new_verdict["confidence"] = note
    return new_verdict


def dkim_domain_aligned(signing_domain: str | None, from_domain: str) -> bool:
    """DMARC-style "relaxed" alignment: the DKIM signing domain and the
    From: header's domain must share the same organizational/registrable
    domain (mail.example.com aligns with example.com) - not necessarily
    an exact match, which is how DMARC itself defines relaxed alignment
    (the common default; "strict" mode requiring an exact match is rarer
    in practice). Returns True (nothing to flag) if either domain is
    missing - alignment has nothing to check without both."""
    if not signing_domain or not from_domain:
        return True
    from . import web_analysis as wa

    return wa._registrable_domain(signing_domain.lower()) == wa._registrable_domain(from_domain.lower())


def apply_dkim_verification(verdict: dict, dkim_result: dict, from_domain: str | None = None) -> dict:
    """Unlike apply_email_auth's DKIM check (self-reported - a claim
    from whichever mail system added Authentication-Results),
    dkim_result comes from websec_agent.dkim_verify actually
    recomputing the cryptographic signature against the signing
    domain's public DNS key - genuinely independent evidence, not a
    claim we're choosing to trust.

    verified=False (a signature is present but doesn't validate - either
    tampered in transit or forged outright) pushes hard toward phishing.
    verified=None (no DKIM-Signature header at all) is not evidence
    either way - plenty of legitimate mail isn't DKIM-signed, so absence
    isn't suspicious the way an invalid signature is.

    verified=True does NOT by itself push toward benign - same reasoning
    as apply_email_auth: a valid signature only proves the signing
    domain really authorized the message, not that the message's
    content is safe. But a valid signature from a domain that doesn't
    match the visible From: header (from_domain) - this is what DMARC
    calls identifier alignment, and it's the gap a prior version of this
    function had: it only checked whether the signature validated, never
    whether it was signed by the domain it claims to be from. A message
    can carry a perfectly valid DKIM signature from some unrelated
    platform (anything an attacker has a legitimate signing identity on
    - a SaaS mailer, a compromised/abused domain) while the From: header
    claims to be a completely different brand. That mismatch is computed
    independently here too (dkim_domain_aligned), not self-reported -
    and DOES push toward phishing, unlike a bare valid-and-aligned
    signature."""
    verified = dkim_result.get("verified")
    signing_domain = dkim_result.get("signing_domain")

    if verified is False:
        domain = signing_domain or "an unknown domain"
        note = (
            f"DKIM signature independently verified as INVALID (claims to be signed by "
            f"{domain}, but the cryptographic signature does not match - tampered in transit "
            "or forged) - see websec_agent/dkim_verify.py"
        )
    elif verified is True and from_domain and not dkim_domain_aligned(signing_domain, from_domain):
        note = (
            f"DKIM signature is cryptographically VALID, but signed by {signing_domain!r} - "
            f"which does not match the claimed sender domain {from_domain!r}. The signature is "
            "real, just not from who the message claims to be from (DMARC identifier "
            "misalignment, computed independently - see websec_agent/dkim_verify.py)"
        )
    else:
        return verdict

    new_verdict = dict(verdict)
    if verdict["label"] == "phishing":
        new_verdict["confidence"] = f"{verdict['confidence']}; {note}"
    else:
        new_verdict["label"] = "phishing"
        new_verdict["confidence"] = note
    return new_verdict


def apply_dangerous_attachments(verdict: dict, attachments: list[dict]) -> dict:
    """Pushes toward phishing when an attachment - or a file INSIDE a zip
    attachment, see _inspect_zip_contents - has a dangerous executable
    extension, a double extension disguising one ("facture.pdf.exe"), or
    a declared size consistent with a zip bomb. An archive attachment
    (zip/rar/7z) is never flagged just for existing - legitimate senders
    attach zips too - only actually dangerous contents are."""
    flagged = []
    for att in attachments:
        if att["dangerous_extension"] or att["double_extension"]:
            flagged.append(att["filename"])
        for inner in att.get("archive_contents") or []:
            if inner["dangerous_extension"]:
                flagged.append(f"{att['filename']} -> {inner['filename']}")
            elif inner["likely_zip_bomb"]:
                flagged.append(f"{att['filename']} -> {inner['filename']} (implausible declared size, possible zip bomb)")

    if not flagged:
        return verdict

    note = f"dangerous email attachment(s): {'; '.join(flagged)}"
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
