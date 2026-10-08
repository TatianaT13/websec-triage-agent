"""BIMI (Brand Indicators for Message Identification) lookup - a DNS TXT
record at default._bimi.<domain> pointing to a logo (and optionally a
Verified Mark Certificate, VMC) a mail client may display next to the
sender's name.

DELIBERATELY INFORMATIONAL ONLY - never fed into the verdict, in either
direction. Two separate reasons, not one:

1. Absence isn't suspicious. BIMI adoption is still low even among
   large legitimate senders (most domains simply don't have a record),
   so treating "no BIMI" as a phishing signal would misfire constantly.

2. Presence isn't exculpatory either, and this is the more important
   point: BIMI only proves that the domain's OWNER configured DMARC
   enforcement and chose to publish a particular logo for messages from
   ITS OWN domain. It says nothing about whether that domain is the
   brand it might resemble. Nothing stops an attacker who registers
   "realbank-secure.com" from standing up real mail infrastructure,
   enforcing DMARC, and publishing their own BIMI record pointing at a
   copy of the real bank's logo - BIMI would then validate for that
   phishing domain exactly as "successfully" as it does for the real
   one. A VMC (the `a=` tag, a certificate from a BIMI-authorized CA)
   is supposed to raise the bar by tying the logo to a verified
   trademark holder - but validating a VMC means fetching and checking
   an X.509 certificate chain against the BIMI CA trust roots, real PKI
   work this module does not attempt. So even the stronger VMC case is
   only *reported*, never trusted to clear a domain.

Requires dnspython (already a dependency of requirements-email-verify.txt
via dkimpy, or installable standalone).
"""
from __future__ import annotations

import re

_BIMI_RECORD_RE = re.compile(r"v=BIMI1\s*;\s*l=([^;\s]*)(?:\s*;\s*a=([^;\s]*))?", re.IGNORECASE)


def lookup_bimi(domain: str) -> dict:
    """{"present": bool, "logo_url": str | None, "has_vmc": bool}.
    has_vmc only means an `a=` (authority/VMC) tag is present in the
    record - not that the certificate it points to was validated (see
    module docstring)."""
    if not domain:
        return {"present": False, "logo_url": None, "has_vmc": False}

    try:
        import dns.resolver
    except ImportError as exc:
        raise RuntimeError(
            "BIMI lookup requires: pip install -r requirements-email-verify.txt"
        ) from exc

    try:
        answers = dns.resolver.resolve(f"default._bimi.{domain}", "TXT")
    except Exception:  # noqa: BLE001 - NXDOMAIN, timeout, no record, etc. all mean "no BIMI"
        return {"present": False, "logo_url": None, "has_vmc": False}

    for rdata in answers:
        raw = b"".join(rdata.strings).decode("utf-8", errors="replace")
        match = _BIMI_RECORD_RE.search(raw)
        if match:
            logo_url = match.group(1) or None
            vmc_url = match.group(2) or None
            return {"present": True, "logo_url": logo_url, "has_vmc": bool(vmc_url)}

    return {"present": False, "logo_url": None, "has_vmc": False}
