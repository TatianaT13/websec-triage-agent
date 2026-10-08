"""Independent DKIM signature verification - unlike the self-reported
Authentication-Results header (offline_content.py), this actually
recomputes and checks the cryptographic signature against the signing
domain's public key, published in DNS. Requires
requirements-email-verify.txt (dkimpy, dnspython).

Why DKIM gets this treatment and SPF doesn't: DKIM is end-to-end
cryptographic - its signature covers the message content itself, so
verifying it needs nothing but the message bytes and a DNS lookup,
regardless of how the .eml file reached us. SPF authenticates the
connecting SMTP client's IP address instead, which isn't preserved in
the message except via the Received: header chain - and that chain is
exactly as forgeable/editable as the Authentication-Results header
already is (see offline_content.py's docstring on that trust
boundary). Re-implementing "SPF verification" from a static .eml file
wouldn't actually close that trust gap, just move it one layer deeper
while looking more rigorous - so this project doesn't pretend to. DKIM's
offline verifiability is the whole reason it gets a real upgrade here.

Verified against a real sign/verify/tamper roundtrip (a message signed
with a throwaway keypair, with dkimpy's DNS lookup swapped for a fake
one serving that keypair's public key) before being wired in: a valid
signature verifies true, a single tampered byte in the body verifies
false.
"""
from __future__ import annotations

import re

_SIGNING_DOMAIN_RE = re.compile(rb"\bd=([^;\s]+)")


class DKIMVerificationError(Exception):
    pass


def verify_dkim_signature(raw_eml_bytes: bytes, dnsfunc=None) -> dict:
    """Returns {"verified": bool | None, "signing_domain": str | None,
    "detail": str}. verified=None means there was no DKIM-Signature
    header to check at all - distinct from verified=False (an actual
    invalid/failed signature): not every legitimate email is
    DKIM-signed, so a missing signature isn't itself suspicious the way
    a broken one is.

    dnsfunc lets tests inject a fake DNS TXT lookup instead of hitting
    real DNS - deliberately NOT done by monkeypatching dkim.get_txt:
    dkim.verify()'s own dnsfunc parameter default is bound to the
    function object at dkimpy's import time, so patching the module
    attribute afterward silently has no effect on calls that don't pass
    dnsfunc explicitly (confirmed the hard way - a first version of this
    function's test suite passed with a verified=False it shouldn't
    have). Passing our own dnsfunc through explicitly avoids that trap."""
    try:
        import dkim
    except ImportError as exc:
        raise RuntimeError(
            "DKIM verification requires: pip install -r requirements-email-verify.txt"
        ) from exc

    if b"dkim-signature" not in raw_eml_bytes.lower():
        return {"verified": None, "signing_domain": None, "detail": "no DKIM-Signature header present"}

    sig_match = _SIGNING_DOMAIN_RE.search(raw_eml_bytes)
    signing_domain = sig_match.group(1).decode("ascii", errors="replace") if sig_match else None

    try:
        valid = dkim.verify(raw_eml_bytes, dnsfunc=dnsfunc) if dnsfunc else dkim.verify(raw_eml_bytes)
    except dkim.DKIMException as exc:
        return {"verified": False, "signing_domain": signing_domain, "detail": f"verification error: {exc}"}

    detail = "signature cryptographically valid" if valid else "signature invalid or does not match message content"
    return {"verified": valid, "signing_domain": signing_domain, "detail": detail}
