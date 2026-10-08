"""Opt-in hardening for webapp.py: rate limiting (always on, generous
default - tunable, never off) and HTTP Basic auth (opt-in via env vars).

webapp.py's own docstring already says not to expose it beyond localhost
without adding auth - this is what "adding auth" means in practice, for
whoever eventually does that instead of leaving the warning unactioned.
Both pieces are deliberately simple (in-memory, single-process, no
Redis/session store) since this is a local/single-instance tool, not a
distributed service - see each piece's own docstring for why.
"""
from __future__ import annotations

import os
import secrets
import time
from collections import defaultdict

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials

# --- Rate limiting -----------------------------------------------------


class _FixedWindowLimiter:
    """Per-key fixed-window counter. Deliberately not a sliding-window or
    token-bucket algorithm - those are more precise but this tool doesn't
    need that precision, and a fixed window is simpler to read and
    audit. Resets every window_seconds; in-memory, so counts reset on
    restart (acceptable here - this isn't meant to survive restarts)."""

    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._counts: dict[str, tuple[float, int]] = defaultdict(lambda: (0.0, 0))

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        window_start, count = self._counts[key]
        if now - window_start >= self.window_seconds:
            self._counts[key] = (now, 1)
            return True
        if count >= self.max_requests:
            return False
        self._counts[key] = (window_start, count + 1)
        return True


# Generous by default so normal local/single-operator use is never
# affected - this exists for the case where the UI ends up reachable by
# more than one person, not to throttle the one trusted operator it's
# designed for.
RATE_LIMIT_MAX = int(os.environ.get("WEBAPP_RATE_LIMIT_MAX", "20"))
RATE_LIMIT_WINDOW_S = float(os.environ.get("WEBAPP_RATE_LIMIT_WINDOW_S", "60"))
_limiter = _FixedWindowLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_S)


def _client_ip(request: Request) -> str:
    # X-Forwarded-For is only trusted if explicitly opted into (running
    # behind a real reverse proxy that sets it) - otherwise any client
    # could put an arbitrary value in that header themselves and get a
    # fresh rate-limit bucket for free, defeating the whole point.
    if os.environ.get("WEBAPP_TRUST_PROXY_HEADERS") == "1":
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(request: Request) -> None:
    """FastAPI dependency - raises 429 once this client exceeds
    RATE_LIMIT_MAX requests per RATE_LIMIT_WINDOW_S seconds. Always
    active (no opt-out short of setting the env vars very high) -
    tunable, not optional, since an unbounded request rate is a real
    cost here (screenshot_webpage-style render/fetch endpoints are not
    cheap to let anyone hammer)."""
    if not _limiter.allow(_client_ip(request)):
        raise HTTPException(status_code=429, detail="Too many requests - try again shortly.")


# --- HTTP Basic auth (opt-in) -------------------------------------------

_security = HTTPBasic(auto_error=False)


def require_auth(credentials: HTTPBasicCredentials | None = Depends(_security)) -> None:
    """No-op (no auth required) unless WEBAPP_USERNAME and WEBAPP_PASSWORD
    are BOTH set in the environment - the default local-only experience
    is unchanged unless someone deliberately opts into this. Uses
    secrets.compare_digest for both the username and password checks to
    avoid a timing side-channel leaking how much of either string was
    guessed correctly."""
    expected_user = os.environ.get("WEBAPP_USERNAME")
    expected_pass = os.environ.get("WEBAPP_PASSWORD")
    if not expected_user or not expected_pass:
        return  # auth not configured - same behavior as before this existed

    valid = (
        credentials is not None
        and secrets.compare_digest(credentials.username, expected_user)
        and secrets.compare_digest(credentials.password, expected_pass)
    )
    if not valid:
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
