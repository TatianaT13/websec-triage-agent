"""Tests for webapp_security.py: rate limiting (always on) and opt-in
HTTP Basic auth. Uses fresh _FixedWindowLimiter/require_auth instances
per test rather than the shared module-level singleton webapp.py uses,
so tests don't leak rate-limit state into each other."""
import pytest

pytest.importorskip("fastapi", reason="requires requirements-web.txt")

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from websec_agent import webapp_security as sec


# --- rate limiting -------------------------------------------------------


def test_allows_requests_under_the_limit():
    limiter = sec._FixedWindowLimiter(max_requests=3, window_seconds=60)
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is True


def test_blocks_requests_over_the_limit():
    limiter = sec._FixedWindowLimiter(max_requests=3, window_seconds=60)
    for _ in range(3):
        limiter.allow("1.2.3.4")
    assert limiter.allow("1.2.3.4") is False


def test_different_keys_have_independent_quotas():
    limiter = sec._FixedWindowLimiter(max_requests=1, window_seconds=60)
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("5.6.7.8") is True  # a different IP, not blocked by the first one's usage


def test_window_resets_after_it_elapses(monkeypatch):
    limiter = sec._FixedWindowLimiter(max_requests=1, window_seconds=10)
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is False

    real_monotonic = sec.time.monotonic
    monkeypatch.setattr(sec.time, "monotonic", lambda: real_monotonic() + 11)
    assert limiter.allow("1.2.3.4") is True


def test_rate_limit_dependency_returns_429_when_exhausted(monkeypatch):
    monkeypatch.setattr(sec, "_limiter", sec._FixedWindowLimiter(max_requests=1, window_seconds=60))
    app = FastAPI(dependencies=[Depends(sec.rate_limit)])

    @app.get("/")
    def index():
        return {"ok": True}

    client = TestClient(app)
    assert client.get("/").status_code == 200
    assert client.get("/").status_code == 429


# --- HTTP Basic auth (opt-in) ---------------------------------------------


def _auth_app() -> FastAPI:
    app = FastAPI(dependencies=[Depends(sec.require_auth)])

    @app.get("/")
    def index():
        return {"ok": True}

    return app


def test_no_auth_required_when_env_vars_unset(monkeypatch):
    monkeypatch.delenv("WEBAPP_USERNAME", raising=False)
    monkeypatch.delenv("WEBAPP_PASSWORD", raising=False)
    client = TestClient(_auth_app())
    assert client.get("/").status_code == 200


def test_auth_required_when_both_env_vars_set(monkeypatch):
    monkeypatch.setenv("WEBAPP_USERNAME", "alice")
    monkeypatch.setenv("WEBAPP_PASSWORD", "s3cret")
    client = TestClient(_auth_app())
    assert client.get("/").status_code == 401


def test_correct_credentials_are_accepted(monkeypatch):
    monkeypatch.setenv("WEBAPP_USERNAME", "alice")
    monkeypatch.setenv("WEBAPP_PASSWORD", "s3cret")
    client = TestClient(_auth_app())
    resp = client.get("/", auth=("alice", "s3cret"))
    assert resp.status_code == 200


def test_wrong_credentials_are_rejected(monkeypatch):
    monkeypatch.setenv("WEBAPP_USERNAME", "alice")
    monkeypatch.setenv("WEBAPP_PASSWORD", "s3cret")
    client = TestClient(_auth_app())
    resp = client.get("/", auth=("alice", "wrong-password"))
    assert resp.status_code == 401


def test_only_username_set_does_not_require_auth(monkeypatch):
    # Both must be set - a half-configured deployment shouldn't silently
    # lock out everyone, or silently allow everyone either.
    monkeypatch.setenv("WEBAPP_USERNAME", "alice")
    monkeypatch.delenv("WEBAPP_PASSWORD", raising=False)
    client = TestClient(_auth_app())
    assert client.get("/").status_code == 200


def test_client_ip_ignores_forwarded_header_by_default(monkeypatch):
    monkeypatch.delenv("WEBAPP_TRUST_PROXY_HEADERS", raising=False)
    app = FastAPI()

    @app.get("/")
    def index(request: Request):
        return {"ip": sec._client_ip(request)}

    client = TestClient(app)
    resp = client.get("/", headers={"X-Forwarded-For": "9.9.9.9"})
    assert resp.json()["ip"] != "9.9.9.9"


def test_client_ip_trusts_forwarded_header_when_opted_in(monkeypatch):
    monkeypatch.setenv("WEBAPP_TRUST_PROXY_HEADERS", "1")
    app = FastAPI()

    @app.get("/")
    def index(request: Request):
        return {"ip": sec._client_ip(request)}

    client = TestClient(app)
    resp = client.get("/", headers={"X-Forwarded-For": "9.9.9.9"})
    assert resp.json()["ip"] == "9.9.9.9"
