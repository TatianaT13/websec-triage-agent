"""Tests for the VirusTotal lookup. Mocks the `vt` package entirely (no
real API key/network needed) so these run in plain CI - the one thing
worth testing live, if you have a VT_API_KEY, is that vt-py's actual
wire format still matches what check_url() expects."""
import sys
import types

import pytest

from websec_agent import virustotal as vtmod


class _FakeObject:
    def __init__(self, attrs: dict, obj_id: str = "fake-id"):
        self._attrs = attrs
        self.id = obj_id

    def get(self, name, default=None):
        return self._attrs.get(name, default)


def _install_fake_vt(monkeypatch, *, get_object_fn=None, scan_url_result=None):
    fake_vt = types.ModuleType("vt")

    class APIError(Exception):
        def __init__(self, code, message=""):
            self.code = code
            self.message = message
            super().__init__(code, message)

    class FakeClient:
        def __init__(self, key):
            self.key = key

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get_object(self, path, *args):
            if get_object_fn is None:
                raise APIError("NotFoundError", "not found")
            return get_object_fn(path, *args)

        def scan_url(self, url, wait_for_completion=False):
            return scan_url_result

    fake_vt.Client = FakeClient
    fake_vt.APIError = APIError
    fake_vt.url_id = lambda u: "fake-url-id"
    monkeypatch.setitem(sys.modules, "vt", fake_vt)
    monkeypatch.setenv("VT_API_KEY", "test-key")
    return fake_vt


def test_requires_api_key(monkeypatch):
    # Must fail on the missing key specifically, regardless of whether
    # vt-py happens to be installed in this environment - inject a fake
    # importable `vt` so the import itself can't be what raises here.
    _install_fake_vt(monkeypatch)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="VT_API_KEY"):
        vtmod.check_url("https://example.com")


def test_requires_vt_py_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "vt", None)
    monkeypatch.setenv("VT_API_KEY", "test-key")
    with pytest.raises(RuntimeError, match="requirements-threatintel"):
        vtmod.check_url("https://example.com")


def test_cached_result_returned_immediately(monkeypatch):
    stats = {"malicious": 3, "suspicious": 1, "harmless": 60}

    def get_object_fn(path, *args):
        assert path.startswith("/urls/")
        return _FakeObject({"last_analysis_stats": stats})

    _install_fake_vt(monkeypatch, get_object_fn=get_object_fn)

    result = vtmod.check_url("https://example.com")
    assert result == {"source": "cached", "stats": stats, "url": "https://example.com"}


def test_not_found_then_fresh_scan_completes(monkeypatch):
    calls = {"n": 0}

    def get_object_fn(path, *args):
        if path.startswith("/urls/"):
            raise vt_module_apierror()
        calls["n"] += 1
        status = "in-progress" if calls["n"] == 1 else "completed"
        return _FakeObject({"status": status, "stats": {"malicious": 1}})

    def vt_module_apierror():
        return sys.modules["vt"].APIError("NotFoundError", "not found")

    _install_fake_vt(
        monkeypatch,
        get_object_fn=get_object_fn,
        scan_url_result=_FakeObject({}, obj_id="analysis-1"),
    )

    result = vtmod.check_url("https://example.com", poll_interval_s=0)
    assert result["source"] == "fresh"
    assert result["stats"] == {"malicious": 1}
    assert calls["n"] == 2  # polled once in-progress, then completed


def test_fresh_scan_times_out(monkeypatch):
    def get_object_fn(path, *args):
        if path.startswith("/urls/"):
            raise sys.modules["vt"].APIError("NotFoundError", "not found")
        return _FakeObject({"status": "in-progress"})

    _install_fake_vt(
        monkeypatch,
        get_object_fn=get_object_fn,
        scan_url_result=_FakeObject({}, obj_id="analysis-1"),
    )

    result = vtmod.check_url("https://example.com", max_wait_s=0, poll_interval_s=0)
    assert result == {"source": "timeout", "stats": None, "url": "https://example.com"}


def test_non_notfound_api_error_propagates(monkeypatch):
    def get_object_fn(path, *args):
        raise sys.modules["vt"].APIError("QuotaExceededError", "quota exceeded")

    _install_fake_vt(monkeypatch, get_object_fn=get_object_fn)

    with pytest.raises(Exception, match="quota exceeded"):
        vtmod.check_url("https://example.com")
