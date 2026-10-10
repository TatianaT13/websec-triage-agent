"""Shared fixtures across the whole test suite.

Network isolation for domain age: websec_agent.domain_age.lookup_domain_age()
makes real RDAP HTTP calls (the IANA bootstrap registry, then the per-TLD
RDAP server) - appropriate for its own dedicated tests in
test_domain_age.py, but every other test that happens to call
build_result_from_html() or hit a webapp /analyze* endpoint was silently
depending on those two real network round-trips succeeding on every single
run, for a signal the test isn't even checking - a flakiness risk with
nothing to do with the code under test. Stub it to a safe, static "unknown"
result everywhere else; test_domain_age.py overrides this fixture with a
no-op so its real-RDAP tests are unaffected.
"""
import pytest

from websec_agent import domain_age as da


@pytest.fixture(autouse=True)
def _no_real_rdap_calls(monkeypatch):
    def _stub(hostname: str) -> dict:
        return {
            "registrable_domain": hostname,
            "is_platform_hosted": False,
            "age_days": None,
            "registered_at": None,
        }

    monkeypatch.setattr(da, "lookup_domain_age", _stub)
