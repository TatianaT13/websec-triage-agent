"""Tests for the RDAP-based domain age lookup. Makes real network calls
(IANA bootstrap + the per-domain RDAP server) on purpose - this file's job
is testing that real integration, unlike every other test file where
tests/conftest.py stubs lookup_domain_age() to avoid depending on it."""
import pytest

from websec_agent import domain_age as da


@pytest.fixture(autouse=True)
def _no_real_rdap_calls():
    """Override the blanket stub from tests/conftest.py - this file's
    whole point is exercising the real RDAP calls."""


def test_platform_hosted_subdomain_has_no_meaningful_age():
    # RDAP would only return vercel.app's own (ancient, irrelevant)
    # registration date here - correctly reported as "not meaningful"
    # rather than returned as if it were the tenant subdomain's age.
    result = da.lookup_domain_age("wetransfer-smoky.vercel.app")
    assert result["is_platform_hosted"] is True
    assert result["age_days"] is None
    assert result["registrable_domain"] == "wetransfer-smoky.vercel.app"


def test_reserved_tld_has_no_rdap_record():
    # .example is reserved for documentation (RFC 2606) - not a real gTLD,
    # so it has no RDAP bootstrap entry. Must degrade gracefully, not raise.
    result = da.lookup_domain_age("totally-legit-mail.example")
    assert result["age_days"] is None


def test_long_established_domain_has_a_large_age():
    result = da.lookup_domain_age("wikipedia.org")
    assert result["is_platform_hosted"] is False
    assert result["age_days"] is not None
    assert result["age_days"] > 365 * 10  # registered in 2001


def test_lookup_is_cached_for_the_same_domain():
    da.lookup_domain_age("example.com")
    before = dict(da._lookup_cache)
    da.lookup_domain_age("example.com")
    assert da._lookup_cache == before  # second call didn't need to refetch
