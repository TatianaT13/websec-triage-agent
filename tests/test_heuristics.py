"""Regression tests for the heuristics, built from patterns observed in real
samples pulled from the OpenPhish public feed during calibration (see
README.md -> Limites connues). Fixtures are synthetic reconstructions of
those patterns, not live/hardcoded malicious URLs, so they stay stable.
"""
from websec_agent import web_analysis as wa

from .fixtures import (
    BENIGN_HTML,
    CREDENTIAL_PHISH_HTML,
    IP_LITERAL_IOC_HTML,
    LOOKALIKE_SUBDOMAIN_HTML,
    PUNYCODE_IOC_HTML,
)


def test_benign_page_scores_low():
    structure = wa.analyze_structure(BENIGN_HTML, "https://example.com")
    iocs = wa.extract_iocs(BENIGN_HTML, "https://example.com")
    verdict = wa.score_phishing(BENIGN_HTML, structure, iocs, "https://example.com")
    assert verdict["level"] == "low"
    assert verdict["score"] == 0


def test_brand_in_title_on_lookalike_subdomain_is_flagged():
    url = "https://wetransfer-smoky.vercel.app/"
    structure = wa.analyze_structure(LOOKALIKE_SUBDOMAIN_HTML, url)
    iocs = wa.extract_iocs(LOOKALIKE_SUBDOMAIN_HTML, url)
    verdict = wa.score_phishing(LOOKALIKE_SUBDOMAIN_HTML, structure, iocs, url)
    assert verdict["level"] in ("medium", "high")
    assert any("wetransfer" in r for r in verdict["reasons"])


def test_real_brand_domain_is_not_flagged_for_its_own_name():
    # wetransfer.com mentioning "WeTransfer" in its own title must not
    # trigger the brand-impersonation reason.
    url = "https://wetransfer.com/"
    structure = wa.analyze_structure(LOOKALIKE_SUBDOMAIN_HTML, url)
    iocs = wa.extract_iocs(LOOKALIKE_SUBDOMAIN_HTML, url)
    verdict = wa.score_phishing(LOOKALIKE_SUBDOMAIN_HTML, structure, iocs, url)
    assert not any("brand" in r for r in verdict["reasons"])


def test_credential_phish_scores_high():
    url = "https://totally-legit-mail.example/"
    structure = wa.analyze_structure(CREDENTIAL_PHISH_HTML, url)
    iocs = wa.extract_iocs(CREDENTIAL_PHISH_HTML, url)
    verdict = wa.score_phishing(CREDENTIAL_PHISH_HTML, structure, iocs, url)
    assert verdict["level"] == "high"
    reasons = " ".join(verdict["reasons"])
    assert "password field submits to external domain" in reasons
    assert "urgency" in reasons


def test_punycode_domain_is_extracted_as_ioc():
    iocs = wa.extract_iocs(PUNYCODE_IOC_HTML, "https://example.com")
    assert iocs["punycode_domains"] == ["xn--pypal-4ve.com"]


def test_ip_literal_url_is_extracted_as_ioc():
    iocs = wa.extract_iocs(IP_LITERAL_IOC_HTML, "https://example.com")
    assert iocs["ip_literal_urls"] == ["http://203.0.113.42/track.png"]


def test_registrable_domain_handles_multi_label_suffixes():
    # .co.uk, .com.mu etc. are two-label public suffixes - naive "last two
    # labels" parsing collapses every site on them into one, which would
    # mask lookalike domains sharing a country-code TLD.
    assert wa._registrable_domain("www.bbc.co.uk") == "bbc.co.uk"
    assert wa._registrable_domain("www.roblox.com.mu") == "roblox.com.mu"
    assert wa._registrable_domain("evil.co.uk") == "evil.co.uk"


def test_paas_subdomains_are_treated_as_distinct_sites():
    # vercel.app/pages.dev are PSL "private" suffixes - every tenant
    # subdomain is a different, unrelated site.
    assert wa._registrable_domain("wetransfer-smoky.vercel.app") == "wetransfer-smoky.vercel.app"
    assert wa._registrable_domain("other-tenant.vercel.app") == "other-tenant.vercel.app"
