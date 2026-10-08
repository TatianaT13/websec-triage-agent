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
    WRONG_TLD_LOOKALIKE_HTML,
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


def test_wrong_tld_lookalike_is_flagged_even_with_matching_label():
    # roblox.com.mu: same eTLD+1 *label* as roblox.com, but not in roblox's
    # legitimate-domain allowlist - must be flagged, not waved through just
    # because the label matches (see README.md -> Limites connues).
    url = "https://roblox.com.mu/"
    structure = wa.analyze_structure(WRONG_TLD_LOOKALIKE_HTML, url)
    iocs = wa.extract_iocs(WRONG_TLD_LOOKALIKE_HTML, url)
    verdict = wa.score_phishing(WRONG_TLD_LOOKALIKE_HTML, structure, iocs, url)
    assert any("roblox" in r and "roblox.com.mu" in r for r in verdict["reasons"])


def test_brand_with_dot_in_its_own_keyword_is_not_self_flagged():
    # "booking.com" is both the brand keyword and the real domain - a naive
    # "<brand>.com" fallback would double up the suffix and never match.
    html = "<html><head><title>Booking.com | Official site</title></head><body>Booking.com hotels</body></html>"
    url = "https://booking.com/"
    structure = wa.analyze_structure(html, url)
    iocs = wa.extract_iocs(html, url)
    verdict = wa.score_phishing(html, structure, iocs, url)
    assert not any("brand" in r for r in verdict["reasons"])


def test_brand_whose_real_domain_differs_from_brand_name_is_not_self_flagged():
    # Steam's real domain is steampowered.com, not steam.com.
    html = "<html><head><title>Welcome to Steam</title></head><body>Steam store</body></html>"
    url = "https://store.steampowered.com/"
    structure = wa.analyze_structure(html, url)
    iocs = wa.extract_iocs(html, url)
    verdict = wa.score_phishing(html, structure, iocs, url)
    assert not any("brand" in r for r in verdict["reasons"])


def test_legitimate_regional_domain_variant_is_not_flagged():
    # amazon.fr is a genuine Amazon-operated regional domain, not a lookalike.
    html = "<html><head><title>Amazon.fr</title></head><body>Amazon</body></html>"
    url = "https://amazon.fr/"
    structure = wa.analyze_structure(html, url)
    iocs = wa.extract_iocs(html, url)
    verdict = wa.score_phishing(html, structure, iocs, url)
    assert not any("brand" in r for r in verdict["reasons"])


def test_french_brand_lookalike_domain_is_flagged():
    # Real case that motivated adding French brands to BRAND_KEYWORDS: an
    # email impersonating "Vinci|Autoroutes" went undetected because the
    # list was entirely US/international-tech-centric (see offline_content
    # tests for the display-name-based fix to the same underlying case).
    html = "<html><head><title>Vinci Autoroutes - Espace client</title></head><body>hi</body></html>"
    url = "https://vinci-autoroutes-secure.net/"
    structure = wa.analyze_structure(html, url)
    iocs = wa.extract_iocs(html, url)
    verdict = wa.score_phishing(html, structure, iocs, url)
    assert any("vinci autoroutes" in r for r in verdict["reasons"])


def test_french_brand_real_domain_is_not_flagged():
    html = "<html><head><title>Vinci Autoroutes - Espace client</title></head><body>hi</body></html>"
    url = "https://vinci-autoroutes.com/"
    structure = wa.analyze_structure(html, url)
    iocs = wa.extract_iocs(html, url)
    verdict = wa.score_phishing(html, structure, iocs, url)
    assert not any("brand" in r for r in verdict["reasons"])


def test_accented_french_brand_is_matched_case_and_accent_consistently():
    # Confirms re.escape()/lower() handle accented keywords correctly -
    # not an assumption, this is a real risk with substring matching.
    html = "<html><head><title>Société Générale - Connexion</title></head><body>hi</body></html>"
    url = "https://societe-generale-secure.com/"
    structure = wa.analyze_structure(html, url)
    iocs = wa.extract_iocs(html, url)
    verdict = wa.score_phishing(html, structure, iocs, url)
    assert any("société générale" in r for r in verdict["reasons"])


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
