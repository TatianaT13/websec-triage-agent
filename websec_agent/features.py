"""Turn the heuristic analysis into a fixed-size numeric feature vector for
the trained classifier. Reuses the same structure/IOC extraction as the
rule-based score (web_analysis.py) so both approaches see the same signals -
the heuristic score stays a readable, hand-tuned baseline; the classifier
learns its own weights (and interactions) from labeled data on top of it.
"""
from __future__ import annotations

from . import web_analysis as wa

FEATURE_NAMES = [
    "num_forms",
    "has_password_field",
    "has_external_password_action",
    "has_non_https_password_action",
    "script_src_count",
    "external_script_ratio",
    "link_count",
    "external_link_ratio",
    "iframe_count",
    "favicon_is_external",
    "meta_refresh",
    "brand_in_title_mismatch",
    "brand_in_text_mismatch",
    "domain_count",
    "punycode_domain_count",
    "shortener_link_count",
    "ip_literal_url_count",
    "suspicious_tld_domain_count",
    "urgency_word_count",
    "title_length",
    "domain_length",
    "domain_hyphen_count",
    "domain_digit_count",
]


def extract_features(html: str, base_url: str) -> dict:
    structure = wa.analyze_structure(html, base_url)
    iocs = wa.extract_iocs(html, base_url)
    heuristic = wa.score_phishing(html, structure, iocs, base_url)
    reasons = " | ".join(heuristic["reasons"])

    forms = structure["forms"]
    domain = wa._domain_of(base_url)

    return {
        "num_forms": len(forms),
        "has_password_field": int(any(f["has_password_field"] for f in forms)),
        "has_external_password_action": int(
            any(f["has_password_field"] and f["action_is_external"] for f in forms)
        ),
        "has_non_https_password_action": int(
            any(
                f["has_password_field"] and f["action"] and not f["action"].startswith("https:")
                for f in forms
            )
        ),
        "script_src_count": structure["script_src_count"],
        "external_script_ratio": _safe_ratio(len(structure["external_scripts"]), structure["script_src_count"]),
        "link_count": structure["link_count"],
        "external_link_ratio": _safe_ratio(structure["external_link_count"], structure["link_count"]),
        "iframe_count": len(structure["iframes"]),
        "favicon_is_external": int(structure["favicon_is_external"]),
        "meta_refresh": int(structure["meta_refresh"]),
        "brand_in_title_mismatch": int("in page title but site domain is" in reasons),
        "brand_in_text_mismatch": int("mentioned in page text but site domain is" in reasons),
        "domain_count": len(iocs["domains"]),
        "punycode_domain_count": len(iocs["punycode_domains"]),
        "shortener_link_count": len(iocs["shortener_links"]),
        "ip_literal_url_count": len(iocs["ip_literal_urls"]),
        "suspicious_tld_domain_count": len(iocs["suspicious_tld_domains"]),
        "urgency_word_count": sum(1 for r in heuristic["reasons"] if "urgency" in r),
        "title_length": len(structure["title"] or ""),
        "domain_length": len(domain),
        "domain_hyphen_count": domain.count("-"),
        "domain_digit_count": sum(c.isdigit() for c in domain),
    }


def _safe_ratio(numerator: int, denominator: int) -> float:
    return (numerator / denominator) if denominator else 0.0
