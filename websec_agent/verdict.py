"""Combine the hand-tuned heuristic score and the trained classifier's
probability into one coherent verdict, instead of leaving the agent (or
the user) to reconcile two independent opinions on the same page.

Erring toward "phishing" when the two signals disagree is a deliberate
security-triage choice: missing a real phishing page costs more than a
false alarm that a human then dismisses.
"""
from __future__ import annotations

PHISHING_PROB_HIGH = 0.75
PHISHING_PROB_LOW = 0.25
YOUNG_DOMAIN_DAYS = 30
ESTABLISHED_DOMAIN_DAYS = 365


def _domain_age_tiebreak(domain_age: dict | None) -> tuple[str, str] | None:
    """Only called to break an "uncertain" tie - a corroborating signal,
    not an independent override (a freshly-registered domain can still be
    a legitimate new site)."""
    if not domain_age or domain_age.get("age_days") is None:
        return None
    age = domain_age["age_days"]
    if age < YOUNG_DOMAIN_DAYS:
        return "phishing", f"signals disagree, but the domain is only {age} days old - treating as phishing"
    if age > ESTABLISHED_DOMAIN_DAYS:
        return "benign", f"signals disagree, but the domain is {age} days old - treating as benign"
    return None


def combine_verdicts(heuristic: dict, ml: dict | None, domain_age: dict | None = None) -> dict:
    """heuristic: web_analysis.score_phishing()'s return value.
    ml: classifier.classify_webpage()'s return value, or None if the MLOps
    extras/trained model aren't available - degrades to heuristic-only.
    domain_age: domain_age.lookup_domain_age()'s return value, used only to
    break an "uncertain" tie (see _domain_age_tiebreak)."""
    if ml is None:
        label = "phishing" if heuristic["level"] in ("medium", "high") else "benign"
        return {
            "label": label,
            "confidence": "heuristic-only (ML classifier unavailable)",
            "agreement": None,
            "heuristic": heuristic,
            "ml": None,
            "domain_age": domain_age,
        }

    ml_prob = ml["phishing_probability"]
    ml_says_phish = ml_prob >= 0.5
    heuristic_says_phish = heuristic["level"] in ("medium", "high")
    agreement = ml_says_phish == heuristic_says_phish

    if heuristic["level"] == "high" or ml_prob >= PHISHING_PROB_HIGH:
        label = "phishing"
    elif heuristic["level"] == "low" and ml_prob <= PHISHING_PROB_LOW:
        label = "benign"
    else:
        label = "uncertain"

    confidence = "both signals agree" if agreement else "signals disagree - review manually"
    if label == "uncertain":
        tiebreak = _domain_age_tiebreak(domain_age)
        if tiebreak:
            label, confidence = tiebreak

    return {
        "label": label,
        "confidence": confidence,
        "agreement": agreement,
        "heuristic": heuristic,
        "ml": ml,
        "domain_age": domain_age,
    }
