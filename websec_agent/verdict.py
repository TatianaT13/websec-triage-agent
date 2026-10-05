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


def _apply_virustotal(label: str, confidence: str, vt_result: dict | None) -> tuple[str, str]:
    """VirusTotal is real vendor ground truth, not our own model - a
    malicious verdict from even one vendor is treated as an override, not
    just a tiebreak, and can upgrade any label to "phishing" (but never
    downgrades an existing "phishing" - our own concrete findings, like a
    password field posting externally, don't stop mattering just because
    VirusTotal hasn't caught up yet). A clean VirusTotal report is weaker
    evidence (many fresh phishing pages aren't indexed yet either), so it
    only breaks an "uncertain" tie, the same role domain age plays."""
    if not vt_result or vt_result.get("stats") is None:
        return label, confidence
    stats = vt_result["stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious >= 1:
        vt_note = f"VirusTotal: {malicious} security vendor(s) flag this URL as malicious"
        if label == "phishing":
            return label, f"{confidence}; {vt_note}"
        return "phishing", vt_note
    if label == "uncertain" and malicious == 0 and suspicious == 0:
        return "benign", "signals disagree, but VirusTotal shows no detections across security vendors"
    return label, confidence


def combine_verdicts(
    heuristic: dict,
    ml: dict | None,
    domain_age: dict | None = None,
    vt_result: dict | None = None,
) -> dict:
    """heuristic: web_analysis.score_phishing()'s return value.
    ml: classifier.classify_webpage()'s return value, or None if the MLOps
    extras/trained model aren't available - degrades to heuristic-only.
    domain_age: domain_age.lookup_domain_age()'s return value, used only to
    break an "uncertain" tie (see _domain_age_tiebreak).
    vt_result: virustotal.check_url()'s return value, used as an override
    toward "phishing" and otherwise as a tiebreak (see _apply_virustotal)."""
    if ml is None:
        label = "phishing" if heuristic["level"] in ("medium", "high") else "benign"
        label, confidence = _apply_virustotal(
            label, "heuristic-only (ML classifier unavailable)", vt_result
        )
        return {
            "label": label,
            "confidence": confidence,
            "agreement": None,
            "heuristic": heuristic,
            "ml": None,
            "domain_age": domain_age,
            "virustotal": vt_result,
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

    label, confidence = _apply_virustotal(label, confidence, vt_result)

    return {
        "label": label,
        "confidence": confidence,
        "agreement": agreement,
        "heuristic": heuristic,
        "ml": ml,
        "domain_age": domain_age,
        "virustotal": vt_result,
    }
