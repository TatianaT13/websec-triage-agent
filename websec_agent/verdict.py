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


def combine_verdicts(heuristic: dict, ml: dict | None) -> dict:
    """heuristic: web_analysis.score_phishing()'s return value.
    ml: classifier.classify_webpage()'s return value, or None if the MLOps
    extras/trained model aren't available - degrades to heuristic-only."""
    if ml is None:
        label = "phishing" if heuristic["level"] in ("medium", "high") else "benign"
        return {
            "label": label,
            "confidence": "heuristic-only (ML classifier unavailable)",
            "agreement": None,
            "heuristic": heuristic,
            "ml": None,
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

    return {
        "label": label,
        "confidence": "both signals agree" if agreement else "signals disagree - review manually",
        "agreement": agreement,
        "heuristic": heuristic,
        "ml": ml,
    }
