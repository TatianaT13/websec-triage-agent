"""Combine the hand-tuned heuristic score, the trained classifier's
probability, and domain age into one coherent verdict, instead of
leaving the agent (or the user) to reconcile several opinions by hand.

Two ways this combination happens, in order of preference:
1. A learned meta-model (training/train_verdict_meta.py) if one has been
   trained and actually promoted (logistic regression or gradient
   boosting, whichever won the honest comparison against the baseline -
   see models/verdict_meta_model.meta.json for which) over
   [heuristic_score, ml_probability, domain_age_days, domain_age_unknown]
   that replaces the hand-picked thresholds below with learned weights.
2. The hand-coded thresholds in this file, when the meta-model isn't
   available (sklearn/joblib not installed, or not yet trained) - this
   path is what ships before any training has happened, so it has to
   work standalone, not just as documentation of what the meta-model
   learned to approximate.

Erring toward "phishing" when signals disagree is a deliberate
security-triage choice either way: missing a real phishing page costs
more than a false alarm that a human then dismisses.
"""
from __future__ import annotations

from pathlib import Path

PHISHING_PROB_HIGH = 0.75
PHISHING_PROB_LOW = 0.25
YOUNG_DOMAIN_DAYS = 30
ESTABLISHED_DOMAIN_DAYS = 365

_META_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "verdict_meta_model.joblib"
_META_FEATURE_NAMES = ["heuristic_score", "ml_probability", "domain_age_days", "domain_age_unknown"]
_meta_bundle = None
_meta_unavailable = False


def _load_meta_model():
    global _meta_bundle, _meta_unavailable
    if _meta_bundle is None and not _meta_unavailable:
        if not _META_MODEL_PATH.exists():
            _meta_unavailable = True
        else:
            try:
                import joblib

                _meta_bundle = joblib.load(_META_MODEL_PATH)
            except ImportError:
                _meta_unavailable = True
    return _meta_bundle


def _meta_model_probability(heuristic: dict, ml: dict | None, domain_age: dict | None) -> float | None:
    """None when the meta-model isn't available, or when ml is None (the
    meta-model was trained with an ML probability as one of its inputs -
    without one there's nothing meaningful to feed it)."""
    bundle = _load_meta_model()
    if bundle is None or ml is None:
        return None

    import pandas as pd

    if domain_age and domain_age.get("age_days") is not None:
        age_days, age_unknown = domain_age["age_days"], 0
    else:
        age_days, age_unknown = -1, 1

    row = [[heuristic["score"], ml["phishing_probability"], age_days, age_unknown]]
    X = pd.DataFrame(row, columns=_META_FEATURE_NAMES)
    X_scaled = bundle["scaler"].transform(X)
    return float(bundle["model"].predict_proba(X_scaled)[0][1])


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
            "meta_probability": None,
        }

    ml_prob = ml["phishing_probability"]
    ml_says_phish = ml_prob >= 0.5
    heuristic_says_phish = heuristic["level"] in ("medium", "high")
    agreement = ml_says_phish == heuristic_says_phish

    meta_prob = _meta_model_probability(heuristic, ml, domain_age)
    if meta_prob is not None:
        # The meta-model already takes domain_age_days as one of its
        # inputs, so the separate tiebreak below would be redundant (and
        # could fight a signal the model already weighed in) - skip it.
        if meta_prob >= PHISHING_PROB_HIGH:
            label = "phishing"
        elif meta_prob <= PHISHING_PROB_LOW:
            label = "benign"
        else:
            label = "uncertain"
        agree_note = "both signals agree" if agreement else "signals disagree"
        confidence = f"learned meta-model (p={meta_prob:.2f}); {agree_note}"
    else:
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
        "meta_probability": meta_prob,
    }
