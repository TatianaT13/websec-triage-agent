"""Tests for combining the heuristic score and the ML classifier's
probability into one verdict. Uses hand-built heuristic/ml dicts (not the
real trained model) so these stay deterministic across retrains."""
from websec_agent.verdict import combine_verdicts

LOW = {"score": 0, "level": "low", "reasons": []}
MEDIUM = {"score": 5, "level": "medium", "reasons": ["some reason"]}
HIGH = {"score": 10, "level": "high", "reasons": ["some reason"]}


def _ml(prob):
    return {"label": "phishing" if prob >= 0.5 else "benign", "phishing_probability": prob, "model_version": "x"}


def _vt(malicious=0, suspicious=0, source="cached"):
    return {"source": source, "url": "https://example.com", "stats": {"malicious": malicious, "suspicious": suspicious, "harmless": 60}}


def test_no_ml_falls_back_to_heuristic_only():
    result = combine_verdicts(LOW, None)
    assert result["label"] == "benign"
    assert result["ml"] is None
    assert result["agreement"] is None

    result = combine_verdicts(HIGH, None)
    assert result["label"] == "phishing"


def test_both_signals_agree_on_benign():
    result = combine_verdicts(LOW, _ml(0.1))
    assert result["label"] == "benign"
    assert result["agreement"] is True


def test_both_signals_agree_on_phishing():
    result = combine_verdicts(HIGH, _ml(0.9))
    assert result["label"] == "phishing"
    assert result["agreement"] is True


def test_heuristic_high_overrides_low_ml_probability():
    # heuristic found something concrete (e.g. password field to an
    # external domain) - don't let a so-so ML score override that.
    result = combine_verdicts(HIGH, _ml(0.4))
    assert result["label"] == "phishing"


def test_high_ml_probability_overrides_low_heuristic():
    result = combine_verdicts(LOW, _ml(0.9))
    assert result["label"] == "phishing"


def test_disagreeing_signals_are_uncertain():
    # heuristic says "not phishing-ish", ML says borderline phishing -
    # neither crosses the override threshold, so don't force a label.
    result = combine_verdicts(LOW, _ml(0.5))
    assert result["label"] == "uncertain"
    assert result["agreement"] is False
    assert "disagree" in result["confidence"]


def test_medium_heuristic_with_weak_ml_is_uncertain():
    result = combine_verdicts(MEDIUM, _ml(0.5))
    assert result["label"] == "uncertain"


def test_young_domain_breaks_an_uncertain_tie_toward_phishing():
    result = combine_verdicts(LOW, _ml(0.5), domain_age={"age_days": 5, "is_platform_hosted": False})
    assert result["label"] == "phishing"
    assert "5 days old" in result["confidence"]


def test_established_domain_breaks_an_uncertain_tie_toward_benign():
    result = combine_verdicts(LOW, _ml(0.5), domain_age={"age_days": 3000, "is_platform_hosted": False})
    assert result["label"] == "benign"


def test_mid_age_domain_does_not_break_the_tie():
    result = combine_verdicts(LOW, _ml(0.5), domain_age={"age_days": 180, "is_platform_hosted": False})
    assert result["label"] == "uncertain"


def test_unknown_domain_age_does_not_break_the_tie():
    result = combine_verdicts(LOW, _ml(0.5), domain_age={"age_days": None, "is_platform_hosted": True})
    assert result["label"] == "uncertain"


def test_domain_age_does_not_override_a_clear_signal():
    # a decisive heuristic/ML signal shouldn't be second-guessed just
    # because the domain happens to be old or young.
    result = combine_verdicts(HIGH, _ml(0.9), domain_age={"age_days": 3000, "is_platform_hosted": False})
    assert result["label"] == "phishing"


def test_virustotal_malicious_upgrades_benign_to_phishing():
    # real vendor ground truth - overrides, not just a tiebreak.
    result = combine_verdicts(LOW, _ml(0.1), vt_result=_vt(malicious=2))
    assert result["label"] == "phishing"
    assert "VirusTotal" in result["confidence"]


def test_virustotal_malicious_upgrades_uncertain_to_phishing():
    result = combine_verdicts(LOW, _ml(0.5), vt_result=_vt(malicious=1))
    assert result["label"] == "phishing"


def test_virustotal_clean_breaks_an_uncertain_tie_toward_benign():
    result = combine_verdicts(LOW, _ml(0.5), vt_result=_vt(malicious=0, suspicious=0))
    assert result["label"] == "benign"


def test_virustotal_suspicious_only_does_not_force_benign():
    result = combine_verdicts(LOW, _ml(0.5), vt_result=_vt(malicious=0, suspicious=1))
    assert result["label"] == "uncertain"


def test_virustotal_does_not_downgrade_an_existing_phishing_label():
    # our own concrete findings don't stop mattering just because VT is clean.
    result = combine_verdicts(HIGH, _ml(0.9), vt_result=_vt(malicious=0, suspicious=0))
    assert result["label"] == "phishing"


def test_virustotal_corroboration_is_visible_even_when_already_phishing():
    # VT agreeing with an already-"phishing" verdict is still worth
    # surfacing, not silently dropped just because the label didn't change.
    result = combine_verdicts(HIGH, _ml(0.9), vt_result=_vt(malicious=13))
    assert result["label"] == "phishing"
    assert "VirusTotal" in result["confidence"]


def test_virustotal_timeout_or_missing_stats_is_ignored():
    result = combine_verdicts(LOW, _ml(0.5), vt_result={"source": "timeout", "stats": None, "url": "x"})
    assert result["label"] == "uncertain"


def test_virustotal_applies_even_without_ml():
    result = combine_verdicts(LOW, None, vt_result=_vt(malicious=3))
    assert result["label"] == "phishing"
    assert "VirusTotal" in result["confidence"]
