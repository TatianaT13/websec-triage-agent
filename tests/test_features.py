"""Tests for the numeric feature vector fed to the trained classifier -
checks that it stays aligned with FEATURE_NAMES and that known patterns
produce the expected signal, independently of the heuristic score."""
from websec_agent.features import FEATURE_NAMES, extract_features

from .fixtures import BENIGN_HTML, CREDENTIAL_PHISH_HTML, LOOKALIKE_SUBDOMAIN_HTML


def test_feature_keys_include_all_feature_names():
    # extract_features() also returns "heuristic_score" - not a classifier
    # input (not in FEATURE_NAMES), kept as an auxiliary value for
    # training/train_verdict_meta.py. FEATURE_NAMES must still be exactly
    # what gets fed to the classifier, so check containment, not equality.
    row = extract_features(BENIGN_HTML, "https://example.com")
    assert set(FEATURE_NAMES) <= set(row.keys())
    assert "heuristic_score" in row


def test_benign_page_has_no_password_or_brand_signal():
    row = extract_features(BENIGN_HTML, "https://example.com")
    assert row["num_forms"] == 0
    assert row["has_password_field"] == 0
    assert row["brand_in_title_mismatch"] == 0


def test_credential_phish_features():
    url = "https://totally-legit-mail.example/"
    row = extract_features(CREDENTIAL_PHISH_HTML, url)
    assert row["num_forms"] == 1
    assert row["has_password_field"] == 1
    assert row["has_external_password_action"] == 1
    assert row["urgency_word_count"] >= 1


def test_lookalike_subdomain_sets_brand_title_mismatch():
    url = "https://wetransfer-smoky.vercel.app/"
    row = extract_features(LOOKALIKE_SUBDOMAIN_HTML, url)
    assert row["brand_in_title_mismatch"] == 1
    assert row["favicon_is_external"] == 1


def test_values_are_numeric():
    row = extract_features(CREDENTIAL_PHISH_HTML, "https://example.com")
    for name in FEATURE_NAMES:
        assert isinstance(row[name], (int, float))
