"""Tests for independent DKIM signature verification. Uses a real
sign/verify/tamper roundtrip (a message signed with a throwaway RSA
keypair, with the DNS lookup swapped for a fake one serving that
keypair's public key) rather than mocking the result - confirms the
underlying crypto actually works, not just that our wrapper calls the
right function.

dnsfunc is passed explicitly rather than monkeypatching dkim.get_txt -
see dkim_verify.verify_dkim_signature's docstring for why that doesn't
work (dkimpy binds its own default dnsfunc at import time)."""
import base64

import pytest

pytest.importorskip("dkim", reason="requires requirements-email-verify.txt")

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from websec_agent import dkim_verify as dv


@pytest.fixture(scope="module")
def signed_message():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b64 = base64.b64encode(pub_der).decode()

    message = b"From: sender@example-test.com\r\nTo: victim@example.com\r\nSubject: Test\r\n\r\nHello world\r\n"
    signed_header = dkim.sign(message, selector=b"sel1", domain=b"example-test.com", privkey=priv_pem)

    def fake_dns(name, timeout=5):
        return f"v=DKIM1; k=rsa; p={pub_b64}".encode()

    return signed_header + message, fake_dns


def test_valid_signature_verifies_true(signed_message):
    full_message, fake_dns = signed_message
    result = dv.verify_dkim_signature(full_message, dnsfunc=fake_dns)
    assert result["verified"] is True
    assert result["signing_domain"] == "example-test.com"


def test_tampered_body_fails_verification(signed_message):
    full_message, fake_dns = signed_message
    tampered = full_message.replace(b"Hello world", b"Hello wOrld")
    result = dv.verify_dkim_signature(tampered, dnsfunc=fake_dns)
    assert result["verified"] is False
    assert result["signing_domain"] == "example-test.com"


def test_no_dkim_signature_header_is_verified_none():
    message = b"From: a@b.com\r\nSubject: x\r\n\r\nbody\r\n"
    result = dv.verify_dkim_signature(message)
    assert result["verified"] is None
    assert result["signing_domain"] is None


# --- apply_dkim_verification -------------------------------------------

from websec_agent import offline_content as oc  # noqa: E402

BENIGN_VERDICT = {"label": "benign", "confidence": "both signals agree"}
PHISHING_VERDICT = {"label": "phishing", "confidence": "both signals agree"}


def test_apply_dkim_verification_pushes_benign_to_phishing_on_invalid_signature():
    result = oc.apply_dkim_verification(
        BENIGN_VERDICT, {"verified": False, "signing_domain": "evil.example", "detail": "x"}
    )
    assert result["label"] == "phishing"
    assert "evil.example" in result["confidence"]
    assert "independently verified" in result["confidence"]


def test_apply_dkim_verification_no_change_when_verified_true():
    result = oc.apply_dkim_verification(
        BENIGN_VERDICT, {"verified": True, "signing_domain": "example.com", "detail": "x"}
    )
    assert result == BENIGN_VERDICT


def test_apply_dkim_verification_no_change_when_no_signature():
    result = oc.apply_dkim_verification(BENIGN_VERDICT, {"verified": None, "signing_domain": None, "detail": "x"})
    assert result == BENIGN_VERDICT


def test_apply_dkim_verification_visible_when_already_phishing():
    result = oc.apply_dkim_verification(
        PHISHING_VERDICT, {"verified": False, "signing_domain": "evil.example", "detail": "x"}
    )
    assert result["label"] == "phishing"
    assert "both signals agree" in result["confidence"]
    assert "independently verified" in result["confidence"]


def test_apply_dkim_verification_does_not_mutate_input():
    original = dict(BENIGN_VERDICT)
    oc.apply_dkim_verification(BENIGN_VERDICT, {"verified": False, "signing_domain": "x", "detail": "x"})
    assert BENIGN_VERDICT == original


# --- DKIM/DMARC identifier alignment -------------------------------------
# A prior version of apply_dkim_verification only checked whether the
# signature validated, never whether it was signed by the domain it claims
# to be from - a message can carry a perfectly valid signature from an
# unrelated domain (any legitimate signing identity an attacker has access
# to) while the From: header claims to be a different brand entirely.


def test_dkim_domain_aligned_exact_match():
    assert oc.dkim_domain_aligned("paypal.com", "paypal.com") is True


def test_dkim_domain_aligned_relaxed_subdomain():
    # DMARC's default "relaxed" alignment: a subdomain of the same
    # organizational domain still counts as aligned.
    assert oc.dkim_domain_aligned("mail.paypal.com", "paypal.com") is True
    assert oc.dkim_domain_aligned("paypal.com", "secure.paypal.com") is True


def test_dkim_domain_not_aligned_unrelated_domain():
    assert oc.dkim_domain_aligned("some-saas-mailer.com", "paypal.com") is False


def test_dkim_domain_aligned_true_when_either_domain_missing():
    # Nothing to check without both domains - must not false-positive.
    assert oc.dkim_domain_aligned(None, "paypal.com") is True
    assert oc.dkim_domain_aligned("paypal.com", "") is True


def test_apply_dkim_verification_flags_valid_signature_from_unaligned_domain():
    result = oc.apply_dkim_verification(
        BENIGN_VERDICT,
        {"verified": True, "signing_domain": "some-saas-mailer.com", "detail": "x"},
        from_domain="paypal.com",
    )
    assert result["label"] == "phishing"
    assert "some-saas-mailer.com" in result["confidence"]
    assert "paypal.com" in result["confidence"]
    assert "misalignment" in result["confidence"]


def test_apply_dkim_verification_no_change_when_verified_true_and_aligned():
    result = oc.apply_dkim_verification(
        BENIGN_VERDICT,
        {"verified": True, "signing_domain": "paypal.com", "detail": "x"},
        from_domain="paypal.com",
    )
    assert result == BENIGN_VERDICT


def test_apply_dkim_verification_no_change_when_from_domain_not_provided():
    # Backward-compatible default: without from_domain, can't check
    # alignment, so a valid signature is neither flagged nor assumed safe.
    result = oc.apply_dkim_verification(
        BENIGN_VERDICT, {"verified": True, "signing_domain": "some-saas-mailer.com", "detail": "x"}
    )
    assert result == BENIGN_VERDICT
