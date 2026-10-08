"""Tests for BIMI DNS lookup. Real parsing logic tested against actual
record formats pulled from real domains (confirmed via `dig` before
writing these fixtures - see commit message), not invented ones -
notably eBay's record has no spaces after semicolons, a real format
variation a naive parser could miss."""
import pytest

pytest.importorskip("dns", reason="requires requirements-email-verify.txt")

from unittest.mock import MagicMock, patch

from websec_agent import bimi_lookup as bl


def _fake_txt_answer(raw: str):
    rdata = MagicMock()
    rdata.strings = [raw.encode()]
    return [rdata]


def test_empty_domain_is_not_present():
    assert bl.lookup_bimi("") == {"present": False, "logo_url": None, "has_vmc": False}


def test_parses_a_real_world_record_with_spaces():
    # Pulled from linkedin.com's actual default._bimi record.
    raw = (
        "v=BIMI1; l=https://media.licdn.com/media/AAYQAQQhAAgAAQAAAAAAABrLiVuNIZ3fRKGlFSn4hGZubg.svg; "
        "a=https://media.licdn.com/media/AAYABAQhAAgAAQAAAAAAAYFI0DP_wvHFSv6mYduMZuEwSA.pem;"
    )
    with patch("dns.resolver.resolve", return_value=_fake_txt_answer(raw)):
        result = bl.lookup_bimi("linkedin.com")
    assert result["present"] is True
    assert result["logo_url"].endswith(".svg")
    assert result["has_vmc"] is True


def test_parses_a_real_world_record_with_no_spaces():
    # Pulled from ebay.com's actual default._bimi record - no spaces
    # after semicolons, a real format variation a naive parser could miss.
    raw = (
        "v=BIMI1;l=https://vmc.digicert.com/9e57aa28-3230-463f-b92e-ba8cd5612c17.svg;"
        "a=https://vmc.digicert.com/9e57aa28-3230-463f-b92e-ba8cd5612c17.pem"
    )
    with patch("dns.resolver.resolve", return_value=_fake_txt_answer(raw)):
        result = bl.lookup_bimi("ebay.com")
    assert result["present"] is True
    assert result["has_vmc"] is True


def test_parses_a_record_without_vmc():
    # Pulled from mailchimp.com's actual record - no "a=" tag at all.
    raw = (
        "v=BIMI1; l=https://eep.io/images/yzco4xsimv0y/kXdRxrKY0FSlPA5hyroFP/"
        "1c9b0474c45c40c75869ca2dd1f9d2df/MC-Freddie-Cavendish-square_tiny_ps.svg;"
    )
    with patch("dns.resolver.resolve", return_value=_fake_txt_answer(raw)):
        result = bl.lookup_bimi("mailchimp.com")
    assert result["present"] is True
    assert result["has_vmc"] is False


def test_no_record_returns_not_present():
    with patch("dns.resolver.resolve", side_effect=Exception("NXDOMAIN")):
        result = bl.lookup_bimi("example.com")
    assert result == {"present": False, "logo_url": None, "has_vmc": False}
