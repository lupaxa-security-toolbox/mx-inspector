"""SPF TXT lookup helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from lupaxa.mx_inspector.exceptions import SpfLookupError
from lupaxa.mx_inspector.spf import lookup_spf, parse_spf_all


def _txt(payload: str) -> MagicMock:
    rdata = MagicMock()
    rdata.strings = [payload.encode("utf-8")]
    rdata.to_text.return_value = f'"{payload}"'
    return rdata


def test_lookup_spf_empty_domain() -> None:
    with pytest.raises(SpfLookupError, match="empty domain"):
        lookup_spf("  ")


def test_lookup_spf_no_answer_is_empty() -> None:
    with patch(
        "lupaxa.mx_inspector.spf.dns.resolver.resolve",
        side_effect=dns.resolver.NoAnswer(),
    ):
        assert lookup_spf("example.com") == []


def test_lookup_spf_returns_spf_txt_only() -> None:
    answers = [
        _txt("google-site-verification=abc"),
        _txt("v=spf1 include:_spf.google.com -all"),
    ]
    with patch("lupaxa.mx_inspector.spf.dns.resolver.resolve", return_value=answers):
        records = lookup_spf("example.com")
    assert records == ["v=spf1 include:_spf.google.com -all"]


def test_parse_spf_all() -> None:
    assert parse_spf_all("v=spf1 -all") == "-"
    assert parse_spf_all("v=spf1 ~all") == "~"
    assert parse_spf_all("v=spf1 +all") == "+"
    assert parse_spf_all("v=spf1 ?all") == "?"
    assert parse_spf_all("v=spf1 mx") is None
    assert parse_spf_all("v=spf1 +all -all") == "-"
