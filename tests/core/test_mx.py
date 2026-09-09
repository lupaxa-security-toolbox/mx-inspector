"""MX record lookup helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from lupaxa.mx_inspector.exceptions import MxLookupError
from lupaxa.mx_inspector.mx import lookup_mx


def _mx_rdata(priority: int, exchange: str) -> MagicMock:
    rdata = MagicMock()
    rdata.preference = priority
    rdata.exchange = exchange
    return rdata


def test_lookup_mx_empty_domain() -> None:
    with pytest.raises(MxLookupError, match="empty domain"):
        lookup_mx("   ")


def test_lookup_mx_returns_hosts_sorted_by_priority() -> None:
    answers = [
        _mx_rdata(20, "backup.example.com."),
        _mx_rdata(10, "mail.example.com."),
    ]
    with patch("lupaxa.mx_inspector.mx.dns.resolver.resolve", return_value=answers) as mocked:
        hosts = lookup_mx("example.com")
    mocked.assert_called_once_with("example.com", "MX")
    assert [(host.priority, host.exchange) for host in hosts] == [
        (10, "mail.example.com"),
        (20, "backup.example.com"),
    ]


def test_lookup_mx_null_mx_is_empty() -> None:
    answers = [_mx_rdata(0, ".")]
    with patch("lupaxa.mx_inspector.mx.dns.resolver.resolve", return_value=answers):
        assert lookup_mx("example.com") == []


def test_lookup_mx_skips_blank_exchanges() -> None:
    answers = [_mx_rdata(0, "."), _mx_rdata(10, "mail.example.com.")]
    with patch("lupaxa.mx_inspector.mx.dns.resolver.resolve", return_value=answers):
        hosts = lookup_mx("example.com")
    assert [(host.priority, host.exchange) for host in hosts] == [
        (10, "mail.example.com"),
    ]


def test_lookup_mx_no_answer_is_empty() -> None:
    with patch(
        "lupaxa.mx_inspector.mx.dns.resolver.resolve",
        side_effect=dns.resolver.NoAnswer(),
    ):
        assert lookup_mx("example.com") == []


def test_lookup_mx_nxdomain() -> None:
    with (
        patch(
            "lupaxa.mx_inspector.mx.dns.resolver.resolve",
            side_effect=dns.resolver.NXDOMAIN(),
        ),
        pytest.raises(MxLookupError, match="does not exist"),
    ):
        lookup_mx("missing.example")
