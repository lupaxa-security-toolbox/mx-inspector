"""DMARC parse and lookup helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from lupaxa.mx_inspector.dmarc import (
    expand_policy,
    format_dmarc_table,
    lookup_dmarc,
    parse_dmarc_record,
    remove_prefix,
)
from lupaxa.mx_inspector.exceptions import DmarcLookupError
from lupaxa.mx_inspector.mx import MxHost
from lupaxa.mx_inspector.probe import SmtpProbe

SAMPLE_RECORD = (
    "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com,"
    "mailto:other@example.com; ruf=mailto:forensic@example.com; ri=86400; "
    "pct=100; adkim=r; aspf=s; fo=1"
)


def test_remove_prefix_strips_mailto_and_spaces_lists() -> None:
    assert (
        remove_prefix("mailto:a@example.com,mailto:b@example.com", "mailto:")
        == "a@example.com, b@example.com"
    )


def test_parse_dmarc_record() -> None:
    policy = parse_dmarc_record(SAMPLE_RECORD)
    assert policy["v"] == "DMARC1"
    assert policy["p"] == "reject"
    assert policy["sp"] == "quarantine"
    assert policy["rua"] == "dmarc@example.com, other@example.com"
    assert policy["ruf"] == "forensic@example.com"
    assert policy["ri"] == "86400"
    assert policy["pct"] == "100"
    assert policy["adkim"] == "r"
    assert policy["aspf"] == "s"
    assert policy["fo"] == "1"


def test_parse_dmarc_record_rejects_non_dmarc() -> None:
    with pytest.raises(DmarcLookupError, match="not a DMARC"):
        parse_dmarc_record("v=spf1 include:_spf.example.com ~all")


def test_lookup_dmarc_empty_domain() -> None:
    with pytest.raises(DmarcLookupError, match="empty domain"):
        lookup_dmarc("   ")


def test_lookup_dmarc_uses_resolve() -> None:
    rdata = MagicMock()
    rdata.strings = [b"v=DMARC1; p=none"]
    answers = [rdata]
    with patch("lupaxa.mx_inspector.dmarc.dns.resolver.resolve", return_value=answers) as mocked:
        policy = lookup_dmarc("example.com")
    mocked.assert_called_once_with("_dmarc.example.com", "TXT")
    assert policy["p"] == "none"


def test_lookup_dmarc_nxdomain() -> None:
    with (
        patch(
            "lupaxa.mx_inspector.dmarc.dns.resolver.resolve",
            side_effect=dns.resolver.NXDOMAIN(),
        ),
        pytest.raises(DmarcLookupError, match="does not exist"),
    ):
        lookup_dmarc("missing.example")


def test_lookup_dmarc_no_dmarc_txt() -> None:
    rdata = MagicMock()
    rdata.strings = [b"hello"]
    with (
        patch("lupaxa.mx_inspector.dmarc.dns.resolver.resolve", return_value=[rdata]),
        pytest.raises(DmarcLookupError, match="No DMARC TXT record"),
    ):
        lookup_dmarc("example.com")


def test_format_dmarc_table_includes_known_tags() -> None:
    table = format_dmarc_table("example.com", parse_dmarc_record(SAMPLE_RECORD))
    assert "Results for: example.com" in table
    assert "DMARC policy" in table
    assert "reject" in table
    assert "86400 seconds" in table
    assert "100%" in table


def test_format_dmarc_table_keeps_missing_known_fields() -> None:
    table = format_dmarc_table("example.com", {"v": "DMARC1", "p": "none"})
    assert "Subdomain policy" in table
    assert "Forensic report addresses" in table
    assert "DKIM alignment mode" in table
    assert table.count("missing") >= 1


def test_format_dmarc_table_decodes_alignment_and_failure_options() -> None:
    table = format_dmarc_table(
        "example.com",
        {"p": "reject", "adkim": "r", "aspf": "s", "fo": "1:d"},
    )
    assert "relaxed (r)" in table
    assert "strict (s)" in table
    assert "any mechanism fails" in table
    assert "DKIM failures" in table


def test_expand_policy_fills_missing_known_tags() -> None:
    expanded = expand_policy({"p": "none", "extra": "keep"})
    assert expanded["p"] == "none"
    assert expanded["sp"] is None
    assert expanded["rua"] is None
    assert expanded["extra"] == "keep"


def test_format_dmarc_table_lists_mx_servers() -> None:
    table = format_dmarc_table(
        "example.com",
        {"p": "none"},
        mx_hosts=[
            MxHost(priority=10, exchange="mail.example.com"),
            MxHost(priority=20, exchange="backup.example.com"),
        ],
    )
    assert "MX servers" in table
    assert "mail.example.com (Priority: 10)" in table
    assert "backup.example.com (Priority: 20)" in table
    assert table.index("MX servers") < table.index("DMARC policy")


def test_format_dmarc_table_lists_spf_and_posture() -> None:
    from lupaxa.mx_inspector.score import score_posture

    posture = score_posture(
        {"p": "reject"},
        mx_hosts=[MxHost(priority=10, exchange="mail.example.com")],
        spf_records=["v=spf1 -all"],
    )
    table = format_dmarc_table(
        "example.com",
        {"p": "reject"},
        mx_hosts=[MxHost(priority=10, exchange="mail.example.com")],
        spf_records=["v=spf1 -all"],
        posture=posture,
    )
    assert "MX servers" in table
    assert table.index("MX servers") < table.index("SPF")
    assert table.index("SPF") < table.index("DMARC policy")
    assert table.index("DMARC policy") < table.index("Posture score")
    assert f"{posture.value} ({posture.grade})" in table
    assert "v=spf1 -all" in table
    assert "Posture notes" in table
    lines = table.splitlines()
    score_line = next(index for index, line in enumerate(lines) if "Posture score" in line)
    assert lines[score_line - 1].startswith("+")
    assert "-" in lines[score_line - 1]


def test_format_dmarc_table_colors_names_values_and_score() -> None:
    from colored import Fore, Style

    from lupaxa.mx_inspector.score import PostureScore

    table = format_dmarc_table(
        "example.com",
        {"p": "none"},
        mx_hosts=[],
        posture=PostureScore(value=12, grade="open", reasons=("No SPF record",)),
        color=True,
    )
    assert f"{Fore.cyan}Results for:{Style.reset}" in table
    assert f"{Style.bold}{Fore.white}example.com{Style.reset}" in table
    assert f"{Fore.cyan}MX servers{Style.reset}" in table
    assert f"{Fore.dark_gray}missing{Style.reset}" in table
    assert f"{Fore.green}none" in table or "none (monitor" in table
    assert f"{Fore.red}12 (open){Style.reset}" in table
    assert f"{Fore.green}No SPF record{Style.reset}" in table


def test_format_dmarc_table_splits_comma_separated_addresses() -> None:
    table = format_dmarc_table(
        "example.com",
        {"rua": "dmarc@example.com, other@example.com"},
    )
    assert "dmarc@example.com" in table
    assert "other@example.com" in table
    assert "dmarc@example.com, other@example.com" not in table


def test_format_dmarc_table_marks_missing_mx_servers() -> None:
    table = format_dmarc_table("example.com", {"p": "none"}, mx_hosts=[])
    assert "MX servers" in table
    assert "missing" in table


def test_format_dmarc_table_blank_exchange_is_missing() -> None:
    table = format_dmarc_table(
        "example.com",
        {"p": "none"},
        mx_hosts=[MxHost(priority=0, exchange="")],
    )
    assert "Priority: 0" not in table
    assert "missing" in table


def test_format_dmarc_table_lists_smtp_probe() -> None:
    table = format_dmarc_table(
        "example.com",
        {"p": "none"},
        mx_hosts=[MxHost(priority=10, exchange="mail.example.com")],
        smtp_probes=[
            SmtpProbe(
                host="mail.example.com",
                port=25,
                banner="220 mail.example.com ESMTP Postfix",
                software="Postfix",
                capabilities=("STARTTLS", "PIPELINING"),
                error=None,
            )
        ],
    )
    assert "Mail software (mail.example.com)" in table
    assert "Postfix" in table
    assert "SMTP banner (mail.example.com)" in table
    assert "STARTTLS" in table


def test_format_dmarc_table_marks_missing_probe() -> None:
    table = format_dmarc_table(
        "example.com",
        {"p": "none"},
        mx_hosts=[],
        smtp_probes=[],
    )
    assert "Mail software" in table
    assert "SMTP banner" in table
