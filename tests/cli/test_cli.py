"""CLI entrypoint."""

from __future__ import annotations

import json
from unittest.mock import patch

from lupaxa.mx_inspector.cli import main
from lupaxa.mx_inspector.exceptions import DmarcLookupError
from lupaxa.mx_inspector.version import get_version


def test_help_exits_zero() -> None:
    assert main(["--help"]) == 0


def test_help_includes_no_color(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["--help"]) == 0
    assert "--no-color" in capsys.readouterr().out


def test_no_color_flag_disables_table_colour(capsys, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    with (
        patch("lupaxa.mx_inspector.cli.lookup_dmarc", return_value={"p": "none"}),
        patch("lupaxa.mx_inspector.cli.lookup_mx", return_value=[]),
        patch("lupaxa.mx_inspector.cli.lookup_spf", return_value=[]),
    ):
        code = main(["example.com", "--no-color"])
    assert code == 0
    out = capsys.readouterr().out
    assert "\033[" not in out
    assert "Results for: example.com" in out


def test_version_flag(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["--version"]) == 0
    assert get_version() in capsys.readouterr().out


def test_table_output(capsys) -> None:  # type: ignore[no-untyped-def]
    with (
        patch("lupaxa.mx_inspector.cli.lookup_dmarc", return_value={"p": "none"}),
        patch("lupaxa.mx_inspector.cli.lookup_mx", return_value=[]),
        patch("lupaxa.mx_inspector.cli.lookup_spf", return_value=[]),
    ):
        code = main(["example.com"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Results for: example.com" in out
    assert "DMARC policy" in out
    assert "none" in out
    assert "MX servers" in out


def test_json_format(capsys) -> None:  # type: ignore[no-untyped-def]
    from lupaxa.mx_inspector.mx import MxHost

    with (
        patch("lupaxa.mx_inspector.cli.lookup_dmarc", return_value={"p": "reject"}),
        patch(
            "lupaxa.mx_inspector.cli.lookup_mx",
            return_value=[MxHost(priority=10, exchange="mail.example.com")],
        ),
        patch("lupaxa.mx_inspector.cli.lookup_spf", return_value=["v=spf1 -all"]),
    ):
        code = main(["example.com", "--format", "json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["domain"] == "example.com"
    assert payload[0]["policy"]["p"] == "reject"
    assert payload[0]["policy"]["sp"] is None
    assert payload[0]["mx"] == [{"priority": 10, "exchange": "mail.example.com"}]
    assert payload[0]["spf"] == ["v=spf1 -all"]
    assert payload[0]["spf_error"] is None
    assert payload[0]["score"]["grade"] in {
        "open",
        "monitoring",
        "enforcing",
        "locked down",
    }
    assert payload[0]["score"]["value"] >= 0
    assert payload[0]["error"] is None
    assert payload[0]["mx_error"] is None


def test_probe_flag_includes_fingerprint(capsys) -> None:  # type: ignore[no-untyped-def]
    from lupaxa.mx_inspector.mx import MxHost
    from lupaxa.mx_inspector.probe import SmtpProbe

    host = MxHost(priority=10, exchange="mail.example.com")
    probe = SmtpProbe(
        host="mail.example.com",
        port=25,
        banner="220 mail.example.com ESMTP Postfix",
        software="Postfix",
        capabilities=("STARTTLS",),
        error=None,
    )
    with (
        patch("lupaxa.mx_inspector.cli.lookup_dmarc", return_value={"p": "none"}),
        patch("lupaxa.mx_inspector.cli.lookup_mx", return_value=[host]),
        patch("lupaxa.mx_inspector.cli.lookup_spf", return_value=[]),
        patch("lupaxa.mx_inspector.cli.probe_mx_hosts", return_value=[probe]) as mocked,
    ):
        code = main(["example.com", "--probe", "--format", "json"])
    assert code == 0
    mocked.assert_called_once()
    assert mocked.call_args.kwargs["timeout"] == 5.0
    assert mocked.call_args.kwargs["port"] == 25
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["probe"][0]["software"] == "Postfix"


def test_timeout_flag_is_passed_to_probe() -> None:
    from lupaxa.mx_inspector.mx import MxHost

    host = MxHost(priority=10, exchange="mail.example.com")
    with (
        patch("lupaxa.mx_inspector.cli.lookup_dmarc", return_value={"p": "none"}),
        patch("lupaxa.mx_inspector.cli.lookup_mx", return_value=[host]),
        patch("lupaxa.mx_inspector.cli.lookup_spf", return_value=[]),
        patch("lupaxa.mx_inspector.cli.probe_mx_hosts", return_value=[]) as mocked,
    ):
        code = main(["example.com", "--probe", "--timeout", "2.5"])
    assert code == 0
    assert mocked.call_args.kwargs["timeout"] == 2.5


def test_timeout_must_be_positive() -> None:
    assert main(["example.com", "--timeout", "0"]) == 2
    assert main(["example.com", "--timeout", "-1"]) == 2


def test_port_flag_is_passed_to_probe() -> None:
    from lupaxa.mx_inspector.mx import MxHost

    host = MxHost(priority=10, exchange="mail.example.com")
    with (
        patch("lupaxa.mx_inspector.cli.lookup_dmarc", return_value={"p": "none"}),
        patch("lupaxa.mx_inspector.cli.lookup_mx", return_value=[host]),
        patch("lupaxa.mx_inspector.cli.lookup_spf", return_value=[]),
        patch("lupaxa.mx_inspector.cli.probe_mx_hosts", return_value=[]) as mocked,
    ):
        code = main(["example.com", "--probe", "--port", "587"])
    assert code == 0
    assert mocked.call_args.kwargs["port"] == 587


def test_port_must_be_valid() -> None:
    assert main(["example.com", "--port", "0"]) == 2
    assert main(["example.com", "--port", "65536"]) == 2
    assert main(["example.com", "--port", "-1"]) == 2


def test_lookup_error_is_nonzero(capsys) -> None:  # type: ignore[no-untyped-def]
    with (
        patch(
            "lupaxa.mx_inspector.cli.lookup_dmarc",
            side_effect=DmarcLookupError("No DMARC TXT record found for _dmarc.example.com"),
        ),
        patch("lupaxa.mx_inspector.cli.lookup_mx", return_value=[]),
        patch("lupaxa.mx_inspector.cli.lookup_spf", return_value=[]),
    ):
        code = main(["example.com"])
    assert code == 2
    assert "No DMARC TXT record" in capsys.readouterr().err
