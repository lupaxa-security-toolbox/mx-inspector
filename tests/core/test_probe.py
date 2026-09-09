"""SMTP banner fingerprint helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from lupaxa.mx_inspector.probe import fingerprint_banner, probe_smtp


def test_fingerprint_banner_postfix() -> None:
    assert fingerprint_banner("220 mail.example.com ESMTP Postfix") == "Postfix"


def test_fingerprint_banner_exim() -> None:
    assert fingerprint_banner("220 mx.example.com ESMTP Exim 4.96") == "Exim"


def test_fingerprint_banner_unknown() -> None:
    assert fingerprint_banner("220 mail.example.com ESMTP") is None


def test_probe_smtp_reads_banner_and_ehlo() -> None:
    sock = MagicMock()
    sock.recv.side_effect = [
        b"220 mail.example.com ESMTP Postfix\r\n",
        b"250-mail.example.com\r\n250-PIPELINING\r\n250 STARTTLS\r\n",
        b"221 2.0.0 Bye\r\n",
    ]
    with patch("lupaxa.mx_inspector.probe.socket.create_connection", return_value=sock):
        result = probe_smtp("mail.example.com", timeout=1)
    assert result.host == "mail.example.com"
    assert result.port == 25
    assert result.software == "Postfix"
    assert "220 mail.example.com ESMTP Postfix" in (result.banner or "")
    assert "STARTTLS" in result.capabilities
    assert result.error is None
    sock.sendall.assert_any_call(b"EHLO mx-inspector.invalid\r\n")
    sock.sendall.assert_any_call(b"QUIT\r\n")
    sock.close.assert_called()


def test_probe_smtp_records_connect_error() -> None:
    with patch(
        "lupaxa.mx_inspector.probe.socket.create_connection",
        side_effect=OSError("timed out"),
    ):
        result = probe_smtp("mail.example.com", timeout=1)
    assert result.software is None
    assert result.banner is None
    assert result.error == "timed out"
