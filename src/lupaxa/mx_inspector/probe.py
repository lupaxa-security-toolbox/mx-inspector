"""Optional SMTP banner and EHLO fingerprint of MX hosts."""

from __future__ import annotations

import socket
from collections.abc import Sequence
from dataclasses import dataclass

from .mx import MxHost

DEFAULT_PORT = 25
DEFAULT_TIMEOUT = 5.0
_EHLO_NAME = "mx-inspector.invalid"
_RECV_SIZE = 4096

_SOFTWARE = (
    ("postfix", "Postfix"),
    ("exim", "Exim"),
    ("microsoft", "Microsoft"),
    ("exchange", "Microsoft Exchange"),
    ("outlook.com", "Microsoft 365"),
    ("office365", "Microsoft 365"),
    ("gmail", "Google"),
    ("google", "Google"),
    ("proofpoint", "Proofpoint"),
    ("pphosted", "Proofpoint"),
    ("mimecast", "Mimecast"),
    ("barracuda", "Barracuda"),
    ("cisco", "Cisco"),
    ("ironport", "Cisco IronPort"),
    ("sophos", "Sophos"),
    ("fortinet", "Fortinet"),
    ("messagelabs", "Symantec MessageLabs"),
    ("symantec", "Symantec"),
    ("zimbra", "Zimbra"),
    ("icewarp", "IceWarp"),
    ("haraka", "Haraka"),
    ("opensmtpd", "OpenSMTPD"),
    ("sendmail", "Sendmail"),
    ("amazon", "Amazon SES"),
    ("amazonaws", "Amazon SES"),
    ("mailgun", "Mailgun"),
    ("sendgrid", "SendGrid"),
    ("zoho", "Zoho"),
    ("protonmail", "Proton Mail"),
    ("yahoo", "Yahoo"),
)


@dataclass(frozen=True)
class SmtpProbe:
    """Result of one SMTP banner / EHLO conversation."""

    host: str
    port: int
    banner: str | None
    software: str | None
    capabilities: tuple[str, ...]
    error: str | None


def fingerprint_banner(banner: str) -> str | None:
    """Map a 220 greeting to a known mail product, if the text is distinctive."""
    lowered = banner.lower()
    for needle, name in _SOFTWARE:
        if needle in lowered:
            return name
    return None


def _recv_reply(sock: socket.socket) -> str:
    chunks: list[bytes] = []
    while True:
        piece = sock.recv(_RECV_SIZE)
        if not piece:
            break
        chunks.append(piece)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        if _reply_complete(text):
            return text.replace("\r\n", "\n").strip()
    return b"".join(chunks).decode("utf-8", errors="replace").replace("\r\n", "\n").strip()


def _reply_complete(text: str) -> bool:
    lines = [line for line in text.replace("\r\n", "\n").split("\n") if line]
    if not lines:
        return False
    last = lines[-1]
    return len(last) >= 4 and last[3] == " " and last[:3].isdigit()


def _ehlo_capabilities(reply: str) -> tuple[str, ...]:
    caps: list[str] = []
    for line in reply.replace("\r\n", "\n").split("\n"):
        if len(line) < 4 or not line[:3].isdigit():
            continue
        payload = line[4:].strip()
        if not payload:
            continue
        keyword = payload.split()[0].upper()
        if keyword in {"EHLO", "HELO"}:
            continue
        caps.append(payload)
    return tuple(caps)


def probe_smtp(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
) -> SmtpProbe:
    """Connect to ``host:port``, read the 220 banner, and send ``EHLO``.

    The session only greets the server and quits. It does not authenticate
    or submit mail.
    """
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = _recv_reply(sock)
        sock.sendall(f"EHLO {_EHLO_NAME}\r\n".encode("ascii"))
        ehlo = _recv_reply(sock)
        try:
            sock.sendall(b"QUIT\r\n")
            _recv_reply(sock)
        except OSError:
            pass
        return SmtpProbe(
            host=host,
            port=port,
            banner=banner or None,
            software=fingerprint_banner(banner) if banner else None,
            capabilities=_ehlo_capabilities(ehlo),
            error=None,
        )
    except OSError as exc:
        return SmtpProbe(
            host=host,
            port=port,
            banner=None,
            software=None,
            capabilities=(),
            error=str(exc) or exc.__class__.__name__,
        )
    finally:
        if sock is not None:
            sock.close()


def probe_mx_hosts(
    hosts: Sequence[MxHost],
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[SmtpProbe]:
    """Probe each MX host. An empty host list yields an empty result."""
    return [probe_smtp(host.exchange, port=port, timeout=timeout) for host in hosts]


def probe_payload(probes: Sequence[SmtpProbe]) -> list[dict[str, object]]:
    """JSON-ready probe rows."""
    return [
        {
            "host": item.host,
            "port": item.port,
            "banner": item.banner,
            "software": item.software,
            "capabilities": list(item.capabilities),
            "error": item.error,
        }
        for item in probes
    ]
