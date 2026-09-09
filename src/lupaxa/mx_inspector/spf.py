"""Look up a domain's published SPF TXT record."""

from __future__ import annotations

import re

import dns.resolver
from dns.exception import DNSException

from .exceptions import SpfLookupError

_ALL = re.compile(r"(?P<qual>[+\-~?])?all\b", re.IGNORECASE)


def parse_spf_all(record: str) -> str | None:
    """Return the qualifier of the last ``all`` mechanism, if any.

    A bare ``all`` is treated as ``+`` (RFC 7208 default).
    """
    last: str | None = None
    for match in _ALL.finditer(record):
        last = match.group("qual") or "+"
    return last


def _txt_payload(rdata: object) -> str:
    strings = getattr(rdata, "strings", None)
    if strings:
        parts: list[str] = []
        for item in strings:
            if isinstance(item, bytes):
                parts.append(item.decode("utf-8", errors="replace"))
            else:
                parts.append(str(item))
        return "".join(parts).strip()
    to_text = getattr(rdata, "to_text", None)
    text = str(to_text()).strip() if callable(to_text) else str(rdata).strip()
    if text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    return text


def lookup_spf(domain: str) -> list[str]:
    """Query apex ``TXT`` records and return those that start with ``v=spf1``.

    An empty list means the name exists but published no SPF record.
    """
    name = domain.strip()
    if not name:
        raise SpfLookupError("empty domain")
    try:
        answers = dns.resolver.resolve(name, "TXT")
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN as exc:
        raise SpfLookupError(f"Domain '{name}' does not exist.") from exc
    except dns.resolver.Timeout as exc:
        raise SpfLookupError("DNS query timeout occurred.") from exc
    except dns.resolver.NoNameservers as exc:
        raise SpfLookupError("No name servers were found.") from exc
    except DNSException as exc:
        raise SpfLookupError(str(exc) or "DNS lookup failed.") from exc

    records: list[str] = []
    for rdata in answers:
        payload = _txt_payload(rdata)
        if payload.lower().startswith("v=spf1"):
            records.append(payload)
    return records
