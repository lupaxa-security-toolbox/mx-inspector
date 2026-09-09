"""Look up a domain's published MX hosts."""

from __future__ import annotations

from dataclasses import dataclass

import dns.resolver
from dns.exception import DNSException

from .exceptions import MxLookupError


@dataclass(frozen=True)
class MxHost:
    """One mail exchanger: SMTP preference and host name."""

    priority: int
    exchange: str


def _exchange_name(rdata: object) -> str:
    exchange = getattr(rdata, "exchange", "")
    return str(exchange).rstrip(".")


def _usable_exchange(exchange: str) -> bool:
    """False for a null MX (RFC 7505): exchange is ``.`` / empty."""
    return bool(exchange)


def lookup_mx(domain: str) -> list[MxHost]:
    """Query ``MX`` records for ``domain``, lowest priority first.

    Parameters
    ----------
    domain
        Apex or host name whose mail exchangers should be fetched.

    Returns
    -------
    list[MxHost]
        Published exchangers. An empty list means the name exists but has
        no usable MX records (none published, or only a null MX).

    Raises
    ------
    MxLookupError
        If the domain is empty or DNS fails.
    """
    name = domain.strip()
    if not name:
        raise MxLookupError("empty domain")
    try:
        answers = dns.resolver.resolve(name, "MX")
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN as exc:
        raise MxLookupError(f"Domain '{name}' does not exist.") from exc
    except dns.resolver.Timeout as exc:
        raise MxLookupError("DNS query timeout occurred.") from exc
    except dns.resolver.NoNameservers as exc:
        raise MxLookupError("No name servers were found.") from exc
    except DNSException as exc:
        raise MxLookupError(str(exc) or "DNS lookup failed.") from exc

    hosts = []
    for rdata in answers:
        exchange = _exchange_name(rdata)
        if not _usable_exchange(exchange):
            continue
        hosts.append(MxHost(priority=int(rdata.preference), exchange=exchange))
    hosts.sort(key=lambda host: (host.priority, host.exchange))
    return hosts
