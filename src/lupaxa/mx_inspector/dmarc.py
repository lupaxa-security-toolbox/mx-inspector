"""Look up and decode a domain's published DMARC policy."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import dns.resolver
from dns.exception import DNSException
from prettytable import PrettyTable

from .exceptions import DmarcLookupError
from .mx import MxHost
from .probe import SmtpProbe
from .score import PostureScore
from .style import color_name, color_score, color_title, color_value

_FIELD_LABELS = (
    ("v", "DMARC version", None),
    ("p", "DMARC policy", None),
    ("sp", "Subdomain policy", None),
    ("np", "Nonexistent subdomain policy", None),
    ("rua", "Aggregate report addresses", None),
    ("ruf", "Forensic report addresses", None),
    ("ri", "Report interval", "seconds"),
    ("pct", "Accuracy percentage", "%"),
    ("adkim", "DKIM alignment mode", None),
    ("aspf", "SPF alignment mode", None),
    ("fo", "Failure options", None),
    ("rf", "Report format", None),
    ("pua", "Unauthenticated report address", None),
    ("spua", "Subdomain unauthenticated report address", None),
)
_KNOWN_TAGS = tuple(key for key, _label, _suffix in _FIELD_LABELS)
_LIST_TAGS = frozenset({"rua", "ruf", "pua", "spua"})
_MISSING = "missing"

_POLICY_MEANING = {
    "none": "none (monitor only; do not affect delivery)",
    "quarantine": "quarantine (treat as suspicious)",
    "reject": "reject (refuse non-aligned mail)",
}
_ALIGNMENT_MEANING = {
    "r": "relaxed (r)",
    "s": "strict (s)",
}
_FAILURE_OPTION_MEANING = {
    "0": "0 (report if all mechanisms fail)",
    "1": "1 (report if any mechanism fails)",
    "d": "d (report DKIM failures)",
    "s": "s (report SPF failures)",
}
_REPORT_FORMAT_MEANING = {
    "afrf": "afrf (authentication failure reporting format)",
}


def remove_prefix(
    text: str,
    prefix: str,
    delimiter: str | None = ",",
    replacement_delimiter: str | None = ", ",
) -> str:
    """Strip ``prefix`` from ``text`` and optionally tidy list delimiters."""
    cleaned_text = text.replace(prefix, "")
    if delimiter is not None and replacement_delimiter is not None:
        cleaned_text = cleaned_text.replace(delimiter, replacement_delimiter)
    return cleaned_text


def parse_dmarc_record(record: str) -> dict[str, str]:
    """Parse a DMARC TXT payload into a tag dictionary.

    Parameters
    ----------
    record
        Raw DMARC TXT contents, with or without surrounding quotes.

    Returns
    -------
    dict[str, str]
        Tag names mapped to values. ``rua`` and ``ruf`` have ``mailto:``
        prefixes removed.

    Raises
    ------
    DmarcLookupError
        If the payload is not a DMARC record.
    """
    payload = record.strip().strip('"')
    if not payload.startswith("v=DMARC"):
        raise DmarcLookupError("TXT payload is not a DMARC record")

    policy: dict[str, str] = {}
    for item in payload.split(";"):
        piece = item.strip()
        if not piece or "=" not in piece:
            continue
        key, value = map(str.strip, piece.split("=", 1))
        if not key:
            continue
        if key in {"rua", "ruf"}:
            value = remove_prefix(value, "mailto:")
        policy[key] = value
    return policy


def _txt_payload(rdata: Any) -> str:
    strings = getattr(rdata, "strings", None)
    if strings:
        parts = [part.decode("utf-8") if isinstance(part, bytes) else str(part) for part in strings]
        return "".join(parts)
    return rdata.to_text().strip('"')


def lookup_dmarc(domain: str) -> dict[str, str]:
    """Query ``_dmarc.<domain>`` and return the decoded policy tags.

    Parameters
    ----------
    domain
        Apex or host name whose DMARC record should be fetched.

    Returns
    -------
    dict[str, str]
        Parsed DMARC tags.

    Raises
    ------
    DmarcLookupError
        If DNS fails or no DMARC TXT record is published.
    """
    name = domain.strip()
    if not name:
        raise DmarcLookupError("empty domain")
    query_name = f"_dmarc.{name}"
    try:
        answers = dns.resolver.resolve(query_name, "TXT")
    except dns.resolver.NXDOMAIN as exc:
        raise DmarcLookupError(f"Domain '{query_name}' does not exist.") from exc
    except dns.resolver.Timeout as exc:
        raise DmarcLookupError("DNS query timeout occurred.") from exc
    except dns.resolver.NoAnswer as exc:
        raise DmarcLookupError("No answer from DNS.") from exc
    except dns.resolver.NoNameservers as exc:
        raise DmarcLookupError("No name servers were found.") from exc
    except DNSException as exc:
        raise DmarcLookupError(str(exc) or "DNS lookup failed.") from exc

    for rdata in answers:
        payload = _txt_payload(rdata)
        if payload.startswith("v=DMARC"):
            return parse_dmarc_record(payload)

    raise DmarcLookupError(f"No DMARC TXT record found for {query_name}")


def decode_dmarc_value(key: str, value: str) -> str:
    """Return a human-readable form of a published DMARC tag value."""
    if key in {"p", "sp", "np"}:
        return _POLICY_MEANING.get(value.lower(), value)
    if key in {"adkim", "aspf"}:
        return _ALIGNMENT_MEANING.get(value.lower(), value)
    if key == "rf":
        return _REPORT_FORMAT_MEANING.get(value.lower(), value)
    if key == "fo":
        parts = [part.strip() for part in value.replace(",", ":").split(":") if part.strip()]
        decoded = [_FAILURE_OPTION_MEANING.get(part.lower(), part) for part in parts]
        return "; ".join(decoded) if decoded else value
    return value


def expand_policy(dmarc_policy: dict[str, str]) -> dict[str, str | None]:
    """Return every known tag, using ``None`` where the record omitted it."""
    expanded: dict[str, str | None] = {key: dmarc_policy.get(key) for key in _KNOWN_TAGS}
    for key, value in dmarc_policy.items():
        if key not in expanded:
            expanded[key] = value
    return expanded


def _row_value(key: str, raw: str | None, suffix: str | None) -> str:
    if raw is None:
        return _MISSING
    value = decode_dmarc_value(key, raw)
    if suffix == "seconds":
        return f"{value} seconds"
    if suffix == "%":
        return f"{value}%"
    return value


def _split_list_value(raw: str) -> list[str]:
    parts = [part.strip() for part in raw.split(",") if part.strip()]
    return parts or [raw]


def _row_values(key: str, raw: str | None, suffix: str | None) -> list[str]:
    if raw is None:
        return [_MISSING]
    if key in _LIST_TAGS or (key not in _KNOWN_TAGS and "," in raw):
        return _split_list_value(raw)
    return [_row_value(key, raw, suffix)]


def _add_named_rows(
    table: PrettyTable,
    label: str,
    values: Sequence[str],
    *,
    color: bool = False,
) -> None:
    for index, value in enumerate(values):
        name = label if index == 0 else ""
        table.add_row([_style_name(name, color), _style_value(value, color)])


def _style_name(text: str, color: bool) -> str:
    return color_name(text) if color else text


def _style_value(text: str, color: bool, *, grade: str | None = None) -> str:
    if not color:
        return text
    if grade is not None:
        return color_score(text, grade)
    return color_value(text)


def format_dmarc_table(
    domain: str,
    dmarc_policy: dict[str, str],
    mx_hosts: Sequence[MxHost] | None = None,
    smtp_probes: Sequence[SmtpProbe] | None = None,
    spf_records: Sequence[str] | None = None,
    posture: PostureScore | None = None,
    color: bool = False,
) -> str:
    """Render a human-readable table for a decoded DMARC policy.

    Every known field is listed. Tags the domain did not publish are shown
    as ``missing`` rather than omitted. MX hosts are listed first, or as
    ``missing`` when none were published. Posture score and notes are a
    footer below a divider, after SPF, DMARC, and any probe rows.
    """
    table = PrettyTable()
    table.field_names = [
        _style_name("Name", color),
        _style_value("Value", color),
    ]
    table.title = color_title(domain) if color else f"Results for: {domain}"

    usable = [host for host in (mx_hosts or ()) if host.exchange]
    if usable:
        mx_values = [f"{host.exchange} (Priority: {host.priority})" for host in usable]
        _add_named_rows(table, "MX servers", mx_values, color=color)
    else:
        table.add_row([_style_name("MX servers", color), _style_value(_MISSING, color)])

    if spf_records is not None:
        if spf_records:
            _add_named_rows(table, "SPF", list(spf_records), color=color)
        else:
            table.add_row([_style_name("SPF", color), _style_value(_MISSING, color)])

    seen: set[str] = set()
    for key, label, suffix in _FIELD_LABELS:
        seen.add(key)
        raw = dmarc_policy.get(key) if key in dmarc_policy else None
        _add_named_rows(table, label, _row_values(key, raw, suffix), color=color)

    for key, value in dmarc_policy.items():
        if key not in seen:
            _add_named_rows(table, key, _row_values(key, value, None), color=color)

    if smtp_probes is not None:
        if smtp_probes:
            for item in smtp_probes:
                host_label = item.host or "MX"
                table.add_row(
                    [
                        _style_name(f"Mail software ({host_label})", color),
                        _style_value(item.software or _MISSING, color),
                    ],
                )
                table.add_row(
                    [
                        _style_name(f"SMTP banner ({host_label})", color),
                        _style_value(item.banner or item.error or _MISSING, color),
                    ],
                )
                caps = list(item.capabilities) if item.capabilities else [_MISSING]
                _add_named_rows(
                    table,
                    f"SMTP capabilities ({host_label})",
                    caps,
                    color=color,
                )
        else:
            table.add_row(
                [_style_name("Mail software", color), _style_value(_MISSING, color)],
            )
            table.add_row(
                [_style_name("SMTP banner", color), _style_value(_MISSING, color)],
            )
            table.add_row(
                [
                    _style_name("SMTP capabilities", color),
                    _style_value(_MISSING, color),
                ],
            )

    if posture is not None:
        table.add_divider()
        table.add_row(
            [
                _style_name("Posture score", color),
                _style_value(
                    f"{posture.value} ({posture.grade})",
                    color,
                    grade=posture.grade,
                ),
            ],
        )
        if posture.reasons:
            _add_named_rows(table, "Posture notes", list(posture.reasons), color=color)

    return str(table)
