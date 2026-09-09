"""lupaxa.mx_inspector — look up MX hosts and a domain's DMARC policy."""

from __future__ import annotations

from .dmarc import (
    decode_dmarc_value,
    expand_policy,
    format_dmarc_table,
    lookup_dmarc,
    parse_dmarc_record,
)
from .exceptions import DmarcLookupError, MxInspectorError, MxLookupError
from .mx import MxHost, lookup_mx
from .probe import (
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    SmtpProbe,
    fingerprint_banner,
    probe_mx_hosts,
    probe_smtp,
)
from .version import __version__, get_version

__all__ = [
    "DmarcLookupError",
    "MxHost",
    "MxInspectorError",
    "MxLookupError",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
    "SmtpProbe",
    "__version__",
    "decode_dmarc_value",
    "expand_policy",
    "fingerprint_banner",
    "format_dmarc_table",
    "get_version",
    "lookup_dmarc",
    "lookup_mx",
    "parse_dmarc_record",
    "probe_mx_hosts",
    "probe_smtp",
]
