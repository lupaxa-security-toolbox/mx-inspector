"""lupaxa.mx_inspector — look up MX hosts, SPF, and a domain's DMARC policy."""

from __future__ import annotations

from .dmarc import (
    decode_dmarc_value,
    expand_policy,
    format_dmarc_table,
    lookup_dmarc,
    parse_dmarc_record,
)
from .exceptions import DmarcLookupError, MxInspectorError, MxLookupError, SpfLookupError
from .mx import MxHost, lookup_mx
from .probe import (
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    SmtpProbe,
    fingerprint_banner,
    probe_mx_hosts,
    probe_smtp,
)
from .score import PostureScore, grade_for, score_posture
from .spf import lookup_spf, parse_spf_all
from .version import __version__, get_version

__all__ = [
    "DmarcLookupError",
    "MxHost",
    "MxInspectorError",
    "MxLookupError",
    "PostureScore",
    "SpfLookupError",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
    "SmtpProbe",
    "__version__",
    "decode_dmarc_value",
    "expand_policy",
    "fingerprint_banner",
    "format_dmarc_table",
    "get_version",
    "grade_for",
    "lookup_dmarc",
    "lookup_mx",
    "lookup_spf",
    "parse_dmarc_record",
    "parse_spf_all",
    "score_posture",
    "probe_mx_hosts",
    "probe_smtp",
]
