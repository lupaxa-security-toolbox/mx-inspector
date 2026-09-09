"""Errors raised by the public MX Inspector API."""

from __future__ import annotations


class MxInspectorError(Exception):
    """Base error for MX Inspector."""


class DmarcLookupError(MxInspectorError):
    """A DMARC DNS lookup failed or returned no usable record."""


class MxLookupError(MxInspectorError):
    """An MX DNS lookup failed."""


class SpfLookupError(MxInspectorError):
    """An SPF DNS lookup failed."""
