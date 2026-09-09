"""Command-line interface for MX Inspector."""

from __future__ import annotations

import argparse
import json
import sys

from .dmarc import expand_policy, format_dmarc_table, lookup_dmarc
from .exceptions import DmarcLookupError, MxLookupError
from .mx import MxHost, lookup_mx
from .probe import DEFAULT_PORT, DEFAULT_TIMEOUT, SmtpProbe, probe_mx_hosts, probe_payload
from .version import get_version


def _positive_timeout(value: str) -> float:
    timeout = float(value)
    if timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than 0")
    return timeout


def _tcp_port(value: str) -> int:
    port = int(value)
    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def build_parser() -> argparse.ArgumentParser:
    """Build the ``mx-inspector`` argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Look up a domain's MX hosts and DMARC policy from public DNS. "
            "Optional --probe greets each MX over SMTP to fingerprint mail software."
        ),
    )
    parser.add_argument(
        "domains",
        nargs="+",
        help="Domain name(s) to inspect (for example example.com)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=("table", "json"),
        default="table",
        help="Stdout format (default: table)",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Connect to each MX, read the banner, and send EHLO",
    )
    parser.add_argument(
        "--port",
        type=_tcp_port,
        default=DEFAULT_PORT,
        metavar="PORT",
        help=f"SMTP probe TCP port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_timeout,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"SMTP probe timeout in seconds (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument("--version", action="version", version=get_version())
    return parser


def _mx_payload(hosts: list[MxHost]) -> list[dict[str, object]]:
    return [{"priority": host.priority, "exchange": host.exchange} for host in hosts]


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code in (0, None):
            return 0
        if isinstance(code, int):
            return code
        return 2

    results: list[dict[str, object]] = []
    failed = False
    for domain in args.domains:
        policy: dict[str, str] | None = None
        dmarc_error: str | None = None
        try:
            policy = lookup_dmarc(domain)
        except DmarcLookupError as exc:
            failed = True
            dmarc_error = str(exc)
            if args.format != "json":
                print(dmarc_error, file=sys.stderr)

        mx_hosts: list[MxHost] = []
        mx_error: str | None = None
        try:
            mx_hosts = lookup_mx(domain)
        except MxLookupError as exc:
            failed = True
            mx_error = str(exc)
            if args.format != "json":
                print(mx_error, file=sys.stderr)

        probes: list[SmtpProbe] | None = None
        if args.probe:
            probes = probe_mx_hosts(
                mx_hosts,
                port=args.port,
                timeout=args.timeout,
            )

        if args.format == "json":
            row: dict[str, object] = {
                "domain": domain,
                "error": dmarc_error,
                "mx_error": mx_error,
                "policy": expand_policy(policy) if policy is not None else None,
                "mx": _mx_payload(mx_hosts),
            }
            if probes is not None:
                row["probe"] = probe_payload(probes)
            results.append(row)
        else:
            print(
                format_dmarc_table(
                    domain,
                    policy or {},
                    mx_hosts=mx_hosts,
                    smtp_probes=probes,
                )
            )

    if args.format == "json":
        print(json.dumps(results, indent=2))
    return 2 if failed else 0
