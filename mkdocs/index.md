# MX Inspector

`lupaxa-mx-inspector` looks up a domain's MX hosts, SPF, and published
DMARC TXT record, then decodes the policy into a table or JSON and
scores spoofing posture. An optional `--probe` greets each MX over SMTP
to fingerprint mail software.

!!! warning "Authorised use only"
    `--probe` opens an SMTP session to the target MX hosts. Use it only on
    systems you are allowed to test.

Install the package for the library API and the `mx-inspector` console
command:

```bash
pip install lupaxa-mx-inspector
mx-inspector example.com
```

You can also run `python -m lupaxa.mx_inspector`.

## What it does

- Queries `MX` records for the domain (priority and host)
- Queries apex `TXT` for SPF (`v=spf1`)
- Queries `_dmarc.<domain>` for a TXT record
- Scores spoofing posture (`open` / `monitoring` / `enforcing` / `locked down`)
- Lists MX, then SPF, then every known DMARC tag; posture is a table footer
- Unpublished tags stay in the table as `missing` (JSON uses `null`)
- Colours the table on a TTY (`--no-color` or `NO_COLOR` to disable)
- Optionally greets each MX (`--probe`: banner + EHLO only)
- `--port` (default 25) and `--timeout` (default 5 seconds) control the probe
- Prints a human-readable table, or JSON with `--format json`
- Exposes the same lookups, score, and probe helpers as library functions

## Next steps

- [Getting started](getting-started.md) — install and first run
- [Usage](usage.md) — CLI flags, probe options, and the library API
- [Reference](reference.md) — tags, JSON fields, errors, and exit codes
- [Examples](examples.md) — table, JSON, probe, and library recipes
