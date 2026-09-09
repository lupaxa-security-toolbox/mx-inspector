# MX Inspector

`lupaxa-mx-inspector` looks up a domain's MX hosts and published DMARC TXT
record, then decodes the policy tags into a table or JSON. An optional
`--probe` greets each MX over SMTP to fingerprint mail software.

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
- Queries `_dmarc.<domain>` for a TXT record
- Lists MX servers first in the table, then every known DMARC tag
- Unpublished tags stay in the table as `missing` (JSON uses `null`)
- Optionally greets each MX (`--probe`: banner + EHLO only)
- `--port` (default 25) and `--timeout` (default 5 seconds) control the probe
- Prints a human-readable table, or JSON with `--format json`
- Exposes the same lookups and probe helpers as library functions

## Next steps

- [Getting started](getting-started.md) — install and first run
- [Usage](usage.md) — CLI flags, probe options, and the library API
- [Reference](reference.md) — tags, JSON fields, errors, and exit codes
- [Examples](examples.md) — table, JSON, probe, and library recipes
