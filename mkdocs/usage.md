# Usage

Input is one or more domain names. Each name is looked up independently.
MX, SPF, and DMARC lookups are independent: one can fail without dropping
the others.

## CLI flags

| Flag             | Default | Description                                   |
| :--------------- | :------ | :-------------------------------------------- |
| `--format`, `-f` | `table` | Output format: `table` or `json`              |
| `--probe`        | off     | Greet each MX (banner + EHLO)                 |
| `--port`         | `25`    | SMTP probe TCP port (e.g. `587` submission)   |
| `--timeout`      | `5`     | SMTP probe timeout in seconds (must be `> 0`) |
| `--no-color`     | off     | Disable colour in table output                |
| `--version`      | —       | Print the package version and exit            |

```bash
mx-inspector example.com
mx-inspector example.com example.org
mx-inspector example.com --format json
mx-inspector example.com --no-color
mx-inspector example.com --probe
mx-inspector example.com --probe --port 587
mx-inspector example.com --probe --timeout 10
mx-inspector example.com --probe --port 587 --timeout 10
```

Table output is a PrettyTable titled with the domain. MX hosts come first
as `hostname (Priority: N)` rows, or `missing` when none are published
(including a null MX). The SPF record (or `missing`) and every known
DMARC field follow. A posture score (0–100) and notes sit in a footer
below a drawn line. On a colour terminal, the title is cyan `Results
for:` plus a bold white domain, names are cyan, values are green,
`missing` is grey, and the posture score is red / orange / yellow /
green by grade. Pass `--no-color` or set `NO_COLOR` to disable.
Unpublished tags are shown as `missing`. Comma-separated values such as
report addresses are split onto their own rows. `--probe` appends mail
software, SMTP banner, and EHLO capabilities per host.

The posture score is DNS-only spoofing posture for this exact domain
name (`open`, `monitoring`, `enforcing`, or `locked down`). It is not a
phishing-safety rating.

JSON is a list of objects with `domain`, `policy`, `mx`, `spf`,
`score`, `error`, `mx_error`, and `spf_error`. `--probe` adds a `probe`
list. Known tags that were not published are `null` on `policy`.

A failed DMARC, MX, or SPF lookup prints the error on stderr for table
mode, or sets `error` / `mx_error` / `spf_error` on that result in JSON
mode. The process exits non-zero if any lookup failed.

## Probe

`--probe` connects to each MX, reads the `220` banner, sends
`EHLO mx-inspector.invalid`, and `QUIT`. It does not authenticate,
start TLS, or submit mail.

| Option      | Default | Notes                                                              |
| :---------- | :------ | :----------------------------------------------------------------- |
| `--port`    | `25`    | TCP port `1`–`65535`. Use `587` for submission                     |
| `--timeout` | `5`     | Connect and read timeout in seconds                                |

The probe speaks cleartext SMTP only. Port 465 (implicit TLS) is not
supported. A connect or read failure is recorded on that host and does
not abort the rest of the report.

`--port` and `--timeout` are ignored unless `--probe` is set.

## Library

```python
from lupaxa.mx_inspector import (
    lookup_dmarc,
    lookup_mx,
    lookup_spf,
    parse_dmarc_record,
    score_posture,
)

policy = lookup_dmarc("example.com")
hosts = lookup_mx("example.com")
spf = lookup_spf("example.com")
score = score_posture(policy, mx_hosts=hosts, spf_records=spf)
print(score.value, score.grade, score.reasons)

tags = parse_dmarc_record("v=DMARC1; p=none; rua=mailto:dmarc@example.com")
```

SMTP probe from Python (authorised targets only):

```python
from lupaxa.mx_inspector import DEFAULT_PORT, DEFAULT_TIMEOUT, lookup_mx, probe_mx_hosts

hosts = lookup_mx("example.com")
for item in probe_mx_hosts(hosts, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    print(item.host, item.port, item.software, item.error)
```

| Function              | Role                                               |
| :-------------------- | :------------------------------------------------- |
| `lookup_dmarc`        | Query `_dmarc.<domain>` and return parsed tags     |
| `lookup_mx`           | Query `MX` records; empty list if none published   |
| `lookup_spf`          | Query apex `TXT` for `v=spf1` records              |
| `parse_spf_all`       | Last published SPF `all` qualifier                 |
| `score_posture`       | 0–100 spoofing posture from DMARC, SPF, and MX     |
| `grade_for`           | Map a 0–100 score to a posture grade               |
| `parse_dmarc_record`  | Parse a DMARC TXT payload without talking to DNS   |
| `format_dmarc_table`  | Render the human-readable table as a string        |
| `expand_policy`       | Fill known tags with `None` where they are absent  |
| `decode_dmarc_value`  | Expand a coded tag value for display               |
| `probe_smtp`          | Banner + EHLO one host                             |
| `probe_mx_hosts`      | Banner + EHLO each `MxHost`                        |
| `fingerprint_banner`  | Map a `220` greeting to a product name if possible |

`lookup_dmarc` and `parse_dmarc_record` raise `DmarcLookupError` when the
lookup fails or the payload is not a DMARC record. `lookup_mx` raises
`MxLookupError` on DNS failure. `lookup_spf` raises `SpfLookupError` on
DNS failure. No MX or SPF records is an empty list, not an error. Probe helpers return an `SmtpProbe` with `error` set on connect
failure; they do not raise for a refused or timed-out SMTP session.
