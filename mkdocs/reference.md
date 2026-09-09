# Reference

## Policy tags

`lookup_dmarc` returns only the tags the domain published. `rua` and `ruf`
have `mailto:` prefixes stripped.

The table and JSON CLI output list every known field. A tag the record did
not publish is kept in the results as `missing` (table) or `null` (JSON).
Published coded values are decoded in the table (`r` / `s`, `p`, `fo`).

| Tag     | Table label                              | Notes                               |
| :------ | :--------------------------------------- | :---------------------------------- |
| `v`     | DMARC version                            | Usually `DMARC1`                    |
| `p`     | DMARC policy                             | `none`, `quarantine`, or `reject`   |
| `sp`    | Subdomain policy                         | Shown as missing when omitted       |
| `np`    | Nonexistent subdomain policy             | RFC 9091                            |
| `rua`   | Aggregate report addresses               | One table row per address           |
| `ruf`   | Forensic report addresses                | One table row per address           |
| `ri`    | Report interval                          | Shown as seconds when present       |
| `pct`   | Accuracy percentage                      | Shown with `%` when present         |
| `adkim` | DKIM alignment mode                      | `relaxed (r)` or `strict (s)`       |
| `aspf`  | SPF alignment mode                       | `relaxed (r)` or `strict (s)`       |
| `fo`    | Failure options                          | `0`, `1`, `d`, and `s` are expanded |
| `rf`    | Report format                            | Usually `afrf`                      |
| `pua`   | Unauthenticated report address           | Optional                            |
| `spua`  | Subdomain unauthenticated report address | Optional                            |

Unknown extra tags are appended after the known rows.

## MX hosts

`lookup_mx` returns `MxHost` values (`priority`, `exchange`), sorted by
priority then host name. The table lists them first as
`hostname (Priority: N)`. If the name has no MX records, or only a null
MX (RFC 7505, exchange `.`), the table says `missing` and JSON uses an
empty `mx` list. A priority is shown only when there is a host name.

## SMTP probe

`--probe` / `probe_smtp` / `probe_mx_hosts` greet each MX over cleartext
SMTP. Defaults are `DEFAULT_PORT` (`25`) and `DEFAULT_TIMEOUT` (`5.0`
seconds).

The session is banner, `EHLO`, and `QUIT` only. No `AUTH`, no `STARTTLS`,
and no mail. Port `587` (submission) works when the host answers in
cleartext. Port `465` (implicit TLS) is not supported.

Table rows after the DMARC fields:

| Table label                    | Source                         |
| :----------------------------- | :----------------------------- |
| `Mail software (<host>)`       | Banner fingerprint, or missing |
| `SMTP banner (<host>)`         | `220` greeting, or the error   |
| `SMTP capabilities (<host>)`   | One EHLO keyword per row       |

A refused or timed-out connect is stored on that host. The rest of the
report still prints and the process exit code is unchanged.

## JSON result fields

| Field      | Type           | Meaning                                         |
| :--------- | :------------- | :---------------------------------------------- |
| `domain`   | `str`          | Domain that was requested                       |
| `policy`   | `dict or null` | Known tags (`null` if unpublished), plus extras |
| `mx`       | `list`         | `{priority, exchange}` objects, maybe empty     |
| `error`    | `str or null`  | DMARC failure message, or `null`                |
| `mx_error` | `str or null`  | MX failure message, or `null`                   |
| `probe`    | `list`         | Present only when `--probe` is set              |

Each `probe` item:

| Field          | Type          | Meaning                            |
| :------------- | :------------ | :--------------------------------- |
| `host`         | `str`         | MX exchange that was contacted     |
| `port`         | `int`         | TCP port used for this probe       |
| `banner`       | `str or null` | SMTP `220` greeting                |
| `software`     | `str or null` | Fingerprint from the banner        |
| `capabilities` | `list`        | EHLO keywords                      |
| `error`        | `str or null` | Connect or read failure, or `null` |

## Errors

| Case                         | Library                              | CLI                                 |
| :--------------------------- | :----------------------------------- | :---------------------------------- |
| Empty domain                 | `DmarcLookupError` / `MxLookupError` | Exit 2; stderr or JSON error fields |
| NXDOMAIN / timeout / no NS   | `DmarcLookupError` / `MxLookupError` | Exit 2; stderr or JSON error fields |
| TXT present but not DMARC    | `DmarcLookupError`                   | Exit 2; stderr or JSON `error`      |
| No MX records                | Empty list                           | Table `missing`; JSON `mx: []`      |
| One of several domains fails | Raised per call                      | Other domains still print; exit 2   |
| SMTP probe connect / timeout | `SmtpProbe.error` set                | Host row records it; exit unchanged |
| `--port` outside `1`–`65535` | —                                    | Exit 2 (argparse)                   |
| `--timeout` `<= 0`           | —                                    | Exit 2 (argparse)                   |

## Exit codes

| Code | When                                               |
| :--- | :------------------------------------------------- |
| `0`  | Lookups succeeded (probe host errors do not count) |
| `2`  | Bad flags, or any DMARC / MX lookup failed         |
