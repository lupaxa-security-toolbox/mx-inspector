# Examples

## Table (default)

```bash
mx-inspector example.com
```

Live table from `mx-inspector example.com`. MX servers are first;
unpublished tags stay as `missing`:

![Table output from mx-inspector example.com](assets/images/example-com-table.png)

## Several domains

```bash
mx-inspector example.com example.org
```

Each domain prints its own table. If one lookup fails, the others still
print and the process exits non-zero.

## JSON

```bash
mx-inspector example.com --format json
```

JSON is a list of result objects. Every known policy tag is present;
unpublished tags are `null`:

```json
[
  {
    "domain": "example.com",
    "error": null,
    "mx_error": null,
    "policy": {
      "v": "DMARC1",
      "p": "reject",
      "sp": null,
      "rua": "dmarc@example.com",
      "ruf": null
    },
    "mx": [
      {"priority": 10, "exchange": "mail.example.com"}
    ]
  }
]
```

## Probe

Authorised targets only. Default port is 25; use `--port 587` for
submission and `--timeout` when a host is slow:

```bash
mx-inspector example.com --probe
mx-inspector example.com --probe --port 587 --timeout 10 --format json
```

Table output adds mail software, banner, and capabilities after the
DMARC rows:

```text
| Mail software (mail.example.com)         | Postfix                                    |
| SMTP banner (mail.example.com)           | 220 mail.example.com ESMTP Postfix         |
| SMTP capabilities (mail.example.com)     | PIPELINING                                 |
|                                          | STARTTLS                                   |
```

JSON adds a `probe` list:

```json
[
  {
    "domain": "example.com",
    "error": null,
    "mx_error": null,
    "policy": {"p": "reject"},
    "mx": [{"priority": 10, "exchange": "mail.example.com"}],
    "probe": [
      {
        "host": "mail.example.com",
        "port": 587,
        "banner": "220 mail.example.com ESMTP Postfix",
        "software": "Postfix",
        "capabilities": ["PIPELINING", "STARTTLS"],
        "error": null
      }
    ]
  }
]
```

## Library

```python
from lupaxa.mx_inspector import lookup_dmarc, lookup_mx, parse_dmarc_record

policy = lookup_dmarc("example.com")
print(policy["p"], policy.get("rua"))

for host in lookup_mx("example.com"):
    print(host.priority, host.exchange)

tags = parse_dmarc_record(
    "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
)
print(tags["rua"])
```

Probe helpers (authorised targets only):

```python
from lupaxa.mx_inspector import lookup_mx, probe_mx_hosts, probe_smtp

hosts = lookup_mx("example.com")
results = probe_mx_hosts(hosts, port=587, timeout=10)
print(results[0].software, results[0].capabilities)

one = probe_smtp("mail.example.com", port=25, timeout=5)
print(one.banner, one.error)
```
