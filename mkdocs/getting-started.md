# Getting started

## Requirements

- Python 3.10 or newer
- `dnspython`, `prettytable`, and `colored` (installed with the package)

## Install

```bash
pip install lupaxa-mx-inspector
mx-inspector --help
```

Library import:

```python
from lupaxa.mx_inspector import lookup_dmarc, lookup_mx, lookup_spf, score_posture

policy = lookup_dmarc("example.com")
hosts = lookup_mx("example.com")
spf = lookup_spf("example.com")
print(score_posture(policy, mx_hosts=hosts, spf_records=spf))
```

Module entry point:

```bash
python -m lupaxa.mx_inspector --version
```

### From source (development)

```bash
make init
make python-install-dev
mx-inspector --version
```

## First run

Pass one or more domain names. The tool queries public DNS for MX hosts,
SPF, and `_dmarc.<domain>`, then prints a table. MX servers are first,
then SPF, then every known DMARC tag (unpublished tags show as
`missing`). The posture score is a footer at the bottom. On a colour
terminal the table is coloured; pass `--no-color` or set `NO_COLOR` for
plain text:

```bash
mx-inspector example.com
mx-inspector example.com --no-color
```

JSON output:

```bash
mx-inspector example.com --format json
```

SMTP banner fingerprint (authorised targets only). The probe speaks
cleartext SMTP on port 25 by default. Use `--port 587` for message
submission, and `--timeout` if a host is slow:

```bash
mx-inspector example.com --probe
mx-inspector example.com --probe --port 587
mx-inspector example.com --probe --timeout 10
mx-inspector example.com --probe --port 587 --timeout 10
```

## Makefile helpers

```bash
make init                 # clone makefile-skills into .makefiles/
make python-install-dev   # editable install with [dev]
make python-check         # lint + type + test
make mkdocs-serve         # local docs site
```
