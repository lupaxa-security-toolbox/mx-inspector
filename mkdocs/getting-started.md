# Getting started

## Requirements

- Python 3.10 or newer
- `dnspython` and `prettytable` (installed with the package)

## Install

```bash
pip install lupaxa-mx-inspector
mx-inspector --help
```

Library import:

```python
from lupaxa.mx_inspector import lookup_dmarc, lookup_mx

policy = lookup_dmarc("example.com")
print(policy["p"])
for host in lookup_mx("example.com"):
    print(host.priority, host.exchange)
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

Pass one or more domain names. The tool queries public DNS for MX hosts
and `_dmarc.<domain>`, then prints a table. MX servers are the first row;
every known DMARC tag follows (unpublished tags show as `missing`):

```bash
mx-inspector example.com
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
