<!-- markdownlint-disable -->
<p align="center">
  <a href="https://github.com/lupaxa-security-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/security-toolbox/readme-logo.png" alt="Project Logo" width="256"/><br/>
  </a>
</p>
<h3 align="center">
  The Lupaxa Security Toolbox<br />
  Part of The Lupaxa Project
</h3>

<br />

# lupaxa-mx-inspector

Look up a domain's MX hosts, SPF, and DMARC policy from public DNS,
with an optional SMTP banner probe.

> [!WARNING]
> **Authorised use only.** `--probe` opens an SMTP session to the target
> MX hosts. Use it only on systems you are allowed to test.

## Features

- Query `MX` records (priority and host)
- Query apex `TXT` for SPF (`v=spf1`)
- Query `_dmarc.<domain>` for the published TXT record
- Decode common DMARC tags (`p`, `sp`, `rua`, `ruf`, alignment, and more)
- Score DNS-only spoofing posture (`open` / `monitoring` / `enforcing` / `locked down`)
- Optional `--probe` SMTP banner / EHLO fingerprint (no authentication, no mail)
- Human-readable table (colour on a TTY; `--no-color` or `NO_COLOR` to disable), or JSON
- Library API (`lookup_dmarc` / `lookup_mx` / `lookup_spf` / `score_posture` / `probe_smtp`) and CLI (`mx-inspector`)
- Fully typed, linted, formatted, and tested

## Installation

### From PyPI

```bash
pip install lupaxa-mx-inspector
```

### From source (development mode)

```bash
pip install -e ".[dev]"
```

Requires Python 3.10+. Runtime dependencies: `dnspython`, `prettytable`,
`colored`.

## Library quick start

```python
from lupaxa.mx_inspector import lookup_dmarc, lookup_mx, lookup_spf, score_posture

policy = lookup_dmarc("example.com")
hosts = lookup_mx("example.com")
spf = lookup_spf("example.com")
score = score_posture(policy, mx_hosts=hosts, spf_records=spf)
print(policy["p"], score.value, score.grade)
```

## CLI quick start

```bash
mx-inspector --help
mx-inspector example.com
mx-inspector example.com example.org
mx-inspector example.com --format json
mx-inspector example.com --no-color
mx-inspector example.com --probe --port 587
```

You can also run the CLI as a module:

```bash
python -m lupaxa.mx_inspector --help
python -m lupaxa.mx_inspector --version
```

## Documentation

Online documentation:

[Documentation](https://mx-inspector.thelupaxaproject.org/)

Source repository:

[GitHub](https://github.com/lupaxa-security-toolbox/mx-inspector)

### Serve docs locally

From a clone of the repository:

```bash
make mkdocs-serve
```

Then open the local URL printed by MkDocs in your browser.

## Development

Clone the repository and install with Make:

```bash
make init                # first-time makefile-skills checkout
make python-install-dev  # editable install with [dev]
make python-check        # lint, type-check, and test
```

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
