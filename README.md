<p align="center">
  <a href="https://github.com/lupaxa-security-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/security-toolbox/readme-logo.png" alt="Security Toolbox" />
  </a>
</p>

<h1 align="center">mx-inspector</h1>

Look up a domain's MX hosts and DMARC policy from public DNS, with an
optional SMTP banner probe.

> [!WARNING]
> **Authorised use only.** `--probe` opens an SMTP session to the target
> MX hosts. Use it only on systems you are allowed to test.

<p align="center">
  <a href="https://mx-inspector.thelupaxaproject.org/">Documentation</a>
  ·
  <a href="https://github.com/lupaxa-security-toolbox/mx-inspector">GitHub</a>
</p>

## Install

```bash
pip install lupaxa-mx-inspector
mx-inspector --help
```

## CLI

```bash
mx-inspector example.com
mx-inspector example.com example.org
mx-inspector example.com --format json
mx-inspector example.com --probe
mx-inspector example.com --probe --port 587
mx-inspector example.com --probe --timeout 10
python -m lupaxa.mx_inspector --version
```

The tool queries MX hosts, SPF, and `_dmarc.<domain>`, then prints a
table of decoded tags and a spoofing-posture score. `--probe` greets
each MX (banner + EHLO only) to fingerprint mail software. `--port`
sets the SMTP probe port (default 25; use `587` for submission).
`--timeout` sets the SMTP probe timeout (default 5 seconds).
`--format json` writes `{domain, policy, mx, spf, score, error,
mx_error, spf_error}` objects, plus `probe` when `--probe` is set.

## Library

```python
from lupaxa.mx_inspector import lookup_dmarc, lookup_mx

policy = lookup_dmarc("example.com")
print(policy["p"], policy.get("rua"))
for host in lookup_mx("example.com"):
    print(host.priority, host.exchange)
```

## Development

```bash
make init
make python-install-dev
make python-check
make mkdocs-serve
```

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
