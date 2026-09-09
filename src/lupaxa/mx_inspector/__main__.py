"""Allow ``python -m lupaxa.mx_inspector`` to run the CLI."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
