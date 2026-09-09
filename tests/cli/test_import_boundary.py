"""Package CLI wiring."""

from __future__ import annotations

import lupaxa.mx_inspector.cli as cli_mod
from lupaxa.mx_inspector.__main__ import main as module_main


def test_dunder_main_is_cli_main() -> None:
    assert module_main is cli_mod.main
