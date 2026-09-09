"""Table colours via colored (256-colour names)."""

from __future__ import annotations

import os
from typing import TextIO

from colored import Fore, Style

_GRADE_COLOR: dict[str, str] = {
    "open": f"{Fore.red}",
    "monitoring": f"{Fore.dark_orange}",
    "enforcing": f"{Fore.yellow}",
    "locked down": f"{Fore.green}",
}


def paint(text: str, code: str) -> str:
    """Wrap ``text`` in ``code`` if it is not empty."""
    if not text:
        return text
    return f"{code}{text}{Style.reset}"


def color_name(text: str) -> str:
    """Cyan for the Name header and row labels."""
    return paint(text, Fore.cyan)


def color_value(text: str) -> str:
    """Green for values; dark grey for ``missing``."""
    if text == "missing":
        return paint(text, Fore.dark_gray)
    return paint(text, Fore.green)


def color_score(text: str, grade: str) -> str:
    """Colour a posture score by grade: red, orange, yellow, green."""
    return paint(text, _GRADE_COLOR.get(grade, _GRADE_COLOR["locked down"]))


def color_title(domain: str) -> str:
    """Cyan ``Results for:`` label and bold white domain."""
    label = paint("Results for:", Fore.cyan)
    name = paint(domain, f"{Style.bold}{Fore.white}")
    return f"{label} {name}"


def use_color(stream: TextIO) -> bool:
    """True when table colour should be written to ``stream``."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("CLICOLOR_FORCE"):
        return True
    isatty = getattr(stream, "isatty", None)
    return bool(isatty()) if callable(isatty) else False
