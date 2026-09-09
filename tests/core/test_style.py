"""Colour helpers for table output."""

from __future__ import annotations

import io

import pytest
from colored import Fore, Style

from lupaxa.mx_inspector.style import (
    color_name,
    color_score,
    color_title,
    color_value,
    use_color,
)


def test_color_name_is_cyan() -> None:
    assert color_name("MX servers") == f"{Fore.cyan}MX servers{Style.reset}"


def test_color_value_green_unless_missing() -> None:
    assert color_value("reject") == f"{Fore.green}reject{Style.reset}"
    assert color_value("missing") == f"{Fore.dark_gray}missing{Style.reset}"


def test_color_title_is_cyan_label_and_bold_white_domain() -> None:
    title = color_title("example.com")
    assert title.startswith(f"{Fore.cyan}Results for:{Style.reset}")
    assert f"{Style.bold}{Fore.white}example.com{Style.reset}" in title


def test_use_color_respects_no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = io.StringIO()
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert use_color(stream) is False
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert use_color(stream) is True


def test_color_score_follows_grade() -> None:
    assert color_score("12 (open)", "open") == f"{Fore.red}12 (open){Style.reset}"
    assert color_score("30 (monitoring)", "monitoring") == (
        f"{Fore.dark_orange}30 (monitoring){Style.reset}"
    )
    assert color_score("60 (enforcing)", "enforcing") == (
        f"{Fore.yellow}60 (enforcing){Style.reset}"
    )
    assert color_score("90 (locked down)", "locked down") == (
        f"{Fore.green}90 (locked down){Style.reset}"
    )
