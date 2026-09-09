"""DMARC / MX / SPF posture score."""

from __future__ import annotations

from lupaxa.mx_inspector.mx import MxHost
from lupaxa.mx_inspector.score import grade_for, score_posture


def test_grade_bands() -> None:
    assert grade_for(0) == "open"
    assert grade_for(24) == "open"
    assert grade_for(25) == "monitoring"
    assert grade_for(49) == "monitoring"
    assert grade_for(50) == "enforcing"
    assert grade_for(74) == "enforcing"
    assert grade_for(75) == "locked down"
    assert grade_for(100) == "locked down"


def test_score_no_dmarc_no_spf_is_open() -> None:
    result = score_posture({}, mx_hosts=[], spf_records=[])
    assert result.value == 0
    assert result.grade == "open"
    assert "No DMARC record" in result.reasons
    assert "No SPF record" in result.reasons


def test_score_p_none_is_monitoring() -> None:
    result = score_posture({"p": "none"}, mx_hosts=[], spf_records=[])
    assert result.grade == "monitoring"
    assert any("p=none" in reason for reason in result.reasons)


def test_score_reject_and_spf_fail_is_locked_down() -> None:
    result = score_posture(
        {
            "p": "reject",
            "sp": "reject",
            "np": "reject",
            "rua": "dmarc@example.com",
            "adkim": "s",
            "aspf": "s",
        },
        mx_hosts=[MxHost(priority=10, exchange="mail.example.com")],
        spf_records=["v=spf1 include:_spf.example.net -all"],
    )
    assert result.value == 100
    assert result.grade == "locked down"


def test_score_reject_scales_with_pct() -> None:
    full = score_posture({"p": "reject"}, mx_hosts=[], spf_records=[])
    partial = score_posture({"p": "reject", "pct": "10"}, mx_hosts=[], spf_records=[])
    assert partial.value < full.value
    assert any("pct=10" in reason for reason in partial.reasons)


def test_score_plus_all_is_a_penalty() -> None:
    hard = score_posture({"p": "reject"}, mx_hosts=[], spf_records=["v=spf1 -all"])
    open_all = score_posture({"p": "reject"}, mx_hosts=[], spf_records=["v=spf1 +all"])
    assert open_all.value < hard.value
    assert any("+all" in reason for reason in open_all.reasons)


def test_score_aspf_ignored_without_spf() -> None:
    result = score_posture(
        {"p": "reject", "aspf": "s"},
        mx_hosts=[],
        spf_records=[],
    )
    assert any("no SPF" in reason for reason in result.reasons)


def test_score_subdomain_none_penalises_reject() -> None:
    inherited = score_posture({"p": "reject"}, mx_hosts=[], spf_records=[])
    weak_sp = score_posture({"p": "reject", "sp": "none"}, mx_hosts=[], spf_records=[])
    assert weak_sp.value < inherited.value
