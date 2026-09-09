"""DNS-only spoofing posture score from DMARC, SPF, and MX."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .mx import MxHost
from .spf import parse_spf_all

_POLICY_POINTS = {
    "none": 28,
    "quarantine": 50,
    "reject": 70,
}


@dataclass(frozen=True)
class PostureScore:
    """A 0–100 posture score with a grade and human reasons."""

    value: int
    grade: str
    reasons: tuple[str, ...]


def grade_for(value: int) -> str:
    """Map a clamped 0–100 score onto a named band."""
    if value >= 75:
        return "locked down"
    if value >= 50:
        return "enforcing"
    if value >= 25:
        return "monitoring"
    return "open"


def score_payload(score: PostureScore) -> dict[str, object]:
    """JSON-ready posture object."""
    return {
        "value": score.value,
        "grade": score.grade,
        "reasons": list(score.reasons),
    }


def score_posture(
    dmarc_policy: dict[str, str],
    mx_hosts: Sequence[MxHost] | None = None,
    spf_records: Sequence[str] | None = None,
) -> PostureScore:
    """Score published DMARC + SPF against spoofing of this domain name.

    This is not a phishing-safety rating. Lookalike domains and user
    behaviour are out of scope.
    """
    points = 0
    reasons: list[str] = []
    policy = {key.lower(): value.strip() for key, value in dmarc_policy.items()}
    records = list(spf_records or ())
    usable_mx = [host for host in (mx_hosts or ()) if host.exchange]

    policy_tag = policy.get("p", "").lower()
    if policy_tag not in _POLICY_POINTS:
        reasons.append("No DMARC record")
    else:
        raw_points = _POLICY_POINTS[policy_tag]
        pct = _parse_pct(policy.get("pct"))
        if pct is not None and pct < 100:
            points += int(raw_points * pct / 100)
            reasons.append(f"DMARC p={policy_tag} applies to pct={pct}")
        else:
            points += raw_points
            reasons.append(f"DMARC p={policy_tag}")

        points += _subdomain_points(policy, reasons)
        if policy.get("rua"):
            points += 5
            reasons.append("Aggregate reports (rua) are published")
        else:
            reasons.append("No aggregate reporting (rua)")

        adkim = policy.get("adkim", "r").lower()
        if adkim == "s":
            points += 3
            reasons.append("DKIM alignment is strict (selectors not checked)")
        else:
            points += 1
            reasons.append("DKIM alignment is relaxed (selectors not checked)")

    if not records:
        reasons.append("No SPF record")
        if policy_tag in _POLICY_POINTS and policy.get("aspf", "").lower() == "s":
            reasons.append("SPF alignment not evaluated (no SPF record)")
    else:
        if len(records) > 1:
            points -= 5
            reasons.append("Multiple SPF records are published")
        qualifier = parse_spf_all(records[0] if len(records) == 1 else " ".join(records))
        points += _spf_all_points(qualifier, reasons)
        if policy_tag in _POLICY_POINTS:
            aspf = policy.get("aspf", "r").lower()
            if aspf == "s":
                points += 5
                reasons.append("SPF alignment is strict")
            else:
                points += 2
                reasons.append("SPF alignment is relaxed")

    if usable_mx:
        reasons.append("MX hosts are published")
    else:
        reasons.append("No usable MX hosts")

    value = max(0, min(100, points))
    return PostureScore(value=value, grade=grade_for(value), reasons=tuple(reasons))


def _parse_pct(raw: str | None) -> int | None:
    if raw is None or raw == "":
        return None
    try:
        return max(0, min(100, int(raw)))
    except ValueError:
        return None


def _subdomain_points(policy: dict[str, str], reasons: list[str]) -> int:
    points = 0
    parent = policy.get("p", "").lower()
    sp = policy.get("sp", "").lower()
    if parent in {"quarantine", "reject"}:
        if sp == "none":
            points -= 15
            reasons.append("Subdomain policy is p=none")
        elif sp == "quarantine" and parent == "reject":
            points -= 5
            reasons.append("Subdomain policy is weaker than p=reject")
        elif sp == "reject":
            points += 5
            reasons.append("Subdomain policy is reject")

    np = policy.get("np", "").lower()
    if np == "reject":
        points += 5
        reasons.append("Nonexistent-subdomain policy is reject")
    elif np == "none":
        points -= 5
        reasons.append("Nonexistent-subdomain policy is none")
    return points


def _spf_all_points(qualifier: str | None, reasons: list[str]) -> int:
    if qualifier == "-":
        reasons.append("SPF ends with -all")
        return 15
    if qualifier == "~":
        reasons.append("SPF ends with ~all")
        return 10
    if qualifier == "?":
        reasons.append("SPF ends with ?all")
        return 4
    if qualifier == "+":
        reasons.append("SPF +all allows any sender")
        return -10
    reasons.append("SPF has no all mechanism")
    return 6
