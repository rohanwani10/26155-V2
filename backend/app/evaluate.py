"""Deterministic evaluation: fact model + control data -> findings.

No AI anywhere in this path -- that's the point. This is the part of the
system that must always be trustworthy on its own.
"""

import dataclasses
from dataclasses import dataclass
from typing import Any

from .rules import CIS_CONTROLS, Control


@dataclass(frozen=True)
class Finding:
    control_id: str
    framework: str
    title: str
    severity: str
    status: str  # "pass" | "fail"
    remediation: str | None


def _evaluate_one(control: Control, fact_value: bool) -> Finding:
    passed = fact_value == control.passes_when
    return Finding(
        control_id=control.control_id,
        framework=control.framework,
        title=control.title,
        severity=control.severity,
        status="pass" if passed else "fail",
        remediation=None if passed else control.remediation,
    )


def evaluate_cis(facts: Any) -> list[Finding]:
    facts_by_id = dataclasses.asdict(facts)
    return [
        _evaluate_one(control, facts_by_id[control.fact_id])
        for control in CIS_CONTROLS
    ]
