"""Deterministic evaluation: fact model + control data -> findings.

No AI anywhere in this path -- that's the point. This is the part of the
system that must always be trustworthy on its own.
"""

import dataclasses
from dataclasses import dataclass
from typing import Any

from .rules import CIS_CONTROLS, ISO_ANNEX_CONTROLS, NIST_CONTROLS, STIG_CONTROLS, Control


@dataclass(frozen=True)
class Finding:
    control_id: str
    framework: str
    title: str
    severity: str
    status: str  # "pass" | "fail"
    remediation: str | None


@dataclass(frozen=True)
class FactEvidence:
    """One fact's contribution to an ISO Annex A control's evidence -- not a
    verdict on the control itself (see IsoEvidenceFinding)."""

    fact_id: str
    title: str
    satisfied: bool
    remediation: str | None


@dataclass(frozen=True)
class IsoEvidenceFinding:
    control_id: str
    framework: str
    title: str
    evidence: list[FactEvidence]


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


def _evaluate_framework(
    facts_by_id: dict[str, Any], controls: list[Control]
) -> list[Finding]:
    return [_evaluate_one(control, facts_by_id[control.fact_id]) for control in controls]


def evaluate_cis(facts: Any) -> list[Finding]:
    return _evaluate_framework(dataclasses.asdict(facts), CIS_CONTROLS)


def evaluate_nist(facts: Any) -> list[Finding]:
    return _evaluate_framework(dataclasses.asdict(facts), NIST_CONTROLS)


def evaluate_stig(facts: Any) -> list[Finding]:
    return _evaluate_framework(dataclasses.asdict(facts), STIG_CONTROLS)


def evaluate_iso(facts: Any) -> list[IsoEvidenceFinding]:
    """ISO/IEC 27001 Annex A is evaluated at the control-objective level:
    many facts support one Annex A control. This deliberately produces no
    pass/fail verdict for the control itself -- only per-fact evidence --
    so it can never be misread as a line-item check the way CIS/NIST/STIG
    are (see ISO_ANNEX_CONTROLS in rules.py)."""
    facts_by_id = dataclasses.asdict(facts)
    passes_when_by_fact = {c.fact_id: c.passes_when for c in CIS_CONTROLS}
    title_by_fact = {c.fact_id: c.title for c in CIS_CONTROLS}
    remediation_by_fact = {c.fact_id: c.remediation for c in CIS_CONTROLS}

    findings = []
    for annex in ISO_ANNEX_CONTROLS:
        evidence = []
        for fact_id in annex.fact_ids:
            satisfied = facts_by_id[fact_id] == passes_when_by_fact[fact_id]
            evidence.append(
                FactEvidence(
                    fact_id=fact_id,
                    title=title_by_fact[fact_id],
                    satisfied=satisfied,
                    remediation=None if satisfied else remediation_by_fact[fact_id],
                )
            )
        findings.append(
            IsoEvidenceFinding(
                control_id=annex.control_id,
                framework="ISO/IEC 27001",
                title=annex.title,
                evidence=evidence,
            )
        )
    return findings


# The three frameworks that map 1:1 at the technical-control level (ISO is
# evaluated separately via evaluate_iso -- see evaluate_all). Shared so
# callers that need to know the framework set (e.g. the fleet summary) don't
# hardcode a second copy of these names that could drift out of sync.
FRAMEWORK_NAMES = ("CIS", "NIST SP 800-53", "DISA STIG")


def evaluate_all(facts: Any) -> dict[str, list[dict[str, Any]]]:
    """Findings broken out per framework, for the three frameworks that map
    1:1 at the technical-control level. ISO/IEC 27001 is deliberately not
    included here -- call evaluate_iso separately -- since its evidentiary
    shape must never be flattened into the same pass/fail list as the others."""
    return {
        "CIS": [dataclasses.asdict(f) for f in evaluate_cis(facts)],
        "NIST SP 800-53": [dataclasses.asdict(f) for f in evaluate_nist(facts)],
        "DISA STIG": [dataclasses.asdict(f) for f in evaluate_stig(facts)],
    }
