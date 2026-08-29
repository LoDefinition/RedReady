"""Risk scoring.

``RiskScore = CVSS_base * 0.4 + Prevalence * 0.35 + EPSS * 0.25`` (spec 8.3). Findings that carry
no intelligence at all — a missing security header, an exposed port — fall back to the base score
for the severity the emitting module assigned, so the ordering of the report stays meaningful.
"""

from __future__ import annotations

from redready.engine.result import (
    SEVERITY_BASE_SCORE,
    Finding,
    Severity,
    severity_for_score,
)

CVSS_WEIGHT = 0.4
PREVALENCE_WEIGHT = 0.35
EPSS_WEIGHT = 0.25


def risk_score(
    cvss_score: float | None,
    prevalence: float | None,
    epss: float | None,
) -> float | None:
    """Weighted risk score in ``0.0–1.0``; ``None`` when no intelligence is available.

    Weights of absent components are redistributed across the ones we do have, so a finding with
    only a CVSS score is not artificially deflated by a missing EPSS probability.
    """
    components: list[tuple[float, float]] = []
    if cvss_score is not None:
        components.append((min(cvss_score, 10.0) / 10.0, CVSS_WEIGHT))
    if prevalence is not None:
        components.append((prevalence, PREVALENCE_WEIGHT))
    if epss is not None:
        components.append((epss, EPSS_WEIGHT))
    if not components:
        return None
    total_weight = sum(weight for _value, weight in components)
    return sum(value * weight for value, weight in components) / total_weight


def score_finding(finding: Finding) -> Finding:
    """Set ``risk_score`` (and, when intelligence exists, ``severity``) on a finding in place."""
    computed = risk_score(finding.cvss_score, finding.prevalence_score, finding.epss_score)
    if computed is None:
        finding.risk_score = SEVERITY_BASE_SCORE[finding.severity]
        return finding
    finding.risk_score = computed
    finding.severity = _max_severity(finding.severity, severity_for_score(computed))
    return finding


def _max_severity(module_severity: Severity, scored_severity: Severity) -> Severity:
    """Never let intelligence downgrade a module's own judgement, only raise it."""
    return (
        scored_severity
        if SEVERITY_BASE_SCORE[scored_severity] > SEVERITY_BASE_SCORE[module_severity]
        else module_severity
    )
