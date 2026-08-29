"""Canonical result types shared by every module, the intel engine and all reporters."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

#: Lower bound of the RiskScore band for each severity, per spec section 8.3.
SEVERITY_THRESHOLDS: tuple[tuple[float, Severity], ...] = (
    (0.80, "CRITICAL"),
    (0.60, "HIGH"),
    (0.40, "MEDIUM"),
    (0.20, "LOW"),
    (0.00, "INFO"),
)

#: Fallback RiskScore for findings that carry no CVSS/prevalence/EPSS input.
SEVERITY_BASE_SCORE: dict[Severity, float] = {
    "CRITICAL": 0.9,
    "HIGH": 0.7,
    "MEDIUM": 0.5,
    "LOW": 0.3,
    "INFO": 0.1,
}


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


def severity_for_score(score: float) -> Severity:
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return "INFO"


@dataclass
class RawData:
    """Unprocessed bytes captured during scanning. Never discarded, never rewritten."""

    module: str
    data_type: str
    data: bytes
    id: str = field(default_factory=new_id)
    host: str | None = None
    port: int | None = None
    protocol: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    captured_at: datetime = field(default_factory=utcnow)


@dataclass
class Finding:
    """A structured, scored observation. Immutable once persisted."""

    module: str
    title: str
    description: str
    severity: Severity
    remediation: str
    id: str = field(default_factory=new_id)
    scan_id: str | None = None
    risk_score: float = 0.0
    cvss_score: float | None = None
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    sigma_rule_ids: list[str] = field(default_factory=list)
    atomic_tests: list[str] = field(default_factory=list)
    elastic_rules: list[str] = field(default_factory=list)
    prevalence_score: float | None = None
    epss_score: float | None = None
    references: list[str] = field(default_factory=list)
    evidence: str = ""
    port: int | None = None
    service: str | None = None
    raw_data_ids: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "module": self.module,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "risk_score": round(self.risk_score, 4),
            "cvss_score": self.cvss_score,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "attack_techniques": self.attack_techniques,
            "sigma_rule_ids": self.sigma_rule_ids,
            "atomic_tests": self.atomic_tests,
            "elastic_rules": self.elastic_rules,
            "prevalence_score": self.prevalence_score,
            "epss_score": self.epss_score,
            "remediation": self.remediation,
            "references": self.references,
            "evidence": self.evidence,
            "port": self.port,
            "service": self.service,
            "raw_data_ids": self.raw_data_ids,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class ScanResult:
    """Everything produced by one execution of the pipeline against one host."""

    scan_id: str
    target_raw: str
    target_host: str
    target_type: str
    profile: str
    target_ip: str | None = None
    status: str = "pending"
    modules_run: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    raw: list[RawData] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at is None or self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    def severity_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER[f.severity], -f.risk_score, f.title),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": {
                "raw": self.target_raw,
                "host": self.target_host,
                "ip": self.target_ip,
                "type": self.target_type,
            },
            "profile": self.profile,
            "status": self.status,
            "modules_run": self.modules_run,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "severity_counts": self.severity_counts(),
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
