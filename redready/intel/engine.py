"""Correlates recon findings against the intelligence sources and scores everything."""

from __future__ import annotations

from typing import Any

import structlog

from redready.config import Settings
from redready.db.session import Database
from redready.engine.result import Finding, Severity
from redready.intel.scorer import score_finding
from redready.intel.sources.nvd import CveMatch, NvdSource

log = structlog.get_logger(__name__)

#: Cap on CVEs reported per identified service, highest CVSS first.
MAX_CVES_PER_SERVICE = 25


class IntelEngine:
    def __init__(self, db: Database, settings: Settings) -> None:
        self._settings = settings
        self.nvd = NvdSource(db, api_key=settings.intel.nvd_api_key)

    def correlate(self, findings: list[Finding], metadata: dict[str, Any]) -> list[Finding]:
        """Produce CVE findings for every identified service version, then score everything.

        Returns only the newly created findings; the input findings are scored in place.
        """
        new_findings: list[Finding] = []
        for service in metadata.get("service_versions", []):
            matches = self.nvd.lookup(service["vendor"], service["product"], service["version"])
            if not matches:
                continue
            ranked = sorted(matches, key=lambda m: -(m.cvss_score or 0.0))[:MAX_CVES_PER_SERVICE]
            new_findings.extend(_cve_findings(service, ranked))

        for finding in [*findings, *new_findings]:
            score_finding(finding)
        return new_findings


def _cve_findings(service: dict[str, str], matches: list[CveMatch]) -> list[Finding]:
    port = int(service["port"]) if service.get("port") else None
    product = f"{service['product']} {service['version']}"
    return [
        Finding(
            module="vuln_intel",
            title=f"{match.cve_id} affects {product}",
            description=(
                f"{product} on port {port} matches the affected version range of "
                f"{match.cve_id}. {match.description}"
            ).strip(),
            severity=_severity_from_nvd(match.severity),
            remediation=(
                f"Upgrade {service['product']} beyond {service['version']}, or apply the vendor "
                f"patch referenced by {match.cve_id}. If patching is not possible, restrict "
                "network access to the service."
            ),
            cvss_score=match.cvss_score,
            cve_ids=[match.cve_id],
            cwe_ids=match.cwe_ids,
            references=match.references,
            evidence=f"{service['cpe']} (banner-derived)",
            port=port,
            service=service.get("service"),
        )
        for match in matches
    ]


def _severity_from_nvd(severity: str | None) -> Severity:
    mapping: dict[str, Severity] = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }
    return mapping.get((severity or "").upper(), "INFO")
