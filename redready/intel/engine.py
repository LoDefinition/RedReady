"""Correlates recon findings against the intelligence sources and scores everything."""

from __future__ import annotations

from typing import Any

import structlog

from redready.config import Settings
from redready.db.session import Database
from redready.engine.result import Finding, Severity
from redready.intel.scorer import score_finding
from redready.intel.sources.nvd import CveMatch, NvdSource
from redready.intel.sources.cpe_dict import canonicalize
from redready.intel.sources.distro import detect_distro_context
from redready.intel.sources.kev import KevSource

log = structlog.get_logger(__name__)

#: Cap on CVEs reported per identified service, highest CVSS first.
MAX_CVES_PER_SERVICE = 25


class IntelEngine:
    def __init__(self, db: Database, settings: Settings) -> None:
        self._settings = settings
        self.nvd = NvdSource(db, api_key=settings.intel.nvd_api_key)
        self.kev = KevSource(db)

    def correlate(self, findings: list[Finding], metadata: dict[str, Any]) -> list[Finding]:
        """Produce CVE findings for every identified service version, then score everything.

        Returns only the newly created findings; the input findings are scored in place.
        """
        new_findings: list[Finding] = []
        for service in metadata.get("service_versions", []):
            canonical = canonicalize(service["vendor"], service["product"], service.get("nmap_cpe"))
            if canonical is None:
                continue
            matches = self.nvd.lookup(canonical.vendor, canonical.product, service["version"])
            candidates = _cve_findings(service, matches, canonical.source, canonical.confidence, self.kev)
            for finding in candidates:
                score_finding(finding)
            new_findings.extend(sorted(candidates, key=lambda finding: -finding.risk_score)[:MAX_CVES_PER_SERVICE])

        for finding in [*findings, *new_findings]:
            score_finding(finding)
        return new_findings


def _cve_findings(service: dict[str, str], matches: list[CveMatch], source: str, match_confidence: float, kev_source: KevSource) -> list[Finding]:
    port = int(service["port"]) if service.get("port") else None
    product = f"{service['product']} {service['version']}"
    distro = detect_distro_context(service.get("raw_banner", service.get("version", "")), product)
    return [
        Finding(
            module="vuln_intel",
            title=f"{match.cve_id} affects {product}",
            description=(
                f"{product} on port {port} matches the affected version range of "
                f"{match.cve_id}. {match.description}"
            ).strip() + (f"\n\nBackport caveat: {distro.caveat}" if distro.detected else ""),
            severity=_severity_from_nvd(match.severity),
            confidence=distro.confidence,
            cpe_match_source=source,
            cpe_match_confidence=match_confidence,
            kev=kev_source.contains(match.cve_id),
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
