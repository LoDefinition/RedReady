"""NVD/CVE feed ingestion and lookup against the local cache."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog
from sqlalchemy import delete, func, select

from redready.db.models import CpeIndex, CveCache, IntelSourceState
from redready.db.session import Database
from redready.intel.sources.version import encode_bound, version_in_range

log = structlog.get_logger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
#: The NVD API rejects lastModStartDate windows wider than 120 days.
MAX_WINDOW_DAYS = 120
#: NVD asks unauthenticated clients for 6s between requests; API keys allow much faster polling.
UNAUTHENTICATED_DELAY = 6.0
AUTHENTICATED_DELAY = 0.6

SOURCE_NAME = "nvd"


@dataclass(frozen=True)
class CveMatch:
    cve_id: str
    cvss_score: float | None
    severity: str | None
    description: str
    cwe_ids: list[str]
    references: list[str]


class NvdSource:
    """Maintains the local CVE cache and answers ``(vendor, product, version)`` lookups."""

    name = SOURCE_NAME

    def __init__(self, db: Database, api_key: str = "") -> None:
        self._db = db
        self._api_key = api_key

    async def update(self, *, days: int = 30, client: httpx.AsyncClient | None = None) -> int:
        """Ingest every CVE modified in the last ``days`` days. Returns the number cached."""
        if days > MAX_WINDOW_DAYS:
            raise ValueError(f"NVD accepts at most a {MAX_WINDOW_DAYS} day window, got {days}")

        owns_client = client is None
        client = client or httpx.AsyncClient(timeout=60.0)
        headers = {"apiKey": self._api_key} if self._api_key else {}
        delay = AUTHENTICATED_DELAY if self._api_key else UNAUTHENTICATED_DELAY

        end = datetime.now(UTC)
        start = end - timedelta(days=days)
        params: dict[str, Any] = {
            "lastModStartDate": _nvd_timestamp(start),
            "lastModEndDate": _nvd_timestamp(end),
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": 0,
        }

        total_cached = 0
        try:
            while True:
                response = await client.get(NVD_API_URL, params=params, headers=headers)
                response.raise_for_status()
                payload = response.json()
                vulnerabilities = payload.get("vulnerabilities", [])
                if not vulnerabilities:
                    break
                total_cached += self._store(vulnerabilities)

                params["startIndex"] += len(vulnerabilities)
                if params["startIndex"] >= payload.get("totalResults", 0):
                    break
                await asyncio.sleep(delay)
        finally:
            if owns_client:
                await client.aclose()

        self._record_state(total_cached, f"last {days} days")
        return total_cached

    def _store(self, vulnerabilities: list[dict[str, Any]]) -> int:
        stored = 0
        with self._db.session() as session:
            for item in vulnerabilities:
                cve = item.get("cve")
                if not cve:
                    continue
                cve_id = cve["id"]
                metrics = _primary_metric(cve.get("metrics", {}))
                record = session.get(CveCache, cve_id) or CveCache(cve_id=cve_id)
                record.cvss_score = metrics[0]
                record.severity = metrics[1]
                record.description = _english_description(cve.get("descriptions", []))
                record.cwe_ids = _cwe_ids(cve.get("weaknesses", []))
                record.reference_urls = [
                    ref["url"] for ref in cve.get("references", []) if ref.get("url")
                ][:20]
                record.published_date = _parse_datetime(cve.get("published"))
                record.modified_date = _parse_datetime(cve.get("lastModified"))
                record.cached_at = datetime.now(UTC)

                matches = list(_cpe_matches(cve.get("configurations", [])))
                record.cpe_matches = [m["criteria"] for m in matches]
                session.merge(record)

                session.execute(delete(CpeIndex).where(CpeIndex.cve_id == cve_id))
                for match in matches:
                    session.add(CpeIndex(cve_id=cve_id, **_index_row(match)))
                stored += 1
        return stored

    def _record_state(self, count: int, detail: str) -> None:
        with self._db.session() as session:
            state = session.get(IntelSourceState, SOURCE_NAME) or IntelSourceState(
                source=SOURCE_NAME
            )
            state.last_updated = datetime.now(UTC)
            state.record_count = session.scalar(select(func.count()).select_from(CveCache)) or count
            state.detail = detail
            session.merge(state)

    def lookup(self, vendor: str, product: str, version: str) -> list[CveMatch]:
        """Return cached CVEs whose CPE ranges cover this product version.

        The vendor is only used to narrow ties: banner strings routinely disagree with NVD's
        vendor naming (OpenSSH is published under the ``openbsd`` vendor), so a product+version
        match on its own is accepted.
        """
        product = product.lower()
        vendor = vendor.lower()
        with self._db.session() as session:
            rows = list(session.scalars(select(CpeIndex).where(CpeIndex.product == product)))
            if any(row.vendor == vendor for row in rows):
                rows = [row for row in rows if row.vendor == vendor]
            matching_ids = {
                row.cve_id
                for row in rows
                if version_in_range(
                    version,
                    exact=row.version_exact,
                    start_including=row.version_start,
                    end_excluding=row.version_end,
                )
            }
            if not matching_ids:
                return []
            cves = session.scalars(select(CveCache).where(CveCache.cve_id.in_(matching_ids)))
            return [
                CveMatch(
                    cve_id=cve.cve_id,
                    cvss_score=cve.cvss_score,
                    severity=cve.severity,
                    description=cve.description or "",
                    cwe_ids=list(cve.cwe_ids or []),
                    references=list(cve.reference_urls or []),
                )
                for cve in cves
            ]

    def status(self) -> IntelSourceState | None:
        with self._db.session() as session:
            return session.get(IntelSourceState, SOURCE_NAME)


def _index_row(match: dict[str, Any]) -> dict[str, str | None]:
    parts = match["criteria"].split(":")
    vendor = parts[3] if len(parts) > 3 else "*"
    product = parts[4] if len(parts) > 4 else "*"
    cpe_version = parts[5] if len(parts) > 5 else "*"

    start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
    end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
    return {
        "vendor": vendor.lower(),
        "product": product.lower(),
        "version_exact": None if cpe_version in ("*", "-") else cpe_version,
        "version_start": (
            encode_bound(start, inclusive="versionStartIncluding" in match) if start else None
        ),
        "version_end": (
            encode_bound(end, inclusive="versionEndIncluding" in match) if end else None
        ),
    }


def _cpe_matches(configurations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for configuration in configurations:
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and match.get("criteria"):
                    matches.append(match)
    return matches


def _primary_metric(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
        return (float(score) if score is not None else None, severity)
    return None, None


def _english_description(descriptions: list[dict[str, Any]]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return str(description.get("value", ""))
    return ""


def _cwe_ids(weaknesses: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    for weakness in weaknesses:
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value.startswith("CWE-") and value not in ids:
                ids.append(value)
    return ids


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _nvd_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000")
