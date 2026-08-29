from __future__ import annotations

import asyncio
from typing import Any

import httpx

from redready.config import Settings
from redready.db.session import Database
from redready.intel.engine import IntelEngine
from redready.intel.sources.nvd import NvdSource

CVE_ITEM: dict[str, Any] = {
    "cve": {
        "id": "CVE-2020-15778",
        "published": "2020-07-24T22:15:00.000",
        "lastModified": "2023-11-07T03:18:00.000",
        "descriptions": [
            {"lang": "en", "value": "scp in OpenSSH allows command injection."},
            {"lang": "es", "value": "ignored"},
        ],
        "metrics": {
            "cvssMetricV31": [
                {"type": "Primary", "cvssData": {"baseScore": 7.8, "baseSeverity": "HIGH"}}
            ]
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
        "references": [{"url": "https://example.test/advisory"}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "8.0",
                                "versionEndExcluding": "8.4",
                            }
                        ]
                    }
                ]
            }
        ],
    }
}


def _client(payload: dict[str, Any]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_update_caches_cves_and_records_state(db: Database) -> None:
    source = NvdSource(db)
    payload = {"vulnerabilities": [CVE_ITEM], "totalResults": 1}

    async def run() -> int:
        async with _client(payload) as client:
            return await source.update(days=7, client=client)

    assert asyncio.run(run()) == 1

    state = source.status()
    assert state is not None
    assert state.record_count == 1

    matches = source.lookup("openbsd", "openssh", "8.2p1")
    assert [m.cve_id for m in matches] == ["CVE-2020-15778"]
    assert matches[0].cvss_score == 7.8
    assert matches[0].cwe_ids == ["CWE-78"]
    assert source.lookup("openbsd", "openssh", "8.4") == []


def test_update_is_idempotent(db: Database) -> None:
    source = NvdSource(db)
    payload = {"vulnerabilities": [CVE_ITEM], "totalResults": 1}

    async def run() -> None:
        async with _client(payload) as client:
            await source.update(days=7, client=client)
            await source.update(days=7, client=client)

    asyncio.run(run())
    assert len(source.lookup("openbsd", "openssh", "8.2p1")) == 1


def test_engine_correlates_service_versions(db: Database, settings: Settings) -> None:
    source = NvdSource(db)

    async def run() -> None:
        async with _client({"vulnerabilities": [CVE_ITEM], "totalResults": 1}) as client:
            await source.update(days=7, client=client)

    asyncio.run(run())

    engine = IntelEngine(db, settings)
    findings = engine.correlate(
        [],
        {
            "service_versions": [
                {
                    "port": "22",
                    "service": "ssh",
                    "vendor": "openbsd",
                    "product": "openssh",
                    "version": "8.2p1",
                    "cpe": "cpe:2.3:a:openbsd:openssh:8.2p1",
                }
            ]
        },
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.cve_ids == ["CVE-2020-15778"]
    assert finding.port == 22
    assert finding.risk_score > 0
