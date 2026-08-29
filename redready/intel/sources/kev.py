"""CISA Known Exploited Vulnerabilities cache."""
from __future__ import annotations
from datetime import UTC, datetime
import httpx
from sqlalchemy import select
from redready.db.models import KevCatalog
from redready.db.session import Database

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

class KevSource:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def update(self, client: httpx.AsyncClient | None = None) -> int:
        owns = client is None
        active = client or httpx.AsyncClient(timeout=30.0)
        try:
            response = await active.get(KEV_URL)
            response.raise_for_status()
            ids = {item["cveID"] for item in response.json().get("vulnerabilities", []) if item.get("cveID")}
        finally:
            if owns:
                await active.aclose()
        now = datetime.now(UTC)
        with self._db.session() as session:
            existing = set(session.scalars(select(KevCatalog.cve_id)))
            for cve_id in ids - existing:
                session.add(KevCatalog(cve_id=cve_id, cached_at=now))
        return len(ids)

    def contains(self, cve_id: str) -> bool:
        with self._db.session() as session:
            return session.get(KevCatalog, cve_id) is not None
