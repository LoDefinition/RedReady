"""Database session factory and scan persistence helpers."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from redready.config import Settings
from redready.db.models import Base, FindingRecord, RawDataRecord, ScanRecord
from redready.engine.result import Finding, ScanResult

SQLITE_PREFIX = "sqlite:///"
#: Scan data contains banners and raw responses, so the local DB is owner-readable only.
DB_FILE_MODE = 0o600


class Database:
    """Owns the SQLAlchemy engine and exposes scan-level persistence operations."""

    def __init__(self, url: str) -> None:
        self.url = _expand_sqlite_path(url)
        self.engine: Engine = create_engine(self.url, future=True)
        self._session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)

    @classmethod
    def from_settings(cls, settings: Settings) -> Database:
        return cls(settings.database.url)

    @property
    def sqlite_path(self) -> Path | None:
        if not self.url.startswith(SQLITE_PREFIX):
            return None
        return Path(self.url[len(SQLITE_PREFIX) :])

    def create_all(self) -> None:
        """Create the schema for a fresh database and lock down the SQLite file."""
        path = self.sqlite_path
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
        Base.metadata.create_all(self.engine)
        if path is not None and path.exists():
            os.chmod(path, DB_FILE_MODE)

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_scan(self, result: ScanResult) -> None:
        """Persist a scan and everything it produced. Findings are never updated in place."""
        with self.session() as session:
            record = session.get(ScanRecord, result.scan_id)
            if record is None:
                record = ScanRecord(id=result.scan_id)
                session.add(record)
            record.target_raw = result.target_raw
            record.target_host = result.target_host
            record.target_ip = result.target_ip
            record.target_type = result.target_type
            record.status = result.status
            record.profile = result.profile
            record.modules_run = list(result.modules_run)
            record.errors = list(result.errors)
            record.started_at = result.started_at
            record.completed_at = result.completed_at

            existing_findings = set(
                session.scalars(
                    select(FindingRecord.id).where(FindingRecord.scan_id == result.scan_id)
                )
            )
            for finding in result.findings:
                if finding.id in existing_findings:
                    continue
                session.add(_finding_record(result.scan_id, finding))

            existing_raw = set(
                session.scalars(
                    select(RawDataRecord.id).where(RawDataRecord.scan_id == result.scan_id)
                )
            )
            for raw in result.raw:
                if raw.id in existing_raw:
                    continue
                session.add(
                    RawDataRecord(
                        id=raw.id,
                        scan_id=result.scan_id,
                        module=raw.module,
                        data_type=raw.data_type,
                        host=raw.host,
                        port=raw.port,
                        protocol=raw.protocol,
                        data=raw.data,
                        meta=raw.metadata,
                        captured_at=raw.captured_at,
                    )
                )

    def list_scans(self, limit: int = 50) -> list[ScanRecord]:
        with self.session() as session:
            return list(
                session.scalars(
                    select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit)
                )
            )

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        with self.session() as session:
            return session.get(ScanRecord, scan_id)

    def find_scan(self, scan_id_prefix: str) -> ScanRecord | None:
        """Look a scan up by full UUID or unique prefix, the way ``git`` resolves short SHAs."""
        with self.session() as session:
            exact = session.get(ScanRecord, scan_id_prefix)
            if exact is not None:
                return exact
            matches = list(
                session.scalars(
                    select(ScanRecord).where(ScanRecord.id.like(f"{scan_id_prefix}%")).limit(2)
                )
            )
            if len(matches) == 1:
                return matches[0]
            return None

    def get_findings(self, scan_id: str) -> list[FindingRecord]:
        with self.session() as session:
            return list(
                session.scalars(select(FindingRecord).where(FindingRecord.scan_id == scan_id))
            )


def _finding_record(scan_id: str, finding: Finding) -> FindingRecord:
    return FindingRecord(
        id=finding.id,
        scan_id=scan_id,
        module=finding.module,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        risk_score=finding.risk_score,
        cvss_score=finding.cvss_score,
        cve_ids=finding.cve_ids,
        cwe_ids=finding.cwe_ids,
        attack_techniques=finding.attack_techniques,
        sigma_rule_ids=finding.sigma_rule_ids,
        atomic_tests=finding.atomic_tests,
        elastic_rules=finding.elastic_rules,
        prevalence_score=finding.prevalence_score,
        epss_score=finding.epss_score,
        remediation=finding.remediation,
        reference_urls=finding.references,
        evidence=finding.evidence,
        port=finding.port,
        service=finding.service,
        raw_data_ids=finding.raw_data_ids,
        created_at=finding.created_at,
    )


def _expand_sqlite_path(url: str) -> str:
    if not url.startswith(SQLITE_PREFIX):
        return url
    raw_path = url[len(SQLITE_PREFIX) :]
    if raw_path in ("", ":memory:"):
        return url
    return SQLITE_PREFIX + str(Path(raw_path).expanduser())
