from __future__ import annotations

import stat
from pathlib import Path

from sqlalchemy import create_engine, inspect

from redready.db.alembic_runner import upgrade_to_head
from redready.db.models import Base
from redready.db.session import Database
from redready.engine.result import Finding, RawData, ScanResult, new_id, utcnow


def _result() -> ScanResult:
    result = ScanResult(
        scan_id=new_id(),
        target_raw="example.com",
        target_host="example.com",
        target_type="domain",
        profile="default",
        started_at=utcnow(),
    )
    result.findings.append(
        Finding(
            scan_id=result.scan_id,
            module="dns",
            title="No SPF record published",
            description="d",
            severity="MEDIUM",
            remediation="Publish an SPF record.",
            risk_score=0.5,
        )
    )
    result.raw.append(
        RawData(
            module="banner",
            data_type="banner",
            host="example.com",
            port=22,
            data=b"SSH-2.0-OpenSSH_8.2p1",
        )
    )
    return result


def test_save_and_load_scan(db: Database) -> None:
    result = _result()
    db.save_scan(result)
    result.status = "completed"
    result.completed_at = utcnow()
    db.save_scan(result)  # a second save must update, not duplicate

    record = db.find_scan(result.scan_id[:8])
    assert record is not None
    assert record.status == "completed"

    findings = db.get_findings(record.id)
    assert len(findings) == 1
    assert findings[0].title == "No SPF record published"
    assert [s.id for s in db.list_scans()] == [result.scan_id]


def test_migrations_match_the_models(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    upgrade_to_head(url)
    engine = create_engine(url)
    try:
        tables = set(inspect(engine).get_table_names()) - {"alembic_version"}
    finally:
        engine.dispose()
    assert tables == set(Base.metadata.tables)


def test_sqlite_file_is_owner_only(db: Database) -> None:
    path = db.sqlite_path
    assert path is not None
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
