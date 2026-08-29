"""SQLAlchemy models.

JSON-shaped columns use SQLAlchemy's ``JSON`` type so the same models work on SQLite (local) and
PostgreSQL (cloud/paid tier) without translation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from redready.engine.result import new_id, utcnow


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_raw: Mapped[str] = mapped_column(Text, nullable=False)
    target_host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_ip: Mapped[str | None] = mapped_column(String(45))
    target_type: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    profile: Mapped[str] = mapped_column(String(32), nullable=False, default="default")
    modules_run: Mapped[list[str]] = mapped_column(JSON, default=list)
    errors: Mapped[list[str]] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    user_id: Mapped[str | None] = mapped_column(String(36))
    notes: Mapped[str | None] = mapped_column(Text)

    findings: Mapped[list[FindingRecord]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    raw_data: Mapped[list[RawDataRecord]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    module: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cve_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    cwe_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    attack_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    sigma_rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    atomic_tests: Mapped[list[str]] = mapped_column(JSON, default=list)
    elastic_rules: Mapped[list[str]] = mapped_column(JSON, default=list)
    prevalence_score: Mapped[float | None] = mapped_column(Float)
    epss_score: Mapped[float | None] = mapped_column(Float)
    confidence: Mapped[str | None] = mapped_column(String(10))
    cpe_match_source: Mapped[str | None] = mapped_column(String(20))
    cpe_match_confidence: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(default=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    # `references` is reserved in some SQL dialects, so the column is named `reference_urls`.
    reference_urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence: Mapped[str | None] = mapped_column(Text)
    port: Mapped[int | None] = mapped_column(Integer)
    service: Mapped[str | None] = mapped_column(String(64))
    raw_data_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[ScanRecord] = relationship(back_populates="findings")


class RawDataRecord(Base):
    __tablename__ = "raw_data"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    module: Mapped[str] = mapped_column(String(32), nullable=False)
    data_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    host: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16))
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[ScanRecord] = relationship(back_populates="raw_data")


class CveCache(Base):
    __tablename__ = "cve_cache"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str | None] = mapped_column(String(16))
    description: Mapped[str | None] = mapped_column(Text)
    cpe_matches: Mapped[list[str]] = mapped_column(JSON, default=list)
    cwe_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    reference_urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    published_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CpeIndex(Base):
    """Flattened ``(vendor, product)`` → CVE index, so lookups avoid scanning JSON columns."""

    __tablename__ = "cpe_index"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vendor: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    product: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version_start: Mapped[str | None] = mapped_column(String(64))
    version_end: Mapped[str | None] = mapped_column(String(64))
    version_exact: Mapped[str | None] = mapped_column(String(64))
    cve_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("cve_cache.cve_id", ondelete="CASCADE"), nullable=False, index=True
    )


class IntelSourceState(Base):
    """Last-update bookkeeping per intelligence source, surfaced by ``redready intel status``."""

    __tablename__ = "intel_source_state"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_updated: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[str | None] = mapped_column(Text)


class KevCatalog(Base):
    __tablename__ = "kev_catalog"
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
