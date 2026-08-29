"""P0 CVE match confidence fields.

Revision ID: a13b8c4d9e20
Revises: 672e96a32312
Create Date: 2026-08-29
"""
from __future__ import annotations
from collections.abc import Sequence
import sqlalchemy as sa
from alembic import op

revision: str = "a13b8c4d9e20"
down_revision: str | None = "672e96a32312"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("confidence", sa.String(length=10), nullable=True))
        batch.add_column(sa.Column("cpe_match_source", sa.String(length=20), nullable=True))
        batch.add_column(sa.Column("cpe_match_confidence", sa.Float(), nullable=True))
        batch.add_column(sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table("kev_catalog", sa.Column("cve_id", sa.String(length=32), primary_key=True), sa.Column("cached_at", sa.DateTime(timezone=True), nullable=False))

def downgrade() -> None:
    op.drop_table("kev_catalog")
    with op.batch_alter_table("findings") as batch:
        batch.drop_column("kev")
        batch.drop_column("cpe_match_confidence")
        batch.drop_column("cpe_match_source")
        batch.drop_column("confidence")
