"""``redready db`` — scan history and schema management."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from redready.cli.context import build_context
from redready.db.alembic_runner import stamp_head, upgrade_to_head

app = typer.Typer(help="Inspect scan history and manage the database.", no_args_is_help=True)


@app.command("list")
def list_scans(
    limit: Annotated[int, typer.Option("--limit", "-n", help="Maximum rows to show.")] = 25,
) -> None:
    """List past scans, newest first."""
    context = build_context()
    table = Table(title="Scans", title_justify="left")
    for column in ("scan id", "target", "profile", "status", "started"):
        table.add_column(column)
    for record in context.db.list_scans(limit=limit):
        table.add_row(
            record.id[:8],
            record.target_host,
            record.profile,
            record.status,
            record.started_at.isoformat(timespec="seconds") if record.started_at else "-",
        )
    context.console.print(table)


@app.command("upgrade")
def upgrade() -> None:
    """Apply pending Alembic migrations."""
    context = build_context()
    upgrade_to_head(context.settings.database.url)
    context.console.print("[green]database is at head[/]")


@app.command("stamp")
def stamp() -> None:
    """Mark an existing database as being at the latest revision without running migrations."""
    context = build_context()
    stamp_head(context.settings.database.url)
    context.console.print("[green]database stamped at head[/]")


@app.command("path")
def path() -> None:
    """Print the resolved database URL."""
    context = build_context()
    context.console.print(context.db.url)
