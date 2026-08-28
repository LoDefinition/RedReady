"""``redready intel`` — manage the local vulnerability intelligence cache."""

from __future__ import annotations

import asyncio
from typing import Annotated

import httpx
import typer
from rich.table import Table

from redready.cli.context import build_context
from redready.intel.sources.nvd import MAX_WINDOW_DAYS, NvdSource

app = typer.Typer(help="Manage vulnerability intelligence sources.", no_args_is_help=True)


@app.command("update")
def update(
    days: Annotated[
        int,
        typer.Option(
            "--days", help=f"Ingest CVEs modified in the last N days (max {MAX_WINDOW_DAYS})."
        ),
    ] = 30,
) -> None:
    """Pull recent CVEs from NVD into the local cache."""
    context = build_context()
    source = NvdSource(context.db, api_key=context.settings.intel.nvd_api_key)
    if not context.settings.intel.nvd_api_key:
        context.console.print(
            "[yellow]note:[/] no NVD API key configured — requests are rate limited to one per "
            "6 seconds. Set intel.nvd_api_key or REDREADY_INTEL__NVD_API_KEY to speed this up."
        )
    context.console.print(f"Fetching CVEs modified in the last {days} days…")
    try:
        count = asyncio.run(source.update(days=days))
    except httpx.HTTPError as exc:
        context.console.print(f"[red]error:[/] NVD request failed: {exc}")
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        context.console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    context.console.print(f"[green]cached {count} CVEs[/]")


@app.command("status")
def status() -> None:
    """Show intelligence source freshness."""
    context = build_context()
    source = NvdSource(context.db, api_key=context.settings.intel.nvd_api_key)
    state = source.status()
    table = Table(title="Intelligence sources", title_justify="left")
    for column in ("source", "records", "last updated", "detail"):
        table.add_column(column)
    table.add_row(
        "nvd",
        str(state.record_count) if state else "0",
        state.last_updated.isoformat(timespec="seconds")
        if state and state.last_updated
        else "never",
        (state.detail if state and state.detail else "run `redready intel update`"),
    )
    context.console.print(table)
