"""Shared CLI wiring: settings, database, logging and the authorization gate."""

from __future__ import annotations

import logging
import stat
from dataclasses import dataclass
from pathlib import Path

import structlog
import typer
from rich.console import Console

from redready.config import USER_CONFIG_PATH, Settings, load_settings
from redready.db.session import Database

AUTHORIZATION_NOTICE = (
    "RedReady performs active network probing. Scanning systems you do not own or have written "
    "authorization to test is illegal in most jurisdictions."
)


@dataclass
class CliContext:
    settings: Settings
    db: Database
    console: Console


def build_context(*, db_url: str | None = None, log_level: str | None = None) -> CliContext:
    overrides: dict[str, object] = {}
    if db_url:
        overrides["database"] = {"url": db_url}
    if log_level:
        overrides["log_level"] = log_level

    settings = load_settings(overrides=overrides)
    _configure_logging(settings.log_level)
    console = Console()
    _warn_on_world_readable_config(console)

    db = Database.from_settings(settings)
    db.create_all()
    return CliContext(settings=settings, db=db, console=console)


def require_authorization(console: Console, settings: Settings, confirmed: bool) -> None:
    """Block the scan until the operator confirms they are authorized to test the target."""
    if confirmed or settings.scan.confirm_authorized:
        return
    console.print(f"[yellow]{AUTHORIZATION_NOTICE}[/]")
    if not typer.confirm("Do you have authorization to scan this target?", default=False):
        console.print("[red]Aborted.[/] Pass --confirm-authorized in automated contexts.")
        raise typer.Exit(code=2)


def _warn_on_world_readable_config(console: Console) -> None:
    path: Path = USER_CONFIG_PATH
    if not path.is_file():
        return
    mode = path.stat().st_mode
    if mode & (stat.S_IROTH | stat.S_IRGRP):
        console.print(
            f"[yellow]warning:[/] {path} holds API keys and is readable by other users "
            f"(mode {oct(mode & 0o777)}). Run: chmod 600 {path}"
        )


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, level.upper(), logging.INFO),
        force=True,
    )
    # httpx logs every request at INFO, which drowns out the scan output.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )
