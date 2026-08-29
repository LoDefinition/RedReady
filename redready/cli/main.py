"""``redready`` root command."""

from __future__ import annotations

import typer

from redready import __version__
from redready.cli import db as db_cli
from redready.cli import intel as intel_cli
from redready.cli import report as report_cli
from redready.cli.scan import profiles_command, scan_command

app = typer.Typer(
    help="RedReady — pre-engagement OPSEC validation and reconnaissance scanner.",
    no_args_is_help=True,
    add_completion=False,
)

app.command("scan")(scan_command)
app.command("profiles")(profiles_command)
app.add_typer(report_cli.app, name="report")
app.add_typer(db_cli.app, name="db")
app.add_typer(intel_cli.app, name="intel")


@app.command("version")
def version() -> None:
    """Print the installed RedReady version."""
    typer.echo(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
