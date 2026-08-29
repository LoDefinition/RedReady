"""``redready scan`` — run the module pipeline against one or more targets."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Any

import typer

from redready.cli.context import build_context, require_authorization
from redready.engine.orchestrator import Orchestrator
from redready.engine.profiles import load_profiles
from redready.engine.result import ScanResult
from redready.engine.target import TargetError, load_targets_file, normalize_target
from redready.reporting.json_report import write_json_report
from redready.reporting.terminal import TerminalReporter, print_report


def scan_command(
    target: Annotated[
        str | None,
        typer.Argument(help="Domain, IP, CIDR or URL to scan."),
    ] = None,
    targets_file: Annotated[
        Path | None,
        typer.Option("--targets-file", help="File with one target per line."),
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", "-p", help="Scan profile to use.")
    ] = None,
    disable: Annotated[
        list[str] | None, typer.Option("--disable", help="Disable a module (repeatable).")
    ] = None,
    only: Annotated[
        list[str] | None, typer.Option("--only", help="Run only these modules (repeatable).")
    ] = None,
    ports: Annotated[
        str | None, typer.Option("--ports", help="nmap port spec, e.g. 22,80,8000-8100.")
    ] = None,
    full_scan: Annotated[
        bool, typer.Option("--full-scan", help="Scan all 65535 TCP ports.")
    ] = False,
    output: Annotated[
        list[str] | None,
        typer.Option("--output", "-o", help="Output format: terminal or json (repeatable)."),
    ] = None,
    out_dir: Annotated[
        Path | None, typer.Option("--out", help="Directory for file reports.")
    ] = None,
    confirm_authorized: Annotated[
        bool,
        typer.Option("--confirm-authorized", help="Skip the interactive authorization prompt."),
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show INFO findings and skipped modules.")
    ] = False,
    db_url: Annotated[str | None, typer.Option("--db-url", help="Override the database URL.")] = (
        None
    ),
) -> None:
    """Scan a target and report prioritized findings."""
    context = build_context(db_url=db_url)
    console = context.console

    targets = _resolve_targets(target, targets_file)
    if not targets:
        console.print("[red]error:[/] provide a target or --targets-file")
        raise typer.Exit(code=2)

    require_authorization(console, context.settings, confirm_authorized)

    formats = [fmt.lower() for fmt in (output or context.settings.reporting.default_formats)]
    unknown = [fmt for fmt in formats if fmt not in ("terminal", "json")]
    if unknown:
        console.print(f"[red]error:[/] unsupported output format(s): {', '.join(unknown)}")
        raise typer.Exit(code=2)

    options: dict[str, Any] = {}
    if ports:
        options["ports"] = ports
    if full_scan:
        options["full_scan"] = True

    reporter = TerminalReporter(console=console, verbose=verbose)
    orchestrator = Orchestrator(context.settings, context.db)
    reporter.attach(orchestrator.bus)

    results: list[ScanResult] = []
    for raw_target in targets:
        try:
            normalized = normalize_target(raw_target)
        except TargetError as exc:
            console.print(f"[red]error:[/] {exc}")
            raise typer.Exit(code=2) from exc
        results.extend(
            asyncio.run(
                orchestrator.run(
                    normalized,
                    profile_name=profile,
                    disabled_modules=tuple(disable or ()),
                    enabled_modules=tuple(only or ()),
                    options=options,
                )
            )
        )

    directory = out_dir or context.settings.reporting.output_dir
    for result in results:
        if "terminal" in formats:
            print_report(result, console=console)
        if "json" in formats:
            path = write_json_report(result, directory)
            console.print(f"[green]JSON report written to[/] {path}")


def profiles_command() -> None:
    """List available scan profiles."""
    context = build_context()
    for profile in load_profiles().values():
        context.console.print(
            f"[bold]{profile.name:<12}[/] {profile.description} "
            f"[grey62](modules: {', '.join(profile.modules)})[/]"
        )


def _resolve_targets(target: str | None, targets_file: Path | None) -> list[str]:
    targets: list[str] = []
    if target:
        targets.append(target)
    if targets_file:
        targets.extend(load_targets_file(str(targets_file)))
    return targets
