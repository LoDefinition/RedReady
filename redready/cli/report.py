"""``redready report`` — display and export findings from past scans."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from redready.cli.context import build_context
from redready.db.models import FindingRecord, ScanRecord
from redready.db.session import Database
from redready.engine.result import SEVERITY_ORDER, Finding, ScanResult, Severity
from redready.reporting.json_report import build_report
from redready.reporting.terminal import SEVERITY_STYLE, print_report

app = typer.Typer(help="Display and export scan reports.", no_args_is_help=True)


@app.command("show")
def show(
    scan_id: Annotated[str, typer.Argument(help="Scan UUID or unique prefix.")],
    severity: Annotated[
        list[str] | None,
        typer.Option("--severity", "-s", help="Only show these severities (repeatable)."),
    ] = None,
    detail: Annotated[
        bool, typer.Option("--detail", help="Print full descriptions and evidence.")
    ] = False,
) -> None:
    """Print a stored scan report."""
    context = build_context()
    result = _load(context.db, scan_id, context.console)
    if severity:
        wanted = {s.upper() for s in severity}
        result.findings = [f for f in result.findings if f.severity in wanted]
    print_report(result, console=context.console)
    if detail:
        _print_details(result, context.console)


@app.command("export")
def export(
    scan_id: Annotated[str, typer.Argument(help="Scan UUID or unique prefix.")],
    fmt: Annotated[str, typer.Option("--format", "-f", help="Export format: json.")] = "json",
    out: Annotated[Path, typer.Option("--out", help="Output directory.")] = Path(
        "./redready-reports"
    ),
) -> None:
    """Export a stored scan to a file."""
    context = build_context()
    if fmt != "json":
        context.console.print(f"[red]error:[/] unsupported export format: {fmt}")
        raise typer.Exit(code=2)
    result = _load(context.db, scan_id, context.console)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"redready-{result.target_host}-{result.scan_id[:8]}.json"
    path.write_text(json.dumps(build_report(result), indent=2))
    context.console.print(f"[green]written[/] {path}")


def _load(db: Database, scan_id: str, console: Console) -> ScanResult:
    record = db.find_scan(scan_id)
    if record is None:
        console.print(f"[red]error:[/] no scan matching {scan_id!r}")
        raise typer.Exit(code=1)
    return _to_result(record, db.get_findings(record.id))


def _to_result(record: ScanRecord, findings: list[FindingRecord]) -> ScanResult:
    result = ScanResult(
        scan_id=record.id,
        target_raw=record.target_raw,
        target_host=record.target_host,
        target_type=record.target_type,
        profile=record.profile,
        target_ip=record.target_ip,
        status=record.status,
        modules_run=list(record.modules_run or []),
        errors=list(record.errors or []),
        started_at=record.started_at,
        completed_at=record.completed_at,
    )
    result.findings = [_to_finding(f) for f in findings]
    return result


def _to_finding(record: FindingRecord) -> Finding:
    severity: Severity = record.severity if record.severity in SEVERITY_ORDER else "INFO"  # type: ignore[assignment]
    return Finding(
        id=record.id,
        scan_id=record.scan_id,
        module=record.module,
        title=record.title,
        description=record.description,
        severity=severity,
        remediation=record.remediation,
        risk_score=record.risk_score,
        cvss_score=record.cvss_score,
        cve_ids=list(record.cve_ids or []),
        cwe_ids=list(record.cwe_ids or []),
        attack_techniques=list(record.attack_techniques or []),
        sigma_rule_ids=list(record.sigma_rule_ids or []),
        atomic_tests=list(record.atomic_tests or []),
        elastic_rules=list(record.elastic_rules or []),
        prevalence_score=record.prevalence_score,
        epss_score=record.epss_score,
        references=list(record.reference_urls or []),
        evidence=record.evidence or "",
        port=record.port,
        service=record.service,
        raw_data_ids=list(record.raw_data_ids or []),
        created_at=record.created_at,
    )


def _print_details(result: ScanResult, console: Console) -> None:
    for finding in result.sorted_findings():
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_row("severity", f"[{SEVERITY_STYLE[finding.severity]}]{finding.severity}[/]")
        table.add_row("risk", f"{finding.risk_score:.2f}")
        if finding.cve_ids:
            table.add_row("cves", ", ".join(finding.cve_ids))
        if finding.port:
            table.add_row("port", str(finding.port))
        table.add_row("description", finding.description)
        if finding.evidence:
            table.add_row("evidence", finding.evidence)
        table.add_row("remediation", finding.remediation)
        console.print(f"\n[bold]{finding.title}[/]")
        console.print(table)
