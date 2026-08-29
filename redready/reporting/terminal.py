"""Rich terminal output: live event stream during the scan, summary tables afterwards."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from redready.engine import events
from redready.engine.events import Event, EventBus
from redready.engine.result import SEVERITY_ORDER, Finding, ScanResult

SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "dark_orange",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "grey62",
}


class TerminalReporter:
    """Subscribes to the event bus and streams scan progress to the console."""

    def __init__(self, console: Console | None = None, *, verbose: bool = False) -> None:
        self.console = console or Console()
        self.verbose = verbose

    def attach(self, bus: EventBus) -> None:
        bus.subscribe(events.SCAN_STARTED, self._on_scan_started)
        bus.subscribe(events.MODULE_STARTED, self._on_module_started)
        bus.subscribe(events.MODULE_COMPLETED, self._on_module_completed)
        bus.subscribe(events.MODULE_SKIPPED, self._on_module_skipped)
        bus.subscribe(events.MODULE_FAILED, self._on_module_failed)
        bus.subscribe(events.FINDING, self._on_finding)

    def _on_scan_started(self, event: Event) -> None:
        payload = event.payload
        self.console.print(
            Panel(
                Text.assemble(
                    ("target  ", "bold"),
                    f"{payload['host']}\n",
                    ("profile ", "bold"),
                    f"{payload['profile']}\n",
                    ("modules ", "bold"),
                    ", ".join(payload["modules"]),
                ),
                title=f"RedReady scan {payload['scan_id'][:8]}",
                border_style="red",
            )
        )

    def _on_module_started(self, event: Event) -> None:
        self.console.print(f"[bold cyan]▶[/] running [bold]{event.payload['module']}[/]")

    def _on_module_completed(self, event: Event) -> None:
        count = event.payload["finding_count"]
        self.console.print(f"[green]✔[/] {event.payload['module']} finished — {count} finding(s)")

    def _on_module_skipped(self, event: Event) -> None:
        if self.verbose:
            self.console.print(
                f"[grey62]‣ skipped {event.payload['module']}: {event.payload['reason']}[/]"
            )

    def _on_module_failed(self, event: Event) -> None:
        self.console.print(f"[red]✘[/] {event.payload['module']} failed: {event.payload['error']}")

    def _on_finding(self, event: Event) -> None:
        finding: Finding = event.payload["finding"]
        if finding.severity == "INFO" and not self.verbose:
            return
        style = SEVERITY_STYLE[finding.severity]
        suffix = " [backport?]" if finding.confidence == "possible" else ""
        self.console.print(f"  [{style}]{finding.severity:<8}[/] {finding.title}{suffix}")


def print_report(result: ScanResult, console: Console | None = None) -> None:
    """Print the post-scan summary: severity counts, findings table and remediation list."""
    console = console or Console()
    counts = result.severity_counts()

    summary = Table(title=f"Scan summary — {result.target_host}", title_justify="left")
    summary.add_column("Severity")
    summary.add_column("Count", justify="right")
    for severity in sorted(counts, key=lambda s: SEVERITY_ORDER[s]):
        summary.add_row(f"[{SEVERITY_STYLE[severity]}]{severity}[/]", str(counts[severity]))
    duration = result.duration_seconds
    summary.caption = (
        f"scan {result.scan_id} · {result.status} · "
        f"{duration:.1f}s · modules: {', '.join(result.modules_run) or 'none'}"
        if duration is not None
        else f"scan {result.scan_id} · {result.status}"
    )
    console.print(summary)

    findings = [f for f in result.sorted_findings() if f.severity != "INFO"]
    if findings:
        table = Table(title="Findings", title_justify="left", show_lines=False)
        table.add_column("Severity")
        table.add_column("Risk", justify="right")
        table.add_column("Port", justify="right")
        table.add_column("Module")
        table.add_column("Title", overflow="fold")
        for finding in findings:
            table.add_row(
                f"[{SEVERITY_STYLE[finding.severity]}]{finding.severity}[/]",
                f"{finding.risk_score:.2f}",
                str(finding.port or "-"),
                finding.module,
                finding.title + (" [backport?]" if finding.confidence == "possible" else ""),
            )
        console.print(table)

        console.print("\n[bold]Remediation[/]")
        for index, finding in enumerate(findings, start=1):
            console.print(f"  {index}. [bold]{finding.title}[/]\n     {finding.remediation}")
    else:
        console.print("[green]No findings above INFO severity.[/]")

    if result.errors:
        console.print("\n[bold yellow]Errors[/]")
        for error in result.errors:
            console.print(f"  · {error}")
