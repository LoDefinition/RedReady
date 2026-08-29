from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from redready.cli.main import app
from redready.config import Settings
from redready.db.session import Database
from redready.engine.profiles import Profile
from redready.engine.result import Finding
from redready.modules import _REGISTRY
from redready.modules.base import BaseModule, ModuleInput, ModuleOutput

runner = CliRunner()


class DemoModule(BaseModule):
    name = "demo"
    description = "deterministic module for CLI tests"

    async def run(self, input: ModuleInput) -> ModuleOutput:  # noqa: A002
        return self.output(
            findings=[
                Finding(
                    module=self.name,
                    title="Telnet exposed on port 23",
                    description="Telnet transmits credentials in cleartext.",
                    severity="HIGH",
                    remediation="Disable telnet and use SSH.",
                    port=23,
                )
            ]
        )


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch, settings: Settings, tmp_path: Path) -> Path:
    monkeypatch.setitem(_REGISTRY, DemoModule.name, DemoModule)
    monkeypatch.setattr(
        "redready.engine.orchestrator.get_profile",
        lambda name: Profile(name="test", description="t", modules=("demo",)),
    )
    monkeypatch.setattr("redready.cli.context.load_settings", lambda **_: settings)
    return tmp_path


def test_scan_writes_terminal_and_json_reports(cli_env: Path, settings: Settings) -> None:
    out_dir = cli_env / "out"
    result = runner.invoke(
        app,
        ["scan", "example.com", "--confirm-authorized", "--out", str(out_dir)],
    )
    assert result.exit_code == 0, result.output
    assert "Telnet exposed on port 23" in result.output

    reports = list(out_dir.glob("redready-example.com-*.json"))
    assert len(reports) == 1
    payload = json.loads(reports[0].read_text())
    assert payload["scan"]["target"]["host"] == "example.com"
    assert payload["scan"]["findings"][0]["severity"] == "HIGH"
    assert payload["redready_version"]


def test_scan_requires_authorization(cli_env: Path) -> None:
    result = runner.invoke(app, ["scan", "example.com"], input="n\n")
    assert result.exit_code == 2
    assert "authorization" in result.output.lower()


def test_scan_rejects_invalid_target(cli_env: Path) -> None:
    result = runner.invoke(app, ["scan", "not a host", "--confirm-authorized"])
    assert result.exit_code == 2


def test_scan_requires_a_target(cli_env: Path) -> None:
    result = runner.invoke(app, ["scan", "--confirm-authorized"])
    assert result.exit_code == 2


def test_report_show_and_export(cli_env: Path, settings: Settings) -> None:
    scan = runner.invoke(
        app, ["scan", "example.com", "--confirm-authorized", "--output", "terminal"]
    )
    assert scan.exit_code == 0, scan.output

    db = Database.from_settings(settings)
    scan_id = db.list_scans()[0].id

    shown = runner.invoke(app, ["report", "show", scan_id[:8], "--detail"])
    assert shown.exit_code == 0, shown.output
    assert "Telnet exposed on port 23" in shown.output

    filtered = runner.invoke(app, ["report", "show", scan_id[:8], "--severity", "CRITICAL"])
    assert filtered.exit_code == 0
    assert "No findings above INFO severity" in filtered.output

    out_dir = cli_env / "exported"
    exported = runner.invoke(app, ["report", "export", scan_id[:8], "--out", str(out_dir)])
    assert exported.exit_code == 0, exported.output
    assert len(list(out_dir.glob("*.json"))) == 1

    missing = runner.invoke(app, ["report", "show", "deadbeef"])
    assert missing.exit_code == 1


def test_db_list_and_intel_status(cli_env: Path) -> None:
    runner.invoke(app, ["scan", "example.com", "--confirm-authorized", "-o", "terminal"])
    listed = runner.invoke(app, ["db", "list"])
    assert listed.exit_code == 0
    assert "example.com" in listed.output

    status = runner.invoke(app, ["intel", "status"])
    assert status.exit_code == 0
    assert "nvd" in status.output


def test_version_and_profiles(cli_env: Path) -> None:
    version = runner.invoke(app, ["version"])
    assert version.exit_code == 0
    assert version.output.strip()

    profiles = runner.invoke(app, ["profiles"])
    assert profiles.exit_code == 0
    assert "default" in profiles.output
