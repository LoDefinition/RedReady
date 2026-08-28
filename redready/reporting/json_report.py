"""Machine-readable JSON report."""

from __future__ import annotations

import json
from pathlib import Path

from redready import __version__
from redready.engine.result import ScanResult


def build_report(result: ScanResult) -> dict[str, object]:
    return {"redready_version": __version__, "scan": result.to_dict()}


def write_json_report(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"redready-{result.target_host}-{result.scan_id[:8]}.json"
    path.write_text(json.dumps(build_report(result), indent=2, sort_keys=False))
    return path
