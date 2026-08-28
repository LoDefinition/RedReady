"""Scan orchestration: runs the module pipeline in dependency order and correlates intel.

The orchestrator is instantiated per scan and holds no global state. Config and the database are
injected by the caller (CLI today, API later).
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from redready.config import Settings
from redready.db.session import Database
from redready.engine import events
from redready.engine.events import EventBus
from redready.engine.profiles import Profile, get_profile
from redready.engine.result import Finding, ScanResult, new_id, utcnow
from redready.engine.target import NormalizedTarget, normalize_target
from redready.intel.engine import IntelEngine
from redready.modules import get_module
from redready.modules.base import BaseModule, ModuleInput, ModuleOutput

log = structlog.get_logger(__name__)

INTEL_MODULE = "vuln_intel"


class Orchestrator:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        *,
        bus: EventBus | None = None,
        intel: IntelEngine | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.bus = bus or EventBus()
        self.intel = intel if intel is not None else IntelEngine(db, settings)

    async def run(
        self,
        target: str | NormalizedTarget,
        *,
        profile_name: str | None = None,
        disabled_modules: tuple[str, ...] = (),
        enabled_modules: tuple[str, ...] = (),
        options: dict[str, Any] | None = None,
    ) -> list[ScanResult]:
        """Scan a target, expanding a CIDR into one scan record per host."""
        normalized = normalize_target(target) if isinstance(target, str) else target
        profile = get_profile(profile_name or self.settings.scan.default_profile)
        module_names = _select_modules(profile, enabled_modules, disabled_modules)

        results = []
        for host in normalized.hosts:
            results.append(
                await self._run_host(normalized, host, profile, module_names, options or {})
            )
        return results

    async def _run_host(
        self,
        target: NormalizedTarget,
        host: str,
        profile: Profile,
        module_names: list[str],
        cli_options: dict[str, Any],
    ) -> ScanResult:
        result = ScanResult(
            scan_id=new_id(),
            target_raw=target.raw,
            target_host=host,
            target_type=target.type,
            profile=profile.name,
            status="running",
            started_at=utcnow(),
        )
        self.db.save_scan(result)
        await self.bus.publish(
            events.SCAN_STARTED,
            scan_id=result.scan_id,
            host=host,
            profile=profile.name,
            modules=module_names,
        )

        metadata: dict[str, Any] = dict(target.__dict__)
        metadata["ports"] = [target.port] if target.port else []
        options = {**profile.options, **cli_options}
        timeout = self.settings.scan.timeout_per_module

        for name in module_names:
            module = get_module(name)()
            module_input = ModuleInput(
                target=target.raw,
                host=host,
                ip=metadata.get("ip"),
                ports=list(metadata.get("ports", [])),
                metadata=metadata,
                settings=self.settings,
                options=options,
            )
            output = await self._run_module(module, module_input, result, timeout_s=timeout)
            if output is None:
                continue
            metadata.update(output.metadata)
            result.modules_run.append(name)
            await self._collect(result, output.findings, output.raw)
            await self.bus.publish(
                events.MODULE_COMPLETED,
                scan_id=result.scan_id,
                module=name,
                finding_count=len(output.findings),
            )

        await self._run_intel(result, metadata)

        result.status = "complete"
        result.completed_at = utcnow()
        self.db.save_scan(result)
        await self.bus.publish(
            events.SCAN_COMPLETED,
            scan_id=result.scan_id,
            summary=result.severity_counts(),
            duration=result.duration_seconds,
        )
        return result

    async def _run_module(
        self,
        module: BaseModule,
        module_input: ModuleInput,
        result: ScanResult,
        timeout_s: int,
    ) -> ModuleOutput | None:
        missing = [r for r in module.requires if r not in result.modules_run]
        if missing:
            await self.bus.publish(
                events.MODULE_SKIPPED,
                scan_id=result.scan_id,
                module=module.name,
                reason=f"requires {', '.join(missing)}",
            )
            return None
        try:
            if not await module.is_applicable(module_input):
                await self.bus.publish(
                    events.MODULE_SKIPPED,
                    scan_id=result.scan_id,
                    module=module.name,
                    reason="preconditions not met",
                )
                return None
        except Exception as exc:  # noqa: BLE001 - applicability must never abort a scan
            result.errors.append(f"{module.name}: applicability check failed: {exc}")
            return None

        await self.bus.publish(events.MODULE_STARTED, scan_id=result.scan_id, module=module.name)
        try:
            output = await asyncio.wait_for(module.run(module_input), timeout=timeout_s)
        except TimeoutError:
            message = f"{module.name}: timed out after {timeout_s}s"
            result.errors.append(message)
            await self.bus.publish(
                events.MODULE_FAILED, scan_id=result.scan_id, module=module.name, error=message
            )
            return None
        except Exception as exc:  # noqa: BLE001 - one module failing must not stop the pipeline
            message = f"{module.name}: {exc.__class__.__name__}: {exc}"
            log.warning("module_failed", module=module.name, error=str(exc))
            result.errors.append(message)
            await self.bus.publish(
                events.MODULE_FAILED, scan_id=result.scan_id, module=module.name, error=message
            )
            return None

        for error in output.errors:
            result.errors.append(f"{module.name}: {error}")
        return output

    async def _run_intel(self, result: ScanResult, metadata: dict[str, Any]) -> None:
        await self.bus.publish(events.MODULE_STARTED, scan_id=result.scan_id, module=INTEL_MODULE)
        try:
            new_findings = self.intel.correlate(result.findings, metadata)
        except Exception as exc:  # noqa: BLE001 - correlation failure keeps the recon results
            message = f"{INTEL_MODULE}: {exc.__class__.__name__}: {exc}"
            result.errors.append(message)
            await self.bus.publish(
                events.MODULE_FAILED, scan_id=result.scan_id, module=INTEL_MODULE, error=message
            )
            return
        result.modules_run.append(INTEL_MODULE)
        await self._collect(result, new_findings, [])
        await self.bus.publish(
            events.MODULE_COMPLETED,
            scan_id=result.scan_id,
            module=INTEL_MODULE,
            finding_count=len(new_findings),
        )

    async def _collect(self, result: ScanResult, findings: list[Finding], raw: list[Any]) -> None:
        for finding in findings:
            finding.scan_id = result.scan_id
            result.findings.append(finding)
            await self.bus.publish(events.FINDING, scan_id=result.scan_id, finding=finding)
        result.raw.extend(raw)


def _select_modules(
    profile: Profile,
    enabled: tuple[str, ...],
    disabled: tuple[str, ...],
) -> list[str]:
    names = list(enabled) if enabled else list(profile.modules)
    return [name for name in names if name not in disabled]
