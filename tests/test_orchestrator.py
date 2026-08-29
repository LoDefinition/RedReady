from __future__ import annotations

import asyncio

import pytest

from redready.config import Settings
from redready.db.session import Database
from redready.engine import events
from redready.engine.events import Event, EventBus
from redready.engine.orchestrator import Orchestrator
from redready.engine.profiles import Profile
from redready.engine.result import Finding
from redready.modules import _REGISTRY, base
from redready.modules.base import BaseModule, ModuleInput, ModuleOutput


class OkModule(BaseModule):
    name = "ok"
    description = "emits one finding"

    async def run(self, input: ModuleInput) -> ModuleOutput:  # noqa: A002
        return self.output(
            findings=[
                Finding(
                    module=self.name,
                    title="finding from ok",
                    description="d",
                    severity="HIGH",
                    remediation="r",
                )
            ],
            metadata={"ports": [22]},
        )


class BoomModule(BaseModule):
    name = "boom"
    description = "always fails"

    async def run(self, input: ModuleInput) -> ModuleOutput:  # noqa: A002
        raise RuntimeError("module exploded")


class DependentModule(BaseModule):
    name = "dependent"
    description = "requires a module that never runs"
    requires = ["never"]

    async def run(self, input: ModuleInput) -> ModuleOutput:  # noqa: A002
        return self.output()


@pytest.fixture(autouse=True)
def fake_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    for module_cls in (OkModule, BoomModule, DependentModule):
        monkeypatch.setitem(_REGISTRY, module_cls.name, module_cls)


def _use_profile(monkeypatch: pytest.MonkeyPatch, *modules: str) -> None:
    profile = Profile(name="test", description="test profile", modules=modules)
    monkeypatch.setattr("redready.engine.orchestrator.get_profile", lambda name: profile)


def test_failing_module_does_not_abort_the_scan(
    settings: Settings, db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_profile(monkeypatch, "boom", "ok", "dependent")
    orchestrator = Orchestrator(settings, db)

    seen: list[Event] = []
    orchestrator.bus.subscribe(None, seen.append)

    results = asyncio.run(orchestrator.run("example.com"))
    assert len(results) == 1
    result = results[0]

    assert result.status == "complete"
    assert "ok" in result.modules_run
    assert "boom" not in result.modules_run
    assert any("module exploded" in error for error in result.errors)
    assert [f.title for f in result.findings] == ["finding from ok"]

    types = [event.type for event in seen]
    assert events.MODULE_FAILED in types
    assert events.MODULE_SKIPPED in types
    assert types[-1] == events.SCAN_COMPLETED

    stored = db.find_scan(result.scan_id)
    assert stored is not None
    assert stored.status == "complete"
    assert len(db.get_findings(result.scan_id)) == 1


def test_cidr_produces_one_result_per_host(
    settings: Settings, db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_profile(monkeypatch, "ok")
    orchestrator = Orchestrator(settings, db)
    results = asyncio.run(orchestrator.run("192.0.2.0/30"))
    assert [r.target_host for r in results] == ["192.0.2.1", "192.0.2.2"]


def test_disabled_module_is_not_run(
    settings: Settings, db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_profile(monkeypatch, "ok", "boom")
    orchestrator = Orchestrator(settings, db)
    results = asyncio.run(orchestrator.run("example.com", disabled_modules=("boom",)))
    assert results[0].errors == []


def test_event_handler_failure_is_isolated() -> None:
    bus = EventBus()

    def explode(event: Event) -> None:
        raise RuntimeError("handler failed")

    received: list[Event] = []
    bus.subscribe(events.FINDING, explode)
    bus.subscribe(events.FINDING, received.append)

    asyncio.run(bus.publish(events.FINDING, finding=None))
    assert len(received) == 1


def test_base_module_defaults() -> None:
    module = OkModule()
    assert asyncio.run(module.is_applicable(base.ModuleInput(target="x", host="x"))) is True
