"""Module contract. Every recon capability is a :class:`BaseModule` subclass."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from redready.config import Settings
from redready.engine.result import Finding, RawData


@dataclass
class ModuleInput:
    target: str
    host: str
    ip: str | None = None
    ports: list[int] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    settings: Settings = field(default_factory=Settings)
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleOutput:
    module_name: str
    findings: list[Finding] = field(default_factory=list)
    raw: list[RawData] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class BaseModule(ABC):
    name: str
    description: str
    requires: list[str] = []
    enabled_by_default: bool = True

    @abstractmethod
    async def run(self, input: ModuleInput) -> ModuleOutput:  # noqa: A002 - spec'd signature
        ...

    async def is_applicable(self, input: ModuleInput) -> bool:  # noqa: A002 - spec'd signature
        """Override to skip the module when preconditions are not met."""
        return True

    def output(self, **kwargs: Any) -> ModuleOutput:
        return ModuleOutput(module_name=self.name, **kwargs)
