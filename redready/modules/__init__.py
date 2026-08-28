"""Scan modules and the module registry."""

from __future__ import annotations

from redready.modules.banner import BannerModule
from redready.modules.base import BaseModule, ModuleInput, ModuleOutput
from redready.modules.dns import DnsModule
from redready.modules.ports import PortsModule
from redready.modules.tls import TlsModule

#: Registry of built-in modules. Third-party modules register via :func:`register_module`.
_REGISTRY: dict[str, type[BaseModule]] = {}


def register_module(module_cls: type[BaseModule]) -> type[BaseModule]:
    """Register a module class so profiles and the CLI can reference it by name."""
    _REGISTRY[module_cls.name] = module_cls
    return module_cls


def available_modules() -> dict[str, type[BaseModule]]:
    return dict(_REGISTRY)


def get_module(name: str) -> type[BaseModule]:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown module: {name!r}") from None


for _cls in (DnsModule, PortsModule, BannerModule, TlsModule):
    register_module(_cls)

__all__ = [
    "BannerModule",
    "BaseModule",
    "DnsModule",
    "ModuleInput",
    "ModuleOutput",
    "PortsModule",
    "TlsModule",
    "available_modules",
    "get_module",
    "register_module",
]
