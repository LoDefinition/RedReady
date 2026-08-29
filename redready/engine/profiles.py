"""Scan profiles: named presets controlling which modules run and at what intensity.

Custom profiles may be defined in ``~/.redready/profiles.yaml`` using the same keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

USER_PROFILES_PATH = Path.home() / ".redready" / "profiles.yaml"


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    modules: tuple[str, ...]
    options: dict[str, Any] = field(default_factory=dict)


BUILTIN_PROFILES: dict[str, Profile] = {
    "default": Profile(
        name="default",
        description="Balanced recon across every Phase 1 module.",
        modules=("dns", "ports", "banner", "tls"),
    ),
    "quick": Profile(
        name="quick",
        description="Fast surface scan of the most common ports.",
        modules=("dns", "ports", "banner"),
        options={"ports": "1-100,443,3306,3389,5432,6379,8080,8443"},
    ),
    "network": Profile(
        name="network",
        description="Network-focused scan with service and TLS inspection.",
        modules=("dns", "ports", "banner", "tls"),
    ),
    "web-only": Profile(
        name="web-only",
        description="HTTP/TLS focused scan.",
        modules=("dns", "ports", "banner", "tls"),
        options={"ports": "80,443,8000-9000"},
    ),
    "aggressive": Profile(
        name="aggressive",
        description="All 65535 TCP ports plus OS detection.",
        modules=("dns", "ports", "banner", "tls"),
        options={"full_scan": True, "os_detection": True},
    ),
    "stealth": Profile(
        name="stealth",
        description="Minimal active probing against well-known ports only.",
        modules=("dns", "tls"),
        options={"ports": "80,443,8080,8443"},
    ),
}


def load_profiles(path: Path = USER_PROFILES_PATH) -> dict[str, Profile]:
    """Built-in profiles overlaid with any user-defined ones."""
    profiles = dict(BUILTIN_PROFILES)
    if not path.is_file():
        return profiles
    data = yaml.safe_load(path.read_text()) or {}
    for name, spec in data.items():
        profiles[name] = Profile(
            name=name,
            description=spec.get("description", "User-defined profile."),
            modules=tuple(spec.get("modules", BUILTIN_PROFILES["default"].modules)),
            options=spec.get("options", {}),
        )
    return profiles


def get_profile(name: str, path: Path = USER_PROFILES_PATH) -> Profile:
    profiles = load_profiles(path)
    try:
        return profiles[name]
    except KeyError:
        raise KeyError(
            f"unknown profile {name!r}; available: {', '.join(sorted(profiles))}"
        ) from None
