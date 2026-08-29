"""Typed configuration root.

Resolution order, highest priority first: CLI flags (applied by the caller), ``REDREADY_*``
environment variables, ``.redready.yaml`` in the working directory, ``~/.redready/config.yaml``,
built-in defaults.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

USER_CONFIG_DIR = Path.home() / ".redready"
USER_CONFIG_PATH = USER_CONFIG_DIR / "config.yaml"
LOCAL_CONFIG_PATH = Path(".redready.yaml")
DEFAULT_DB_PATH = USER_CONFIG_DIR / "redready.db"


class DatabaseSettings(BaseModel):
    url: str = f"sqlite:///{DEFAULT_DB_PATH}"


class IntelSettings(BaseModel):
    auto_update: bool = True
    update_interval_hours: int = 24
    nvd_api_key: str = ""
    cache_dir: Path = USER_CONFIG_DIR / "intel"


class ApiKeySettings(BaseModel):
    shodan: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    abuseipdb: str = ""
    greynoise: str = ""
    virustotal: str = ""


class ScanSettings(BaseModel):
    default_profile: str = "default"
    timeout_per_module: int = 120
    max_concurrent_modules: int = 5
    port_scan_rate: int = 1000
    banner_timeout: float = 5.0
    confirm_authorized: bool = False


class ReportingSettings(BaseModel):
    default_formats: list[str] = Field(default_factory=lambda: ["terminal", "json"])
    output_dir: Path = Path("./redready-reports")


class Settings(BaseSettings):
    """Root configuration object. Injected into the engine; never imported as global state."""

    model_config = SettingsConfigDict(
        env_prefix="REDREADY_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    intel: IntelSettings = Field(default_factory=IntelSettings)
    api_keys: ApiKeySettings = Field(default_factory=ApiKeySettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    reporting: ReportingSettings = Field(default_factory=ReportingSettings)
    log_level: str = "INFO"


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    loaded = yaml.safe_load(path.read_text()) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"config file {path} must contain a YAML mapping")
    return loaded


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(existing, value)
        else:
            merged[key] = value
    return merged


def load_settings(
    *,
    user_config: Path = USER_CONFIG_PATH,
    local_config: Path = LOCAL_CONFIG_PATH,
    overrides: dict[str, Any] | None = None,
) -> Settings:
    """Build a :class:`Settings` from config files, environment and explicit overrides."""
    data = _deep_merge(_read_yaml(user_config), _read_yaml(local_config))
    if overrides:
        data = _deep_merge(data, overrides)
    return Settings(**data)
