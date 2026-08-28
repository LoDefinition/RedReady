"""Target parsing and normalization."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit

TargetType = Literal["domain", "ip", "cidr", "url"]

#: Guard against accidentally expanding an enormous CIDR into individual scans.
MAX_CIDR_HOSTS = 4096

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


class TargetError(ValueError):
    """Raised when a user-supplied target cannot be parsed."""


@dataclass
class NormalizedTarget:
    raw: str
    type: TargetType
    host: str
    hosts: list[str] = field(default_factory=list)
    port: int | None = None
    scheme: str | None = None

    def __post_init__(self) -> None:
        if not self.hosts:
            self.hosts = [self.host]


def _split_host_port(value: str) -> tuple[str, int | None]:
    if value.startswith("["):
        closing = value.find("]")
        if closing == -1:
            raise TargetError(f"unbalanced brackets in target: {value!r}")
        host = value[1:closing]
        remainder = value[closing + 1 :]
        if remainder.startswith(":"):
            return host, _parse_port(remainder[1:])
        return host, None
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        return host, _parse_port(port)
    return value, None


def _parse_port(value: str) -> int:
    if not value.isdigit():
        raise TargetError(f"invalid port: {value!r}")
    port = int(value)
    if not 1 <= port <= 65535:
        raise TargetError(f"port out of range: {port}")
    return port


def normalize_target(raw: str) -> NormalizedTarget:
    """Normalize any accepted target string into a :class:`NormalizedTarget`."""
    value = raw.strip()
    if not value:
        raise TargetError("empty target")

    scheme: str | None = None
    target_type: TargetType | None = None

    if "://" in value:
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https"):
            raise TargetError(f"unsupported URL scheme: {parts.scheme!r}")
        if not parts.hostname:
            raise TargetError(f"URL has no host: {raw!r}")
        scheme = parts.scheme
        target_type = "url"
        host, port = parts.hostname, parts.port
    else:
        host, port = _split_host_port(value)

    if "/" in host:
        network = _parse_network(host, raw)
        hosts = [str(ip) for ip in network.hosts()] or [str(network.network_address)]
        if len(hosts) > MAX_CIDR_HOSTS:
            raise TargetError(
                f"CIDR expands to {len(hosts)} hosts, above the {MAX_CIDR_HOSTS} host limit"
            )
        return NormalizedTarget(raw=raw, type="cidr", host=host, hosts=hosts)

    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME_RE.match(host):
            raise TargetError(f"not a valid domain, IP, CIDR or URL: {raw!r}") from None
        host = host.rstrip(".").lower()
        resolved_type: TargetType = target_type or "domain"
    else:
        resolved_type = target_type or "ip"

    return NormalizedTarget(raw=raw, type=resolved_type, host=host, port=port, scheme=scheme)


def _parse_network(host: str, raw: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(host, strict=False)
    except ValueError as exc:
        raise TargetError(f"invalid CIDR in target {raw!r}: {exc}") from exc


def load_targets_file(path: str) -> list[str]:
    """Read one target per line, ignoring blank lines and ``#`` comments."""
    with open(path, encoding="utf-8") as handle:
        return [
            line.strip() for line in handle if line.strip() and not line.lstrip().startswith("#")
        ]
