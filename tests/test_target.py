from __future__ import annotations

from pathlib import Path

import pytest

from redready.engine.target import (
    MAX_CIDR_HOSTS,
    TargetError,
    load_targets_file,
    normalize_target,
)


def test_bare_domain() -> None:
    target = normalize_target("Example.COM")
    assert (target.type, target.host, target.port) == ("domain", "example.com", None)
    assert target.hosts == ["example.com"]


def test_trailing_dot_and_host_port() -> None:
    target = normalize_target("example.com.:8443")
    assert target.host == "example.com"
    assert target.port == 8443


def test_url_keeps_scheme_and_port() -> None:
    target = normalize_target("https://example.com:8443/admin")
    assert target.type == "url"
    assert target.scheme == "https"
    assert target.host == "example.com"
    assert target.port == 8443


def test_ipv4_and_ipv6() -> None:
    assert normalize_target("192.0.2.10").type == "ip"
    assert normalize_target("[2001:db8::1]:443").host == "2001:db8::1"
    assert normalize_target("2001:db8::1").host == "2001:db8::1"


def test_cidr_expands_hosts() -> None:
    target = normalize_target("192.0.2.0/30")
    assert target.type == "cidr"
    assert target.hosts == ["192.0.2.1", "192.0.2.2"]


def test_cidr_limit() -> None:
    with pytest.raises(TargetError, match=str(MAX_CIDR_HOSTS)):
        normalize_target("10.0.0.0/8")


@pytest.mark.parametrize(
    "value",
    ["", "   ", "ftp://example.com", "example.com:0", "example.com:99999", "not a host"],
)
def test_invalid_targets(value: str) -> None:
    with pytest.raises(TargetError):
        normalize_target(value)


def test_targets_file(tmp_path: Path) -> None:
    path = tmp_path / "targets.txt"
    path.write_text("# comment\nexample.com\n\n  192.0.2.1  \n")
    assert load_targets_file(str(path)) == ["example.com", "192.0.2.1"]
