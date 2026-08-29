from __future__ import annotations

import pytest

from redready.modules.banner import parse_banner
from redready.modules.dns import _spf_findings
from redready.modules.ports import _parse_nmap_xml

NMAP_XML = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1" ostype="Linux">
          <cpe>cpe:/a:openbsd:openssh:8.2p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
        <service name="telnet"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_returns_only_open_ports() -> None:
    services = _parse_nmap_xml(NMAP_XML)
    assert sorted(services) == [22, 443]
    assert services[22]["product"] == "OpenSSH"
    assert services[22]["version"] == "8.2p1"
    assert services[22]["cpe"] == "cpe:/a:openbsd:openssh:8.2p1"
    assert services[443]["name"] == "https"


@pytest.mark.parametrize("xml", [b"", b"not xml at all"])
def test_parse_nmap_xml_tolerates_garbage(xml: bytes) -> None:
    assert _parse_nmap_xml(xml) == {}


@pytest.mark.parametrize(
    ("banner", "product", "version"),
    [
        ("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "openssh", "8.2p1"),
        ("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", "nginx", "1.18.0"),
        ("HTTP/1.1 403\r\nServer: Apache/2.4.54 (Debian)\r\n\r\n", "http_server", "2.4.54"),
    ],
)
def test_parse_banner(banner: str, product: str, version: str) -> None:
    parsed = parse_banner(banner)
    assert parsed is not None
    assert parsed.product == product
    assert parsed.version == version
    assert parsed.cpe.startswith("cpe:2.3:a:")


def test_parse_banner_unknown() -> None:
    assert parse_banner("hello there") is None


def test_spf_missing_record() -> None:
    findings = _spf_findings("dns", "example.com", ["google-site-verification=abc"])
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "No SPF" in findings[0].title


def test_spf_permissive_all() -> None:
    findings = _spf_findings("dns", "example.com", ["v=spf1 include:_spf.example.com +all"])
    assert [f.severity for f in findings] == ["HIGH"]


def test_spf_hard_fail_is_clean() -> None:
    assert _spf_findings("dns", "example.com", ["v=spf1 -all"]) == []
