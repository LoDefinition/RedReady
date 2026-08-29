"""Banner grabbing and service/version extraction.

Extracted ``(vendor, product, version)`` tuples become CPE strings that the intel engine uses to
query the CVE cache.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import ssl
from dataclasses import dataclass

from redready.engine.result import Finding, RawData
from redready.modules.base import BaseModule, ModuleInput, ModuleOutput

HTTP_PORTS = frozenset({80, 81, 591, 8000, 8008, 8080, 8081, 8888})
TLS_PORTS = frozenset({443, 465, 993, 995, 8443, 9443})

#: Protocol-specific probes. Banner-first services (SSH, SMTP, FTP) get an empty probe.
PROBES: dict[int, bytes] = {
    21: b"",
    22: b"",
    25: b"EHLO redready.local\r\n",
    110: b"",
    143: b"",
    587: b"EHLO redready.local\r\n",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
    27017: b"",
}


@dataclass(frozen=True)
class ServiceVersion:
    service: str
    vendor: str
    product: str
    version: str
    os_hint: str | None = None

    @property
    def cpe(self) -> str:
        return f"cpe:2.3:a:{self.vendor.lower()}:{self.product.lower()}:{self.version}"


#: ``(regex, service, vendor_group, product, version_group, os_group)`` banner signatures.
_SIGNATURES: tuple[tuple[re.Pattern[str], str, str, str, str | None], ...] = (
    (
        re.compile(r"SSH-\d+\.\d+-OpenSSH[_-](?P<version>[\w.]+p?\d*)(?:\s+(?P<os>[\w.~-]+))?"),
        "ssh",
        "openssh",
        "openssh",
        "os",
    ),
    (
        re.compile(r"SSH-\d+\.\d+-(?P<version>dropbear[_ ][\w.]+)"),
        "ssh",
        "dropbear_ssh_server",
        "dropbear_ssh_server",
        None,
    ),
    (re.compile(r"nginx/(?P<version>[\d.]+)"), "http", "nginx", "nginx", None),
    (re.compile(r"Apache/(?P<version>[\d.]+)"), "http", "apache", "http_server", None),
    (re.compile(r"Microsoft-IIS/(?P<version>[\d.]+)"), "http", "microsoft", "iis", None),
    (re.compile(r"Postfix|Exim (?P<version>[\d.]+)"), "smtp", "exim", "exim", None),
    (re.compile(r"vsFTPd (?P<version>[\d.]+)"), "ftp", "vsftpd", "vsftpd", None),
    (re.compile(r"ProFTPD (?P<version>[\d.]+)"), "ftp", "proftpd", "proftpd", None),
    (re.compile(r"(?P<version>\d+\.\d+\.\d+)-MariaDB"), "mysql", "mariadb", "mariadb", None),
    (re.compile(r"redis_version:(?P<version>[\d.]+)"), "redis", "redis", "redis", None),
    (re.compile(r"OpenSSL/(?P<version>[\w.]+)"), "tls", "openssl", "openssl", None),
)


def parse_banner(banner: str) -> ServiceVersion | None:
    """Extract a service/vendor/version tuple from a raw banner string."""
    for pattern, service, vendor, product, os_group in _SIGNATURES:
        match = pattern.search(banner)
        if match is None:
            continue
        version = (match.groupdict().get("version") or "").strip()
        if not version:
            continue
        os_hint = match.groupdict().get(os_group) if os_group else None
        return ServiceVersion(
            service=service,
            vendor=vendor,
            product=product,
            version=version,
            os_hint=os_hint,
        )
    return None


class BannerModule(BaseModule):
    name = "banner"
    description = "Grab service banners from every open port and extract software versions."
    requires = ["ports"]

    async def is_applicable(self, input: ModuleInput) -> bool:  # noqa: A002
        return bool(input.ports)

    async def run(self, input: ModuleInput) -> ModuleOutput:  # noqa: A002
        out = self.output()
        host = input.ip or input.host
        timeout = float(input.settings.scan.banner_timeout)

        results = await asyncio.gather(
            *(_grab(host, port, timeout_s=timeout) for port in input.ports),
            return_exceptions=False,
        )

        versions: list[dict[str, str]] = []
        for port, banner, error in results:
            if error:
                out.errors.append(f"port {port}: {error}")
                continue
            if not banner:
                continue
            raw = RawData(
                module=self.name,
                data_type="banner",
                host=host,
                port=port,
                protocol="tcp",
                data=banner,
                metadata={"length": len(banner)},
            )
            out.raw.append(raw)

            text = banner.decode("utf-8", errors="replace")
            parsed = parse_banner(text)
            if parsed is None:
                continue
            versions.append(
                {
                    "port": str(port),
                    "service": parsed.service,
                    "vendor": parsed.vendor,
                    "product": parsed.product,
                    "version": parsed.version,
                    "cpe": parsed.cpe,
                }
            )
            out.findings.append(
                Finding(
                    module=self.name,
                    title=f"{parsed.product} {parsed.version} identified on port {port}",
                    description=(
                        f"The banner returned by {host}:{port} identifies "
                        f"{parsed.product} {parsed.version}"
                        + (f" on {parsed.os_hint}" if parsed.os_hint else "")
                        + ". Exact version disclosure lets an attacker look up known "
                        "vulnerabilities without touching the service again."
                    ),
                    severity="INFO",
                    remediation=(
                        "Suppress version strings in the service banner where supported, and keep "
                        "the software patched."
                    ),
                    evidence=text.strip()[:500],
                    port=port,
                    service=parsed.service,
                    raw_data_ids=[raw.id],
                )
            )

        out.metadata["service_versions"] = versions
        out.metadata["cpes"] = [v["cpe"] for v in versions]
        return out


async def _grab(host: str, port: int, *, timeout_s: float) -> tuple[int, bytes, str | None]:
    try:
        return await asyncio.wait_for(_connect_and_read(host, port), timeout=timeout_s)
    except TimeoutError:
        return port, b"", None
    except OSError as exc:
        return port, b"", str(exc)


async def _connect_and_read(host: str, port: int) -> tuple[int, bytes, str | None]:
    use_tls = port in TLS_PORTS
    reader, writer = await asyncio.open_connection(
        host, port, ssl=_permissive_ssl_context() if use_tls else None
    )
    try:
        probe = _probe_for(host, port, use_tls)
        if probe:
            writer.write(probe)
            await writer.drain()
        data = await reader.read(4096)
    finally:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()
    return port, data, None


def _probe_for(host: str, port: int, use_tls: bool) -> bytes:
    if port in PROBES:
        return PROBES[port]
    if use_tls or port in HTTP_PORTS:
        return (
            f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: RedReady\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        ).encode()
    return b"\r\n"


def _permissive_ssl_context() -> ssl.SSLContext:
    # Banner grabbing must succeed against expired/self-signed certificates; the TLS module is
    # what actually validates certificate posture.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context
