"""Port scanning via nmap.

nmap is invoked as a subprocess with XML output rather than through python-nmap: the XML schema is
stable, parsing it needs no third-party dependency, and it keeps the call fully async.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from dataclasses import dataclass
from xml.etree import ElementTree

from redready.engine.result import Finding, RawData
from redready.modules.base import BaseModule, ModuleInput, ModuleOutput


class NmapNotInstalledError(RuntimeError):
    def __init__(self) -> None:
        super().__init__(
            "nmap was not found on PATH. Install it with `apt install nmap` (Debian/Ubuntu), "
            "`brew install nmap` (macOS) or from https://nmap.org/download.html."
        )


@dataclass(frozen=True)
class PortFinding:
    """Severity and rationale attached to a notable open port."""

    severity: str
    title: str
    description: str
    remediation: str


#: Ports that are worth a finding purely by being reachable from the internet.
NOTABLE_PORTS: dict[int, PortFinding] = {
    21: PortFinding(
        "MEDIUM",
        "FTP exposed",
        "FTP transmits credentials and file contents in cleartext.",
        "Replace FTP with SFTP/FTPS, or restrict the service to a management network.",
    ),
    23: PortFinding(
        "HIGH",
        "Telnet exposed",
        "Telnet is an unencrypted remote shell; credentials are trivially sniffable.",
        "Disable telnet and use SSH instead.",
    ),
    445: PortFinding(
        "HIGH",
        "SMB exposed",
        "SMB reachable from untrusted networks is a primary lateral-movement and ransomware entry "
        "point.",
        "Block 445/tcp at the perimeter; expose file shares over a VPN only.",
    ),
    3306: PortFinding(
        "CRITICAL",
        "MySQL database exposed",
        "A database port is reachable from outside the host's network.",
        "Bind the database to localhost or a private subnet and front it with the application.",
    ),
    3389: PortFinding(
        "HIGH",
        "RDP exposed",
        "Internet-facing RDP is continuously brute-forced and has a long history of pre-auth RCE.",
        "Place RDP behind a VPN or RD Gateway and require MFA.",
    ),
    5432: PortFinding(
        "CRITICAL",
        "PostgreSQL database exposed",
        "A database port is reachable from outside the host's network.",
        "Bind the database to localhost or a private subnet and front it with the application.",
    ),
    6379: PortFinding(
        "CRITICAL",
        "Redis exposed",
        "Redis is frequently deployed without authentication and allows arbitrary key writes.",
        "Bind Redis to localhost, enable requirepass, and firewall 6379/tcp.",
    ),
    27017: PortFinding(
        "CRITICAL",
        "MongoDB exposed",
        "A database port is reachable from outside the host's network.",
        "Bind MongoDB to a private interface and enable authentication.",
    ),
}

#: Common service ports outside nmap's top 1000 that are always worth checking.
EXTRA_DEFAULT_PORTS = (3389, 5985, 5986, 8443, 9200, 27017)


class PortsModule(BaseModule):
    name = "ports"
    description = "Discover open TCP ports and service versions with nmap."
    requires = ["dns"]

    async def is_applicable(self, input: ModuleInput) -> bool:  # noqa: A002
        return input.ip is not None or input.host != ""

    async def run(self, input: ModuleInput) -> ModuleOutput:  # noqa: A002
        out = self.output()
        binary = shutil.which("nmap")
        if binary is None:
            raise NmapNotInstalledError

        target = input.ip or input.host
        args = _nmap_args(input)
        proc = await asyncio.create_subprocess_exec(
            binary,
            *args,
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        out.raw.append(
            RawData(
                module=self.name,
                data_type="nmap_xml",
                host=target,
                data=stdout,
                metadata={"args": args, "exit_code": proc.returncode},
            )
        )
        if proc.returncode != 0:
            out.errors.append(f"nmap exited {proc.returncode}: {stderr.decode(errors='replace')}")
            return out
        if stderr:
            out.errors.append(stderr.decode(errors="replace").strip())

        services = _parse_nmap_xml(stdout)
        open_ports = sorted(services)
        out.metadata["ports"] = open_ports
        out.metadata["services"] = services

        if not open_ports:
            out.findings.append(
                Finding(
                    module=self.name,
                    title="No open ports discovered",
                    description=(
                        f"nmap found no reachable TCP ports on {target} within the scanned range. "
                        "The host may be firewalled, down, or filtering the scan."
                    ),
                    severity="INFO",
                    remediation="No action required; widen the port range if more coverage is "
                    "needed.",
                    evidence=f"scanned with: nmap {' '.join(args)} {target}",
                )
            )
            return out

        for port in open_ports:
            service = services[port]
            out.findings.append(_service_finding(self.name, target, port, service))
            notable = NOTABLE_PORTS.get(port)
            if notable is not None:
                out.findings.append(
                    Finding(
                        module=self.name,
                        title=f"{notable.title} on port {port}",
                        description=notable.description,
                        severity=notable.severity,  # type: ignore[arg-type]
                        remediation=notable.remediation,
                        evidence=f"{port}/tcp open {service.get('name', '')}".strip(),
                        port=port,
                        service=service.get("name"),
                    )
                )
        return out


def _nmap_args(input: ModuleInput) -> list[str]:  # noqa: A002
    options = input.options
    args = ["-Pn", "-sV", "-oX", "-", "--min-rate", str(input.settings.scan.port_scan_rate)]
    # SYN scan needs raw sockets; fall back to a TCP connect scan when unprivileged.
    args.append("-sS" if _has_raw_socket_privileges() else "-sT")

    if options.get("full_scan"):
        args += ["-p-"]
    elif ports := options.get("ports"):
        args += ["-p", ports]
    else:
        args += ["-p", f"1-1000,{','.join(str(p) for p in EXTRA_DEFAULT_PORTS)}"]
    if options.get("os_detection") and _has_raw_socket_privileges():
        args.append("-O")
    return args


def _has_raw_socket_privileges() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _parse_nmap_xml(xml: bytes) -> dict[int, dict[str, str]]:
    services: dict[int, dict[str, str]] = {}
    if not xml.strip():
        return services
    try:
        root = ElementTree.fromstring(xml)  # noqa: S314 - output of our own nmap subprocess
    except ElementTree.ParseError:
        return services

    for port_el in root.iterfind("./host/ports/port"):
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        portid = port_el.get("portid")
        if portid is None:
            continue
        service_el = port_el.find("service")
        service = {
            key: (service_el.get(key) or "")
            for key in ("name", "product", "version", "extrainfo", "ostype", "cpe")
            if service_el is not None
        }
        if service_el is not None:
            cpes = [c.text for c in service_el.iterfind("cpe") if c.text]
            if cpes:
                service["cpe"] = cpes[0]
                service["cpes"] = ",".join(cpes)
        services[int(portid)] = service
    return services


def _service_finding(module: str, host: str, port: int, service: dict[str, str]) -> Finding:
    product = " ".join(x for x in (service.get("product"), service.get("version")) if x).strip()
    banner = product or service.get("name") or "unknown service"
    return Finding(
        module=module,
        title=f"Open port {port}/tcp ({banner})",
        description=(
            f"Port {port}/tcp on {host} is open and answered nmap's service probes as {banner!r}."
        ),
        severity="INFO",
        remediation=(
            "Confirm this service is intended to be reachable from the scanning network; close "
            "or firewall it otherwise."
        ),
        evidence=f"{port}/tcp open {service.get('name', '')} {product}".strip(),
        port=port,
        service=service.get("name"),
    )
