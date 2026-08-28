"""DNS enumeration: record queries, SPF/DMARC posture, DNSSEC, AXFR attempt, reverse DNS."""

from __future__ import annotations

import asyncio
import ipaddress

import dns.asyncresolver
import dns.exception
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone

from redready.engine.result import Finding, RawData
from redready.modules.base import BaseModule, ModuleInput, ModuleOutput

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV")


class DnsModule(BaseModule):
    name = "dns"
    description = "Resolve the target and audit its DNS posture (SPF, DMARC, DNSSEC, AXFR)."

    async def is_applicable(self, input: ModuleInput) -> bool:  # noqa: A002
        return not _is_ip(input.host)

    async def run(self, input: ModuleInput) -> ModuleOutput:  # noqa: A002
        out = self.output()
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 10.0

        records: dict[str, list[str]] = {}
        for rtype in RECORD_TYPES:
            values, error = await _query(resolver, input.host, rtype)
            if error:
                out.errors.append(f"{rtype} query failed: {error}")
            if values:
                records[rtype] = values
                out.raw.append(
                    RawData(
                        module=self.name,
                        data_type="dns_record",
                        host=input.host,
                        data="\n".join(values).encode(),
                        metadata={"record_type": rtype},
                    )
                )

        ips = records.get("A", []) + records.get("AAAA", [])
        out.metadata["dns_records"] = records
        out.metadata["resolved_ips"] = ips
        if ips:
            out.metadata["ip"] = ips[0]
        else:
            out.findings.append(
                Finding(
                    module=self.name,
                    title="Target does not resolve to any address",
                    description=(
                        f"No A or AAAA records were returned for {input.host}. Active modules "
                        "that need an IP address will be skipped."
                    ),
                    severity="INFO",
                    remediation="Confirm the target hostname is correct and publicly resolvable.",
                    evidence=f"host={input.host}",
                )
            )

        txt_records = records.get("TXT", [])
        out.findings.extend(_spf_findings(self.name, input.host, txt_records))
        out.findings.extend(await _dmarc_findings(self.name, resolver, input.host))
        out.findings.extend(await _dnssec_findings(self.name, resolver, input.host))

        zone_findings, zone_raw = await _zone_transfer(self.name, input.host, records.get("NS", []))
        out.findings.extend(zone_findings)
        out.raw.extend(zone_raw)

        ptr_map = await _reverse_dns(resolver, ips)
        if ptr_map:
            out.metadata["ptr_records"] = ptr_map
            out.raw.append(
                RawData(
                    module=self.name,
                    data_type="dns_record",
                    host=input.host,
                    data=str(ptr_map).encode(),
                    metadata={"record_type": "PTR"},
                )
            )
        return out


async def _query(
    resolver: dns.asyncresolver.Resolver, host: str, rtype: str
) -> tuple[list[str], str | None]:
    try:
        answer = await resolver.resolve(host, rtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return [], None
    except (dns.exception.Timeout, dns.exception.DNSException) as exc:
        return [], str(exc) or exc.__class__.__name__
    return [rdata.to_text() for rdata in answer], None


def _spf_findings(module: str, host: str, txt_records: list[str]) -> list[Finding]:
    spf = next((r for r in txt_records if "v=spf1" in r.lower()), None)
    if spf is None:
        return [
            Finding(
                module=module,
                title="No SPF record published",
                description=(
                    f"{host} publishes no SPF record, so receiving mail servers have no way to "
                    "tell which hosts may send mail on this domain's behalf."
                ),
                severity="MEDIUM",
                remediation=(
                    "Publish a TXT record such as "
                    '"v=spf1 include:<your-mail-provider> -all" listing every authorized sender.'
                ),
                evidence=f"txt_records={txt_records}",
            )
        ]
    findings: list[Finding] = []
    if "+all" in spf:
        findings.append(
            Finding(
                module=module,
                title="SPF record permits any sender (+all)",
                description=(
                    "The SPF record ends in +all, which authorizes every host on the internet to "
                    "send mail as this domain. This makes spoofing trivial."
                ),
                severity="HIGH",
                remediation="Replace +all with -all (hard fail) and enumerate legitimate senders.",
                evidence=spf,
            )
        )
    return findings


async def _dmarc_findings(
    module: str, resolver: dns.asyncresolver.Resolver, host: str
) -> list[Finding]:
    values, _ = await _query(resolver, f"_dmarc.{host}", "TXT")
    dmarc = next((v for v in values if "v=dmarc1" in v.lower()), None)
    if dmarc is None:
        return [
            Finding(
                module=module,
                title="No DMARC record published",
                description=(
                    f"{host} has no _dmarc TXT record, so SPF and DKIM results are never enforced "
                    "and the domain owner receives no spoofing reports."
                ),
                severity="MEDIUM",
                remediation=(
                    'Publish "v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>" at '
                    "_dmarc.<domain> and tighten to p=reject once reports look clean."
                ),
                evidence=f"_dmarc.{host} returned no DMARC record",
            )
        ]
    if "p=none" in dmarc.replace(" ", "").lower():
        return [
            Finding(
                module=module,
                title="DMARC policy is not enforced (p=none)",
                description=(
                    "The DMARC policy is set to p=none, which only collects reports; spoofed mail "
                    "is still delivered."
                ),
                severity="LOW",
                remediation="Move the policy to p=quarantine, then p=reject.",
                evidence=dmarc,
            )
        ]
    return []


async def _dnssec_findings(
    module: str, resolver: dns.asyncresolver.Resolver, host: str
) -> list[Finding]:
    values, _ = await _query(resolver, host, "DNSKEY")
    if values:
        return []
    return [
        Finding(
            module=module,
            title="DNSSEC is not enabled",
            description=(
                f"No DNSKEY record was found for {host}, so DNS responses for this domain cannot "
                "be cryptographically validated by resolvers."
            ),
            severity="INFO",
            remediation="Sign the zone with DNSSEC and publish a DS record at the registrar.",
            evidence=f"no DNSKEY record for {host}",
        )
    ]


async def _zone_transfer(
    module: str, host: str, nameservers: list[str]
) -> tuple[list[Finding], list[RawData]]:
    findings: list[Finding] = []
    raw: list[RawData] = []
    for ns in nameservers[:4]:
        ns_host = ns.rstrip(".")
        try:
            zone = await asyncio.to_thread(
                dns.zone.from_xfr, dns.query.xfr(ns_host, host, timeout=8, lifetime=8)
            )
        except Exception as exc:  # noqa: BLE001 - AXFR fails in many distinct ways; log them all
            raw.append(
                RawData(
                    module=module,
                    data_type="axfr_attempt",
                    host=ns_host,
                    data=str(exc).encode(),
                    metadata={"zone": host, "result": "refused"},
                )
            )
            continue
        names = "\n".join(sorted(str(n) for n in zone.nodes))
        raw.append(
            RawData(
                module=module,
                data_type="axfr_attempt",
                host=ns_host,
                data=names.encode(),
                metadata={"zone": host, "result": "success"},
            )
        )
        findings.append(
            Finding(
                module=module,
                title=f"Zone transfer (AXFR) allowed by {ns_host}",
                description=(
                    f"The nameserver {ns_host} served a full copy of the {host} zone to an "
                    "unauthenticated client, disclosing every record in the domain."
                ),
                severity="CRITICAL",
                remediation=(
                    "Restrict AXFR to authorized secondary nameservers only (allow-transfer / "
                    "TSIG keys)."
                ),
                evidence=names[:2000],
            )
        )
    return findings, raw


async def _reverse_dns(
    resolver: dns.asyncresolver.Resolver, ips: list[str]
) -> dict[str, list[str]]:
    ptr: dict[str, list[str]] = {}
    for ip in ips:
        try:
            rev = dns.reversename.from_address(ip)
        except dns.exception.SyntaxError:
            continue
        values, _ = await _query(resolver, str(rev), "PTR")
        if values:
            ptr[ip] = values
    return ptr


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
