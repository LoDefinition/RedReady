"""TLS and certificate inspection: cert parsing, validity, protocol and cipher posture."""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID

from redready.engine.result import Finding, RawData, Severity
from redready.modules.base import BaseModule, ModuleInput, ModuleOutput

DEFAULT_TLS_PORTS = (443, 8443, 993, 995, 465)

#: Legacy protocol versions that should no longer be negotiable, with their finding severity.
LEGACY_PROTOCOLS: tuple[tuple[str, ssl.TLSVersion, Severity], ...] = (
    ("SSLv3", ssl.TLSVersion.SSLv3, "CRITICAL"),
    ("TLSv1.0", ssl.TLSVersion.TLSv1, "HIGH"),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "HIGH"),
)

WEAK_CIPHER_TOKENS = ("RC4", "DES", "3DES", "EXPORT", "NULL", "MD5")

MIN_RSA_KEY_BITS = 2048


@dataclass
class CertificateInfo:
    subject: str
    issuer: str
    sans: list[str]
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    key_type: str
    key_bits: int | None
    serial: str
    self_signed: bool
    pem: str
    negotiated_protocol: str | None = None
    negotiated_cipher: str | None = None
    legacy_protocols: list[str] = field(default_factory=list)

    @property
    def days_until_expiry(self) -> int:
        return (self.not_after - datetime.now(UTC)).days

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "sans": self.sans,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "signature_algorithm": self.signature_algorithm,
            "key_type": self.key_type,
            "key_bits": self.key_bits,
            "serial": self.serial,
            "self_signed": self.self_signed,
            "negotiated_protocol": self.negotiated_protocol,
            "negotiated_cipher": self.negotiated_cipher,
            "legacy_protocols": self.legacy_protocols,
        }


class TlsModule(BaseModule):
    name = "tls"
    description = "Inspect TLS certificates, protocol versions and cipher posture."
    requires = ["ports"]

    async def is_applicable(self, input: ModuleInput) -> bool:  # noqa: A002
        return bool(_tls_ports(input))

    async def run(self, input: ModuleInput) -> ModuleOutput:  # noqa: A002
        out = self.output()
        host = input.host
        connect_host = input.ip or input.host
        certificates: dict[str, dict[str, Any]] = {}

        for port in _tls_ports(input):
            try:
                info = await asyncio.to_thread(_inspect, connect_host, host, port)
            except (OSError, ssl.SSLError) as exc:
                out.errors.append(f"port {port}: TLS handshake failed: {exc}")
                continue

            certificates[str(port)] = info.to_dict()
            out.raw.append(
                RawData(
                    module=self.name,
                    data_type="cert",
                    host=host,
                    port=port,
                    protocol="tls",
                    data=info.pem.encode(),
                    metadata=info.to_dict(),
                )
            )
            out.findings.extend(_certificate_findings(self.name, host, port, info))

        out.metadata["certificates"] = certificates
        return out


def _tls_ports(input: ModuleInput) -> list[int]:  # noqa: A002
    if input.ports:
        return [p for p in input.ports if p in DEFAULT_TLS_PORTS or p in (8080, 9443)]
    return [443]


def _inspect(connect_host: str, server_name: str, port: int) -> CertificateInfo:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with (
        socket.create_connection((connect_host, port), timeout=10) as sock,
        context.wrap_socket(sock, server_hostname=server_name) as tls_sock,
    ):
        der = tls_sock.getpeercert(binary_form=True)
        protocol = tls_sock.version()
        cipher = tls_sock.cipher()

    if der is None:
        raise ssl.SSLError(f"{connect_host}:{port} presented no certificate")

    cert = x509.load_der_x509_certificate(der)
    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        sans=_sans(cert),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        signature_algorithm=_signature_algorithm(cert),
        key_type=type(cert.public_key()).__name__.removeprefix("_").replace("PublicKey", ""),
        key_bits=_key_bits(cert),
        serial=format(cert.serial_number, "x"),
        self_signed=cert.subject == cert.issuer,
        pem=cert.public_bytes(encoding=Encoding.PEM).decode(),
        negotiated_protocol=protocol,
        negotiated_cipher=cipher[0] if cipher else None,
        legacy_protocols=_legacy_protocols(connect_host, server_name, port),
    )


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    san = ext.value
    assert isinstance(san, x509.SubjectAlternativeName)
    return san.get_values_for_type(x509.DNSName)


def _signature_algorithm(cert: x509.Certificate) -> str:
    try:
        algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:  # pragma: no cover - exotic signature algorithms
        return "unknown"
    if isinstance(algorithm, hashes.HashAlgorithm):
        return algorithm.name
    return "unknown"


def _key_bits(cert: x509.Certificate) -> int | None:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey | dsa.DSAPublicKey):
        return key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key.curve.key_size
    return None


def _legacy_protocols(connect_host: str, server_name: str, port: int) -> list[str]:
    supported: list[str] = []
    for label, version, _severity in LEGACY_PROTOCOLS:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
            context.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            # The local OpenSSL build refuses to offer this version at all.
            continue
        try:
            with (
                socket.create_connection((connect_host, port), timeout=6) as sock,
                context.wrap_socket(sock, server_hostname=server_name),
            ):
                supported.append(label)
        except (OSError, ssl.SSLError):
            continue
    return supported


def _certificate_findings(
    module: str, host: str, port: int, info: CertificateInfo
) -> list[Finding]:
    findings: list[Finding] = []
    days = info.days_until_expiry
    evidence = f"subject={info.subject} issuer={info.issuer} not_after={info.not_after.isoformat()}"

    if days < 0:
        findings.append(
            Finding(
                module=module,
                title=f"TLS certificate expired {abs(days)} days ago",
                description=(
                    f"The certificate served on {host}:{port} expired on "
                    f"{info.not_after.date()}. Clients will refuse the connection or train users "
                    "to click through warnings."
                ),
                severity="CRITICAL",
                remediation="Renew the certificate and automate renewal (e.g. ACME/certbot).",
                evidence=evidence,
                port=port,
                service="tls",
            )
        )
    else:
        for limit, severity in ((7, "HIGH"), (30, "MEDIUM")):
            if days <= limit:
                findings.append(
                    Finding(
                        module=module,
                        title=f"TLS certificate expires in {days} days",
                        description=(
                            f"The certificate on {host}:{port} is valid until "
                            f"{info.not_after.date()}."
                        ),
                        severity=severity,  # type: ignore[arg-type]
                        remediation="Renew the certificate and automate future renewals.",
                        evidence=evidence,
                        port=port,
                        service="tls",
                    )
                )
                break

    if info.self_signed:
        findings.append(
            Finding(
                module=module,
                title="Self-signed TLS certificate",
                description=(
                    f"{host}:{port} presents a certificate whose issuer equals its subject, so no "
                    "trusted authority vouches for it and MITM is indistinguishable from normal "
                    "operation."
                ),
                severity="HIGH",
                remediation="Issue the certificate from a publicly trusted CA (or your internal "
                "PKI, distributed to clients).",
                evidence=evidence,
                port=port,
                service="tls",
            )
        )

    if not _hostname_matches(host, info):
        findings.append(
            Finding(
                module=module,
                title="TLS certificate hostname mismatch",
                description=(
                    f"Neither the certificate subject nor its SANs cover {host}: SANs={info.sans}."
                ),
                severity="MEDIUM",
                remediation="Reissue the certificate with the correct subjectAltName entries.",
                evidence=evidence,
                port=port,
                service="tls",
            )
        )

    for label in info.legacy_protocols:
        severity = next(sev for name, _v, sev in LEGACY_PROTOCOLS if name == label)
        findings.append(
            Finding(
                module=module,
                title=f"Deprecated protocol {label} is supported",
                description=(
                    f"{host}:{port} completed a handshake using {label}, which is deprecated and "
                    "vulnerable to known downgrade and padding-oracle attacks."
                ),
                severity=severity,
                remediation=f"Disable {label} and require TLS 1.2 or newer.",
                evidence=f"handshake succeeded with {label}",
                port=port,
                service="tls",
            )
        )

    if info.negotiated_cipher and any(
        token in info.negotiated_cipher.upper() for token in WEAK_CIPHER_TOKENS
    ):
        findings.append(
            Finding(
                module=module,
                title=f"Weak cipher suite negotiated ({info.negotiated_cipher})",
                description="The server selected a cipher suite built on a broken primitive.",
                severity="HIGH",
                remediation="Restrict the cipher list to modern AEAD suites (AES-GCM, ChaCha20).",
                evidence=str(info.negotiated_cipher),
                port=port,
                service="tls",
            )
        )

    if info.key_type.upper().startswith("RSA") and (info.key_bits or 0) < MIN_RSA_KEY_BITS:
        findings.append(
            Finding(
                module=module,
                title=f"RSA key is only {info.key_bits} bits",
                description="RSA keys below 2048 bits no longer provide adequate strength.",
                severity="HIGH",
                remediation="Reissue the certificate with a 2048-bit (or larger) RSA key, or ECDSA "
                "P-256.",
                evidence=evidence,
                port=port,
                service="tls",
            )
        )

    findings.append(
        Finding(
            module=module,
            title=f"TLS certificate details for port {port}",
            description=(
                f"Issued by {info.issuer} for {info.subject}, valid {info.not_before.date()} to "
                f"{info.not_after.date()}, {info.key_type} {info.key_bits or '?'} bits, signed "
                f"with {info.signature_algorithm}."
            ),
            severity="INFO",
            remediation="No action required.",
            evidence=evidence,
            port=port,
            service="tls",
        )
    )
    return findings


def _hostname_matches(host: str, info: CertificateInfo) -> bool:
    candidates = list(info.sans)
    for attribute in info.subject.split(","):
        key, _, value = attribute.strip().partition("=")
        if key.upper() == "CN":
            candidates.append(value)
    return any(_matches(host, candidate) for candidate in candidates)


def _matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return host == pattern[2:] or (
            host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")
        )
    return host == pattern
