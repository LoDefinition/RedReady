"""Canonical CPE resolution for banner-derived services."""
from __future__ import annotations
from dataclasses import dataclass
@dataclass(frozen=True)
class CanonicalCPE:
    vendor: str
    product: str
    source: str
    confidence: float
ALIASES = {
 ("openssh","openssh"):("openbsd","openssh"), ("nginx","nginx"):("f5","nginx"),
 ("apache","apache"):("apache","http_server"), ("apache","httpd"):("apache","http_server"),
 ("mysql","mysql"):("oracle","mysql"), ("microsoft","iis"):("microsoft","internet_information_services"),
 ("openssl","openssl"):("openssl","openssl"), ("redis","redis"):("redis","redis"),
}
def canonicalize(vendor: str, product: str, nmap_cpe: str | None = None) -> CanonicalCPE | None:
    if nmap_cpe:
        parts=nmap_cpe.replace("cpe:/","cpe:2.3:").split(":")
        if len(parts) >= 5 and parts[3] and parts[4]:
            return CanonicalCPE(parts[3].lower(),parts[4].lower(),"nmap_cpe",1.0)
    key=(vendor.lower().strip(),product.lower().strip())
    if key in ALIASES:
        v,p=ALIASES[key]; return CanonicalCPE(v,p,"alias_table",0.9)
    for (_v,p),(cv,cp) in ALIASES.items():
        if p == key[1]: return CanonicalCPE(cv,cp,"alias_table",0.7)
    return CanonicalCPE(*key,"heuristic",0.5) if key[0] and key[1] else None
