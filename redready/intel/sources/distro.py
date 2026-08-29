"""Distro backport detection for version-based CVE matches."""
from __future__ import annotations
from dataclasses import dataclass
import re
@dataclass(frozen=True)
class DistroContext:
    detected: bool
    distro: str | None
    confidence: str
    caveat: str
_PATTERNS=((r"\\bubuntu\\b","Ubuntu"),(r"~deb\\d+u\\d+|\\bdebian\\b","Debian"),(r"\\.(?:el|rhel)\\d+|~rhel","RHEL/CentOS"),(r"\\bfedora\\b","Fedora"),(r"\\balpine\\b","Alpine"))
def detect_distro_context(text: str, product: str = "", cve_id: str = "") -> DistroContext:
    for pattern,name in _PATTERNS:
        if re.search(pattern,text,re.I):
            command="apt-cache policy" if name in ("Ubuntu","Debian") else "rpm -q --changelog"
            return DistroContext(True,name,"possible",f"Version contains a {name} packaging marker. Security patches may be backported; verify with \`{command} {product}\` before reporting {cve_id}.")
    return DistroContext(False,None,"certain","")
