# RedReady — Master Technical Specification
**Version:** 0.1.0-draft  
**Audience:** SWE agents, engineers, contributors — read top to bottom before writing a single line of code.  
**Status:** Active development specification. All decisions herein are canonical until superseded.

---

## 0. TL;DR

RedReady is an **open-source, pre-engagement OPSEC validation and reconnaissance scanner** for red teamers, penetration testers, and security engineers. Given a target (domain, IP, CIDR, URL), it performs layered recon and fingerprinting, banner grabs every reachable service, cross-references all findings against every major vulnerability intelligence source (CVE/NVD, MITRE ATT&CK, Sigma, Atomic Red Team, Elastic detection rules, and a proprietary community-sourced prevalence database), logs everything to a structured database, and delivers prioritized, actionable reports with remediation guidance.

It runs as a **CLI tool**, a **Docker container**, and a **web browser UI** — all three interfaces share one backend engine.

Business model: **open-core**. Core engine is MIT-licensed and free forever. Paid tiers unlock cloud sync, team collaboration, scheduled scans, and managed cloud scanning infrastructure.

---

## 1. Mission & Problem Statement

### 1.1 The Problem
Red teamers and pentesters need to validate their own OPSEC posture and understand a target's attack surface before engagement. Currently this means chaining together a dozen separate tools (nmap, shodan, amass, whatweb, nuclei, etc.), manually correlating results, and writing up findings by hand. There is no single tool that:

- Performs comprehensive recon + fingerprinting in one invocation
- Automatically cross-references findings against the full universe of public vulnerability intelligence
- Scores and prioritizes findings by exploitability *and* real-world prevalence
- Explains findings in plain English with remediation steps
- Keeps a persistent, queryable audit log of every scan ever run

RedReady solves all of this.

### 1.2 Who This Is For
**Primary users:**
- Solo red teamers / penetration testers running pre-engagement recon
- Small pentesting firms needing reproducible, logged recon workflows
- Security engineers validating their own organization's external attack surface

**Secondary users (paid tiers):**
- Enterprise security teams running continuous external attack surface management
- MSSP teams managing multiple client scan profiles

### 1.3 What Makes It Different
| Tool | Recon | Vuln Intel | Fingerprint | Report | Prevalence Scoring | Open Source |
|------|-------|------------|-------------|--------|--------------------|-------------|
| Nmap | ✓ | partial | partial | raw | ✗ | ✓ |
| Nuclei | ✗ | ✓ | ✗ | ✓ | ✗ | ✓ |
| CALDERA | ✗ | ✓ | ✗ | ✓ | ✗ | ✓ |
| Shodan | ✓ | partial | ✓ | raw | ✗ | ✗ |
| **RedReady** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓** |

The **prevalence database** is RedReady's core differentiator — an aggregated, community-sourced record of how frequently each vulnerability is actually observed in the wild, weighted by recency. This tells a tester not just "this CVE exists" but "this CVE is being actively exploited by 34% of engagements targeting this service version."

---

## 2. Architecture Overview

```
┌───────────────────────────────────────────────────────────┐
│                     INTERFACE LAYER                        │
│  ┌──────────┐   ┌──────────────┐   ┌──────────────────┐  │
│  │   CLI    │   │  Docker/API  │   │   Web Browser UI  │  │
│  │ (Typer)  │   │  (FastAPI)   │   │  (React + Vite)   │  │
│  └────┬─────┘   └──────┬───────┘   └────────┬─────────┘  │
└───────┼─────────────────┼────────────────────┼────────────┘
        │                 │                    │
        └─────────────────▼────────────────────┘
                          │
┌─────────────────────────▼─────────────────────────────────┐
│                     CORE ENGINE (Python)                   │
│                                                            │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │  Scan       │  │  Fingerprint │  │  Vuln Intel      │ │
│  │  Orchestr.  │  │  Engine      │  │  Engine          │ │
│  └──────┬──────┘  └──────┬───────┘  └────────┬─────────┘ │
│         │                │                   │            │
│  ┌──────▼──────────────────────────────────────────────┐  │
│  │               Module Pipeline                        │  │
│  │  DNS → Port → Banner → TLS → Web → C2 → Vuln       │  │
│  └──────────────────────┬──────────────────────────────┘  │
│                         │                                  │
│  ┌──────────────────────▼──────────────────────────────┐  │
│  │               Event Bus (internal pub/sub)           │  │
│  └──────────────────────┬──────────────────────────────┘  │
│                         │                                  │
└─────────────────────────┼──────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────┐
│                    DATA LAYER                               │
│                                                            │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐  │
│  │  SQLite      │   │  PostgreSQL  │   │  Redis       │  │
│  │  (local/dev) │   │  (prod/paid) │   │  (job queue) │  │
│  └──────────────┘   └──────────────┘   └──────────────┘  │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Intelligence Cache                       │  │
│  │  (MITRE ATT&CK, NVD/CVE, Sigma, Elastic, Atomic RT) │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

### 2.1 Design Principles
1. **Modularity** — every recon capability is a discrete module with a defined input/output contract. Modules can be enabled/disabled individually.
2. **Pluggable** — community members can write and register custom modules conforming to the module interface.
3. **Persistent logging** — every scan, finding, and raw result is stored. Nothing is ephemeral unless explicitly requested.
4. **Interface-agnostic core** — the engine has zero knowledge of how it is being invoked. CLI, API, and browser all call the same Python functions.
5. **Offline-first** — all core functionality works with no internet beyond reaching the target. Intelligence DBs are cached locally and updated on demand.
6. **Fail-loud** — errors surface with enough context to diagnose. No silent failures.

---

## 3. Tech Stack

### 3.1 Backend / Core Engine
| Component | Technology | Rationale |
|---|---|---|
| Language | Python 3.11+ | Ecosystem dominance in security tooling; asyncio for concurrent scanning |
| CLI framework | [Typer](https://typer.tiangolo.com/) | Click-based, auto-generates help text, supports async |
| API framework | [FastAPI](https://fastapi.tiangolo.com/) | Async, OpenAPI auto-docs, WebSocket support for live scan streaming |
| Task queue | [Celery](https://docs.celeryq.dev/) + Redis | Async scan jobs; Redis also used for live result streaming |
| Database ORM | [SQLAlchemy 2.x](https://docs.sqlalchemy.org/) + Alembic | Supports SQLite (local) and PostgreSQL (cloud/paid) |
| Async HTTP | [httpx](https://www.python-httpx.org/) | Async-native, used for web probing and intel fetching |
| DNS | [dnspython](https://www.dnspython.org/) | Full DNS query capability |
| Port scanning | [python-nmap](https://pypi.org/project/python-nmap/) wrapping nmap | nmap is the gold standard; wrap don't reimplement |
| TLS/Cert | [ssl](https://docs.python.org/3/library/ssl.html) + [cryptography](https://cryptography.io/) | TLS inspection and cert parsing |
| JA3/JARM | [jarm-py](https://github.com/salesforce/jarm) (Salesforce) | JARM fingerprint against C2 reputation lists |
| Scheduler | [APScheduler](https://apscheduler.readthedocs.io/) | Periodic intel DB refresh (paid tier: scheduled scans) |
| Config | [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) | Typed config from env, .env files, YAML |
| Logging | [structlog](https://www.structlog.org/) | Structured JSON logs; every scan event is machine-parseable |
| Testing | pytest + pytest-asyncio | Full async test coverage |

### 3.2 Frontend (Browser UI)
| Component | Technology |
|---|---|
| Framework | React 18 + Vite |
| Styling | Tailwind CSS + shadcn/ui |
| State | Zustand |
| API client | TanStack Query (React Query) |
| Real-time | WebSocket (FastAPI ↔ React) for live scan streaming |
| Charts / viz | Recharts |
| Auth (paid) | NextAuth or Clerk (TBD) |

### 3.3 Infrastructure (Paid Tier)
| Component | Technology |
|---|---|
| Container runtime | Docker + Docker Compose |
| Cloud hosting | AWS / GCP (TBD) |
| Managed DB | PostgreSQL (RDS or Cloud SQL) |
| Object storage | S3 (scan report archiving) |
| CI/CD | GitHub Actions |

---

## 4. Repository Structure

```
redready/
├── redready/                    # Core Python package
│   ├── __init__.py
│   ├── cli/                     # CLI entry points (Typer)
│   │   ├── __init__.py
│   │   ├── main.py              # `redready` root command
│   │   ├── scan.py              # `redready scan` subcommand
│   │   ├── report.py            # `redready report` subcommand
│   │   └── db.py                # `redready db` subcommand (migrations, exports)
│   ├── api/                     # FastAPI app (container/browser mode)
│   │   ├── __init__.py
│   │   ├── app.py               # FastAPI app factory
│   │   ├── routes/
│   │   │   ├── scans.py
│   │   │   ├── targets.py
│   │   │   ├── reports.py
│   │   │   └── intel.py
│   │   └── websocket.py         # Live scan streaming
│   ├── engine/                  # Core scan orchestration
│   │   ├── __init__.py
│   │   ├── orchestrator.py      # Main scan runner; manages module pipeline
│   │   ├── events.py            # Internal pub/sub event bus
│   │   └── result.py            # Canonical ScanResult and Finding types
│   ├── modules/                 # Individual scan/recon modules
│   │   ├── __init__.py
│   │   ├── base.py              # BaseModule ABC — all modules inherit this
│   │   ├── dns.py               # DNS enumeration
│   │   ├── ports.py             # Port scanning (nmap wrapper)
│   │   ├── banner.py            # Banner grabbing
│   │   ├── tls.py               # TLS/cert inspection + JA3/JARM
│   │   ├── web.py               # Web fingerprinting (headers, tech stack)
│   │   ├── whois.py             # WHOIS / RDAP
│   │   ├── c2.py                # C2 reputation scoring
│   │   ├── subdomain.py         # Subdomain enumeration
│   │   └── osint.py             # OSINT (Shodan, Censys, etc.)
│   ├── intel/                   # Vulnerability intelligence engine
│   │   ├── __init__.py
│   │   ├── engine.py            # Correlates findings against all intel sources
│   │   ├── sources/
│   │   │   ├── nvd.py           # NVD/CVE feed parser + local cache
│   │   │   ├── mitre.py         # MITRE ATT&CK STIX parser
│   │   │   ├── sigma.py         # Sigma rule matcher
│   │   │   ├── atomic.py        # Atomic Red Team technique mapper
│   │   │   ├── elastic.py       # Elastic detection rule ingester
│   │   │   └── prevalence.py    # RedReady community prevalence DB
│   │   └── scorer.py            # Produces RiskScore from correlated findings
│   ├── db/                      # Database layer
│   │   ├── __init__.py
│   │   ├── models.py            # SQLAlchemy models
│   │   ├── session.py           # DB session factory (SQLite ↔ PostgreSQL)
│   │   └── migrations/          # Alembic migration files
│   ├── reporting/               # Output generation
│   │   ├── __init__.py
│   │   ├── terminal.py          # Rich-formatted terminal output
│   │   ├── json_report.py       # Machine-readable JSON report
│   │   ├── html_report.py       # Standalone HTML report
│   │   └── pdf_report.py        # PDF export (paid tier)
│   └── config.py                # Pydantic Settings root config
├── frontend/                    # React web UI
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   └── lib/
│   ├── package.json
│   └── vite.config.ts
├── docker/
│   ├── Dockerfile               # Multi-stage: api + worker
│   ├── docker-compose.yml       # Full stack: api + worker + redis + db
│   └── docker-compose.dev.yml
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── intel_db/                    # Local intelligence cache (git-ignored if large)
│   ├── nvd/
│   ├── mitre/
│   ├── sigma/
│   ├── atomic/
│   └── elastic/
├── pyproject.toml               # Project metadata + dependencies (PEP 621)
├── Dockerfile
├── README.md
└── CONTRIBUTING.md
```

---

## 5. Module System

### 5.1 BaseModule Contract
Every scan module must inherit `BaseModule` and implement `run()`:

```python
# redready/modules/base.py

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from redready.engine.result import Finding, RawData

@dataclass
class ModuleInput:
    target: str                  # Original user-supplied target string
    host: str                    # Resolved hostname or IP
    ip: str | None               # Resolved IPv4/IPv6 (None if not yet resolved)
    ports: list[int] = field(default_factory=list)   # Open ports discovered so far
    metadata: dict[str, Any] = field(default_factory=dict)  # Pass-through data from prior modules

@dataclass
class ModuleOutput:
    module_name: str
    findings: list[Finding]      # Structured, scored findings
    raw: list[RawData]           # Raw bytes/strings for logging — everything goes in DB
    metadata: dict[str, Any]     # Data passed forward to later modules
    errors: list[str]            # Non-fatal errors encountered

class BaseModule(ABC):
    name: str                    # Unique slug, e.g. "dns_enum"
    description: str
    requires: list[str] = []     # Module names that must run first
    enabled_by_default: bool = True

    @abstractmethod
    async def run(self, input: ModuleInput) -> ModuleOutput:
        ...

    async def is_applicable(self, input: ModuleInput) -> bool:
        """Override to skip module if conditions not met (e.g., no open ports)."""
        return True
```

### 5.2 Module Pipeline Execution Order
The orchestrator runs modules in dependency order, passing `metadata` forward:

```
1. dns          — Resolve target → IPs, MX, NS, TXT, CNAME, SPF, DMARC
2. whois        — WHOIS / RDAP registrar data, registrant, ASN
3. subdomain    — Passive + active subdomain enumeration
4. ports        — nmap SYN scan (top 1000 by default; configurable)
5. banner       — TCP banner grab on all open ports
6. tls          — TLS cert inspection, cipher suite enum, JA3/JARM
7. web          — HTTP(S) header analysis, tech stack fingerprinting
8. c2           — C2 reputation check (JARM against known C2 fingerprint DB)
9. osint        — Shodan/Censys enrichment (API key optional)
10. vuln_intel  — Cross-reference all findings against all intel sources
```

Any module can emit `findings` that later modules can use. The orchestrator emits every finding to the event bus in real time — this is how the browser UI gets live updates.

---

## 6. Scan Input & Target Handling

### 6.1 Accepted Target Formats
The engine must accept and normalize:
- `example.com` — bare domain
- `https://example.com/path` — full URL (strip to host)
- `192.168.1.1` — IPv4 address
- `2001:db8::1` — IPv6 address
- `192.168.1.0/24` — CIDR (expands to individual host scans, each gets own scan record)
- `example.com:8443` — host:port (treat port as initial hint)
- File input (`--targets-file targets.txt`) — one target per line, any of the above formats

### 6.2 Target Normalization
```python
# redready/engine/target.py

@dataclass
class NormalizedTarget:
    raw: str              # Exactly what the user typed
    type: Literal["domain", "ip", "cidr", "url"]
    host: str             # Hostname or IP (no scheme, no port, no path)
    port: int | None      # If explicitly specified by user
    scheme: str | None    # "http" or "https" if URL was given
    hosts: list[str]      # Expanded list (len > 1 only for CIDR)
```

---

## 7. Module Specifications

### 7.1 DNS Module (`dns`)
**Purpose:** Exhaustive DNS enumeration of the target domain.  
**Operations:**
- A, AAAA, MX, NS, TXT, CNAME, SOA, SRV record queries
- SPF record parsing (detect misconfigurations: `+all`, missing SPF)
- DMARC record parsing (detect `p=none`, missing DMARC)
- DNSSEC validation check
- Zone transfer attempt (AXFR) — will almost always fail but log the attempt
- Reverse DNS (PTR) on resolved IPs

**Findings emitted:**
- Missing SPF → finding with severity MEDIUM
- SPF `+all` (allows any sender) → HIGH
- Missing DMARC → MEDIUM
- DMARC `p=none` (no enforcement) → LOW
- Successful zone transfer → CRITICAL
- DNSSEC not enabled → INFO

**Raw data logged:** Full DNS response for every query attempted.

### 7.2 WHOIS / RDAP Module (`whois`)
**Purpose:** Registrar and ASN context for the target.  
**Operations:**
- WHOIS query via python-whois
- RDAP query (preferred; structured JSON response)
- ASN lookup via ip-api.com or similar (no key required for basic)
- Registrar, registration date, expiry date, registrant (if not privacy-shielded)

**Findings emitted:**
- Domain expiring within 30 days → MEDIUM
- Recently registered domain (< 90 days) → HIGH (common for phishing infra)
- Privacy-shielded registrant → INFO

### 7.3 Subdomain Enumeration Module (`subdomain`)
**Purpose:** Discover all subdomains of the target domain.  
**Operations:**
- Passive enumeration: crt.sh (certificate transparency logs), HackerTarget, VirusTotal (API key optional)
- Active DNS brute force against a built-in wordlist (SecLists DNS Namelist)
- Wildcard detection and filtering
- Each discovered subdomain is queued as an additional scan target (shallow mode by default)

**Config options:**
- `subdomain.passive_only` (default: false)
- `subdomain.wordlist` (path to custom wordlist)
- `subdomain.depth` (default: 1 — do not recurse into discovered subdomains)

### 7.4 Port Scanner Module (`ports`)
**Purpose:** Discover open TCP/UDP ports.  
**Operations:**
- TCP SYN scan via nmap (`-sS` — requires root; falls back to `-sT` connect scan)
- Service version detection (`-sV`)
- OS detection (`-O` — best effort)
- Default: top 1000 ports + common service ports not in top 1000 (3389, 5985, 5986, etc.)
- Full scan (`--full-scan`): all 65535 TCP ports

**Important:** nmap must be installed on the host. Module init checks for nmap presence and fails cleanly with install instructions if absent.

**Findings emitted:**
- Port 23 (Telnet) open → HIGH
- Port 21 (FTP) open → MEDIUM
- Port 3389 (RDP) open → HIGH
- SMB (445) open → HIGH
- Database ports open to internet (3306, 5432, 27017, 6379) → CRITICAL

### 7.5 Banner Grabbing Module (`banner`)
**Purpose:** Extract service banners from every open port to identify software and version.  
**Operations:**
- Raw TCP connection to each open port, send protocol-appropriate probe, read response
- HTTP GET / request for ports likely serving HTTP(S)
- FTP, SMTP, SSH, MySQL, PostgreSQL, Redis, MongoDB protocol-specific probes
- 5-second timeout per port (configurable)
- Store raw banner bytes verbatim in DB

**Banner → Software Version Parsing:**
- Regex-based extraction of service name + version from banner string
- Example: `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5` → `{service: "ssh", vendor: "OpenSSH", version: "8.2p1", os_hint: "Ubuntu"}`
- Extracted `(vendor, version)` tuples are passed to the vuln intel engine as CPE strings

**Findings emitted:**
- Service version identified → INFO (with version string)
- Version EOL/known-vulnerable version detected → surfaced by vuln intel engine after correlating banner output

**Raw data logged:** Full banner bytes, timestamp, port, connection metadata.

### 7.6 TLS/Certificate Module (`tls`)
**Purpose:** Deep TLS inspection and certificate analysis.  
**Operations:**
- Connect and retrieve server certificate
- Parse cert: subject, SANs, issuer, validity dates, signature algorithm, key size
- Enumerate supported cipher suites and TLS versions (TLS 1.0/1.1 — deprecated)
- Check for self-signed cert
- Check for cert hostname mismatch
- HSTS header presence (cross-references with web module)
- **JARM fingerprinting:** Send 10 specially crafted ClientHello packets, compute JARM hash
- **JA3S fingerprinting:** Compute JA3S hash of server TLS response
- Match JARM/JA3S against known C2 framework fingerprint database (Cobalt Strike, Metasploit, Sliver, Brute Ratel, Havoc, etc.)

**Findings emitted:**
- Certificate expired → CRITICAL
- Certificate expiring within 7 days → HIGH
- Certificate expiring within 30 days → MEDIUM
- TLS 1.0 or 1.1 supported → HIGH
- SSLv3 supported → CRITICAL
- Self-signed certificate → HIGH
- Weak cipher suite (RC4, DES, 3DES, EXPORT) → HIGH
- JARM matches known C2 framework → CRITICAL
- JA3S anomaly vs expected service type → MEDIUM

### 7.7 Web Fingerprinting Module (`web`)
**Purpose:** Enumerate web technology stack and detect misconfigurations in HTTP responses.  
**Operations:**
- HTTP(S) GET to all ports serving web traffic
- Parse response headers: `Server`, `X-Powered-By`, `X-Generator`, `X-AspNet-Version`, `Via`, etc.
- Technology fingerprinting (similar to WhatWeb): match response body, headers, cookies against known signatures for CMS, frameworks, CDNs, WAFs
- Detect WAF presence and type
- Security header audit: check for presence and correct configuration of:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - `Cross-Origin-Opener-Policy`
- Directory listing detection
- Robots.txt and sitemap.xml retrieval and parsing
- Admin panel path probing (`/admin`, `/wp-admin`, `/phpmyadmin`, `/manager`, etc.)

**Findings emitted:**
- Missing `Strict-Transport-Security` → MEDIUM
- Missing `Content-Security-Policy` → MEDIUM
- Missing `X-Frame-Options` → MEDIUM
- Server version disclosure in `Server` header → LOW (info leak)
- Accessible admin panel → HIGH
- Directory listing enabled → HIGH
- Technology version disclosed in headers → LOW

### 7.8 C2 Reputation Module (`c2`)
**Purpose:** Determine if the target IP has been observed as a C2 server.  
**Operations:**
- Query threat intel feeds:
  - AbuseIPDB (API key optional; limited free tier)
  - Shodan InternetDB (no key required for basic)
  - GreyNoise (API key optional)
  - Emerging Threats blocklist (free, local cache)
  - MISP community feeds (configurable MISP instance)
- JARM hash matching against RedReady's curated C2 JARM database (updated regularly)
- ASN reputation check (known bulletproof hosting, Tor exit nodes, VPN providers)

**Findings emitted:**
- IP in AbuseIPDB with confidence ≥ 80% → HIGH
- IP in GreyNoise malicious category → HIGH
- JARM matches known C2 → CRITICAL (surfaces from TLS module correlation)
- IP on Emerging Threats blocklist → HIGH
- ASN is known bulletproof hosting → MEDIUM

### 7.9 OSINT Module (`osint`)
**Purpose:** Enrich scan with external intelligence sources.  
**Operations:**
- Shodan host lookup (API key required; gracefully skipped if absent)
- Censys certificate and host search (API key required)
- HaveIBeenPwned email breach check for email addresses found in cert SANs
- Google dork generation (output suggested dorks for manual use — no automated search)

---

## 8. Vulnerability Intelligence Engine

### 8.1 Overview
After all recon modules complete, the intel engine takes the full `ModuleOutput` set and performs correlation. It answers: **"Given what we found, what vulnerabilities exist, how severe are they, how likely are they to be exploited, and how do you fix them?"**

### 8.2 Intelligence Sources

#### 8.2.1 NVD/CVE Feed
- Source: NIST NVD JSON 2.0 feed
- Local cache: SQLite table, updated daily via APScheduler
- Lookup: Given `(vendor, product, version)` from banner grabbing → CPE string → query NVD for matching CVEs
- Stored per CVE: CVE ID, CVSS v3 base score, severity, description, references, CWE IDs, CPE match strings

#### 8.2.2 MITRE ATT&CK
- Source: MITRE ATT&CK STIX 2.1 JSON bundles (Enterprise, ICS, Mobile)
- Local cache: parsed into SQLite from STIX
- Lookup: Given service types and vulnerabilities found → map to relevant ATT&CK techniques (e.g., exposed RDP → T1021.001 Remote Desktop Protocol)
- Output: List of ATT&CK technique IDs with names, descriptions, and mitigations relevant to findings

#### 8.2.3 Sigma Rules
- Source: SigmaHQ official ruleset (git pull on update)
- Local cache: YAML files parsed into SQLite
- Lookup: Given identified service/technique → find Sigma rules that would detect exploitation of this vector
- Output: Per-finding, emit relevant Sigma rule IDs + titles as "detection coverage" metadata — tells a defender what they should be alerting on

#### 8.2.4 Atomic Red Team
- Source: Red Canary Atomic Red Team GitHub repo (git pull on update)
- Local cache: YAML atomics parsed into SQLite
- Lookup: Given ATT&CK technique mapped from a finding → find corresponding Atomic Red Team tests
- Output: Per-finding, list of atomic test names + commands — tells the red teamer exactly how to test this vector

#### 8.2.5 Elastic Detection Rules
- Source: Elastic Security detection-rules GitHub repo
- Local cache: TOML rules parsed into SQLite
- Lookup: Given technique/service/CVE → find relevant Elastic detection rules
- Output: Per-finding, list of Elastic rule names + query excerpts

#### 8.2.6 RedReady Prevalence Database
This is the proprietary differentiator. It is:
- A community-aggregated database of vulnerability observations
- Each record: `(cve_id OR cpe_string, observation_count, last_seen, engagement_context, severity_adjustment)`
- Data sourced from: anonymized user scan submissions (opt-in), public breach databases, exploit-db, Metasploit module adoption rate
- Outputs: `prevalence_score` (0.0–1.0) indicating how commonly this vulnerability is seen in real engagements
- This modifies the final `RiskScore` — a CVSS 9.8 vuln with 0.02 prevalence is lower priority than a CVSS 6.5 with 0.95 prevalence

**Free tier:** Read-only access to prevalence DB (bundled, updated on install/update)  
**Paid tier:** Real-time prevalence data + contribution from your scan results

### 8.3 Risk Scoring Formula
```
RiskScore = (CVSS_base * 0.4) + (Prevalence * 0.35) + (EPSS * 0.25)
```
Where:
- `CVSS_base` — CVSS v3 base score, normalized to 0–1 (divide by 10)
- `Prevalence` — RedReady prevalence score (0–1)
- `EPSS` — FIRST.org EPSS score (probability of exploitation in next 30 days, 0–1)

Final `RiskScore` maps to severity:
| Score | Severity |
|---|---|
| 0.80–1.00 | CRITICAL |
| 0.60–0.79 | HIGH |
| 0.40–0.59 | MEDIUM |
| 0.20–0.39 | LOW |
| 0.00–0.19 | INFO |

### 8.4 Finding Schema
```python
@dataclass
class Finding:
    id: str                          # UUID
    scan_id: str                     # Parent scan UUID
    module: str                      # Which module produced this
    title: str                       # Human-readable title
    description: str                 # Plain-English explanation of what was found
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    risk_score: float                # 0.0–1.0
    cvss_score: float | None
    cve_ids: list[str]               # Associated CVEs
    cwe_ids: list[str]
    attack_techniques: list[str]     # ATT&CK technique IDs (T1234.001)
    sigma_rule_ids: list[str]        # Relevant Sigma detection rules
    atomic_tests: list[str]          # Atomic Red Team test names
    elastic_rules: list[str]         # Elastic detection rule names
    prevalence_score: float | None
    epss_score: float | None
    remediation: str                 # Step-by-step fix in plain English
    references: list[str]            # URLs (CVE, vendor advisory, etc.)
    evidence: str                    # Raw evidence (banner, header, etc.)
    port: int | None
    service: str | None
    raw_data_ids: list[str]          # FK references to RawData records
    created_at: datetime
```

---

## 9. Database Schema

### 9.1 Core Tables

```sql
-- Every scan session
CREATE TABLE scans (
    id              TEXT PRIMARY KEY,       -- UUID
    target_raw      TEXT NOT NULL,          -- Original user input
    target_host     TEXT NOT NULL,          -- Normalized host
    target_ip       TEXT,                   -- Resolved IP
    target_type     TEXT NOT NULL,          -- domain|ip|cidr|url
    status          TEXT NOT NULL,          -- pending|running|complete|failed|cancelled
    profile         TEXT NOT NULL DEFAULT 'default',  -- Scan profile used
    modules_run     TEXT,                   -- JSON array of module names
    started_at      TIMESTAMP,
    completed_at    TIMESTAMP,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id         TEXT,                   -- NULL for local/open source
    notes           TEXT
);

-- Individual findings from scan
CREATE TABLE findings (
    id                  TEXT PRIMARY KEY,
    scan_id             TEXT NOT NULL REFERENCES scans(id),
    module              TEXT NOT NULL,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL,
    severity            TEXT NOT NULL,
    risk_score          REAL NOT NULL,
    cvss_score          REAL,
    cve_ids             TEXT,               -- JSON array
    cwe_ids             TEXT,               -- JSON array
    attack_techniques   TEXT,               -- JSON array
    sigma_rule_ids      TEXT,               -- JSON array
    atomic_tests        TEXT,               -- JSON array
    elastic_rules       TEXT,               -- JSON array
    prevalence_score    REAL,
    epss_score          REAL,
    remediation         TEXT NOT NULL,
    references          TEXT,               -- JSON array of URLs
    evidence            TEXT,
    port                INTEGER,
    service             TEXT,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- All raw data captured during scan (banners, responses, DNS records, etc.)
CREATE TABLE raw_data (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(id),
    module      TEXT NOT NULL,
    data_type   TEXT NOT NULL,    -- banner|dns_record|http_response|cert|jarm|whois|etc.
    host        TEXT,
    port        INTEGER,
    protocol    TEXT,
    data        BLOB NOT NULL,    -- Raw bytes
    metadata    TEXT,             -- JSON: additional context
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Intelligence cache tables (separate from scan data)
CREATE TABLE cve_cache (
    cve_id          TEXT PRIMARY KEY,
    cvss_score      REAL,
    severity        TEXT,
    description     TEXT,
    cpe_matches     TEXT,           -- JSON array of CPE strings
    cwe_ids         TEXT,           -- JSON array
    references      TEXT,           -- JSON array
    published_date  DATE,
    modified_date   DATE,
    cached_at       TIMESTAMP
);

CREATE TABLE prevalence (
    id              TEXT PRIMARY KEY,
    identifier      TEXT NOT NULL UNIQUE,    -- CVE ID or CPE string
    identifier_type TEXT NOT NULL,           -- cve|cpe
    score           REAL NOT NULL,           -- 0.0–1.0
    observation_count INTEGER DEFAULT 0,
    last_seen       TIMESTAMP,
    updated_at      TIMESTAMP
);

CREATE TABLE attack_techniques (
    technique_id    TEXT PRIMARY KEY,        -- T1234.001
    name            TEXT NOT NULL,
    description     TEXT,
    tactics         TEXT,                    -- JSON array of tactic names
    mitigations     TEXT,                    -- JSON array of mitigation descriptions
    detection       TEXT,
    updated_at      TIMESTAMP
);

CREATE TABLE sigma_rules (
    rule_id         TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    description     TEXT,
    level           TEXT,                    -- informational|low|medium|high|critical
    status          TEXT,
    technique_ids   TEXT,                    -- JSON array of ATT&CK IDs
    tags            TEXT,                    -- JSON array
    raw_yaml        TEXT,
    updated_at      TIMESTAMP
);

CREATE TABLE jarm_fingerprints (
    jarm_hash       TEXT PRIMARY KEY,
    tool_name       TEXT NOT NULL,           -- e.g. "Cobalt Strike 4.x"
    version_hint    TEXT,
    category        TEXT,                    -- c2|rat|botnet|proxy
    confidence      REAL,
    source          TEXT,
    updated_at      TIMESTAMP
);
```

---

## 10. Interfaces

### 10.1 CLI Interface

#### Install
```bash
pip install redready
# OR
pipx install redready
```
**System requirements:** Python 3.11+, nmap installed (`apt install nmap` / `brew install nmap`)

#### Core Commands

```bash
# Basic scan with all default modules
redready scan example.com

# Scan with specific profile
redready scan example.com --profile stealth       # Slower, fewer active probes
redready scan example.com --profile aggressive    # Full port scan, all modules
redready scan example.com --profile web-only      # Only DNS + web + TLS modules

# Disable specific modules
redready scan example.com --disable osint --disable subdomain

# Specify output formats (can combine)
redready scan example.com --output json --output html --output pdf

# Scan multiple targets from file
redready scan --targets-file targets.txt

# List all past scans
redready db list

# View findings from a past scan
redready report show <scan-id>
redready report show <scan-id> --severity HIGH CRITICAL

# Export a past scan
redready report export <scan-id> --format html --out ./reports/

# Update intelligence databases
redready intel update

# Show intelligence database status
redready intel status

# Start web UI server
redready serve --host 0.0.0.0 --port 8000

# Interactive mode
redready interactive
```

#### CLI Output Format
Live scan output uses [Rich](https://rich.readthedocs.io/) for formatted terminal display:
- Live progress panel showing currently-running module
- Real-time finding stream with color-coded severity (CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue, INFO=grey)
- Summary table at completion: finding counts by severity, scan duration, modules run
- Remediation list printed below summary

### 10.2 Docker / Container Interface

#### Usage
```bash
# Pull and run (mounts local DB directory)
docker run -v $(pwd)/redready-data:/data redready/redready scan example.com

# Start full stack with web UI
docker-compose up

# Environment variables
REDREADY_DB_URL=postgresql://user:pass@host/redready    # Use PostgreSQL instead of SQLite
REDREADY_REDIS_URL=redis://localhost:6379/0
REDREADY_SHODAN_KEY=<key>
REDREADY_ABUSEIPDB_KEY=<key>
REDREADY_VIRUSTOTAL_KEY=<key>
REDREADY_LOG_LEVEL=INFO
```

#### docker-compose.yml (full stack)
Services:
- `api` — FastAPI server on port 8000
- `worker` — Celery worker for async scan jobs
- `frontend` — Nginx serving built React app on port 3000
- `redis` — Job queue and live event streaming
- `db` — PostgreSQL (for multi-user / paid tier; default is SQLite file mount)

### 10.3 Web Browser UI

#### Pages / Routes
```
/                       — Dashboard: recent scans, global stats
/scans/new              — New scan form (target input, profile selection, module toggles)
/scans                  — Scan history table (filterable, sortable)
/scans/:id              — Live scan view (WebSocket-streamed findings as they arrive)
/scans/:id/report       — Full scan report (findings, severity breakdown, remediation list)
/scans/:id/report/pdf   — PDF export (paid)
/intel                  — Intelligence database status, last-updated timestamps, manual update trigger
/settings               — API key management, scan defaults, notification settings
/account                — Auth, subscription tier (paid)
```

#### Live Scan Streaming (WebSocket)
When a scan is started via the browser:
1. POST `/api/v1/scans` → returns `scan_id`
2. Browser opens `ws://host/api/v1/scans/:id/stream`
3. Backend engine emits events over this socket as modules run:
   ```json
   {"type": "module_started", "module": "dns", "timestamp": "..."}
   {"type": "finding", "finding": {...}}
   {"type": "module_completed", "module": "dns", "finding_count": 3}
   {"type": "scan_completed", "summary": {...}}
   ```
4. Browser renders findings in real time with severity-color-coded cards

#### Scan Report View
- Summary card: target, scan date, duration, total findings by severity
- Severity donut chart
- Findings list (grouped by severity, collapsible)
- Each finding card shows:
  - Title + severity badge
  - Description
  - Evidence (banner, header, etc.) in code block
  - CVSS score + CVE links
  - ATT&CK technique chips (clickable → ATT&CK matrix)
  - Sigma rules (collapsible)
  - Atomic Red Team tests (collapsible)
  - Remediation steps
- Export buttons: JSON, HTML, PDF (PDF = paid)

---

## 11. Scan Profiles

Profiles are named presets that control which modules run and at what intensity:

| Profile | Description | Modules | Port Range | Active Probing |
|---|---|---|---|---|
| `default` | Balanced recon | All | Top 1000 | Yes |
| `stealth` | Minimize detection risk | dns, whois, tls, web (passive) | 80,443,8080,8443 | Minimal |
| `aggressive` | Maximum coverage | All + osint | All 65535 | Yes |
| `web-only` | Web/HTTP focused | dns, tls, web, subdomain | 80,443,8080,8443,8000-9000 | Yes |
| `network` | Network focused | dns, whois, ports, banner, tls, c2 | Top 1000 | Yes |
| `quick` | Fast surface scan | dns, ports, banner | Top 100 | No |

Custom profiles can be defined in `~/.redready/profiles.yaml`.

---

## 12. Configuration

### 12.1 Config Hierarchy (highest to lowest priority)
1. CLI flags
2. Environment variables (`REDREADY_*`)
3. `.redready.yaml` in current directory
4. `~/.redready/config.yaml` (user config)
5. Built-in defaults

### 12.2 Config File Schema (`~/.redready/config.yaml`)
```yaml
database:
  url: sqlite:///~/.redready/redready.db   # Override with postgres:// for paid tier

intel:
  auto_update: true
  update_interval_hours: 24

api_keys:
  shodan: ""
  censys_api_id: ""
  censys_api_secret: ""
  abuseipdb: ""
  greynoise: ""
  virustotal: ""

scan:
  default_profile: default
  timeout_per_module: 120        # seconds
  max_concurrent_modules: 5
  port_scan_rate: 1000           # packets/sec (nmap --min-rate)

reporting:
  default_formats: [terminal, json]
  output_dir: ./redready-reports

notifications:
  # Paid tier: webhook/email notifications when scheduled scans complete
  webhook_url: ""
  email: ""
```

---

## 13. Error Handling & Resilience

- Every module runs inside a try/except. A module failure emits an error event but does not stop the pipeline.
- Timeouts are enforced per-module via asyncio `wait_for`.
- nmap requires root/CAP_NET_RAW. If not available, falls back to TCP connect scan (`-sT`) with a warning.
- If a target is unreachable (all ports filtered, no DNS resolution), scan completes with a `host_unreachable` finding at INFO severity.
- Rate limiting: configurable delay between requests (`--rate-limit`). Default respects polite scanning behavior.
- All errors logged to `raw_data` table with `data_type = "error"` for post-scan debugging.

---

## 14. Open-Core Business Model

### Free Tier (OSS)
- Full core engine — all modules
- CLI and Docker interfaces
- Local SQLite storage
- Bundled (static) prevalence database (updated on each release)
- Community support

### Paid Tier — Pro
- Web browser UI with team accounts
- PostgreSQL cloud sync (scan history accessible from any device)
- Real-time prevalence database (live, community-updated)
- Scheduled scans (run automatically on interval)
- Email/webhook notifications on scan completion
- PDF export
- Increased OSINT API rate limits (managed keys)
- Priority support

### Paid Tier — Enterprise
- Self-hosted cloud deployment (Helm chart / Terraform modules)
- SSO / SAML integration
- RBAC — role-based access to scan results
- API access (build your own integrations)
- SLA support
- Custom prevalence data import (bring your own engagement data)
- White-label reporting

---

## 15. Security Considerations for the Tool Itself

- **Never scan targets without authorization.** CLI shows a prominent disclaimer on first run requiring acknowledgment.
- A `--confirm-authorized` flag must be passed (or set in config) for the disclaimer to be bypassed in automated contexts.
- Stored scan data (banners, raw responses) may contain sensitive information — SQLite DB is stored in `~/.redready/` with mode 600.
- API keys stored in config file — warn if file is world-readable.
- Browser UI should bind to `127.0.0.1` by default, never `0.0.0.0`, unless explicitly configured.
- Web UI in multi-user mode (paid) requires auth. No unauthenticated endpoints that expose scan data.

---

## 16. Development Phases / Roadmap

### Phase 1 — Core Engine MVP
**Goal:** Working CLI that scans a target and produces findings.

Tasks:
- [ ] Project scaffold: pyproject.toml, folder structure, CI (GitHub Actions)
- [ ] BaseModule + orchestrator
- [ ] DNS module
- [ ] Port module (nmap wrapper)
- [ ] Banner grabbing module
- [ ] TLS/cert module
- [ ] SQLAlchemy models + SQLite setup + Alembic
- [ ] NVD/CVE intel source + local cache
- [ ] Basic risk scoring
- [ ] Rich terminal output
- [ ] JSON report output
- [ ] `redready scan` CLI command

**Exit criteria:** `redready scan example.com` produces a color-formatted terminal report with CVE-matched findings.

### Phase 2 — Full Intelligence Engine
- [ ] MITRE ATT&CK integration
- [ ] Sigma rule integration
- [ ] Atomic Red Team integration
- [ ] Elastic detection rule integration
- [ ] EPSS score integration (FIRST.org API)
- [ ] Final risk score formula implementation
- [ ] Prevalence database (initial static version)
- [ ] Web fingerprinting module
- [ ] WHOIS/RDAP module
- [ ] Subdomain enumeration module

### Phase 3 — API + Browser UI
- [ ] FastAPI app with all REST routes
- [ ] WebSocket live scan streaming
- [ ] React frontend: all pages
- [ ] Docker + docker-compose setup
- [ ] HTML report export

### Phase 4 — OPSEC & Red Team Specific Features
- [ ] JARM fingerprinting + C2 detection database
- [ ] JA3/JA3S fingerprinting
- [ ] C2 reputation module (AbuseIPDB, GreyNoise)
- [ ] OSINT module (Shodan, Censys)
- [ ] Stealth/aggressive scan profiles
- [ ] Admin panel detection

### Phase 5 — Open-Core Infrastructure
- [ ] Scan profiles system
- [ ] PostgreSQL support (paid tier backend)
- [ ] Scheduled scans (APScheduler)
- [ ] Auth system for web UI
- [ ] PDF export
- [ ] Real-time prevalence DB pipeline
- [ ] Paid tier account system

---

## 17. Key Conventions for Contributors

- **All async.** Every module method is `async def`. Use `asyncio.gather` for parallel ops within a module.
- **Type everything.** Full type annotations on all public functions. mypy strict mode.
- **Tests for every module.** Unit tests use mocked network responses (no live network in CI). Integration tests marked with `@pytest.mark.integration` and run separately.
- **Findings are immutable.** Once a `Finding` is created and stored, it is never modified. New analysis creates new findings.
- **Raw data is sacred.** Everything goes in `raw_data`. Never discard a response.
- **No global state.** The engine is instantiated per scan. Config is injected, not imported globally.
- **Commit style:** Conventional Commits (`feat:`, `fix:`, `intel:`, `docs:`, `refactor:`)

---

## 18. Glossary

| Term | Definition |
|---|---|
| Target | User-supplied endpoint (domain, IP, URL, CIDR) |
| Scan | One complete execution of the module pipeline against one target |
| Finding | A structured, scored observation produced by a module |
| Raw Data | Unprocessed bytes/strings captured during scanning (stored verbatim) |
| Banner | Service response string used to identify software and version |
| JARM | TLS fingerprinting method that identifies server-side TLS stack |
| JA3 / JA3S | TLS fingerprinting based on ClientHello / ServerHello parameters |
| CPE | Common Platform Enumeration — standardized software identifier used to query NVD |
| EPSS | Exploit Prediction Scoring System — probability a CVE will be exploited in 30 days |
| Prevalence | RedReady-specific metric: how commonly a vuln is observed in real engagements |
| Profile | Named preset controlling which modules run and at what intensity |
| Intel DB | Local cache of vulnerability intelligence sources |
| Open-core | Business model where the core is free/OSS; additional features are paid |

---

*End of RedReady Master Technical Specification v0.1.0-draft*
