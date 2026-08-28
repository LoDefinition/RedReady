# RedReady

Open-source pre-engagement OPSEC validation and reconnaissance scanner for red teamers,
penetration testers, and security engineers.

RedReady performs layered recon against a target (domain, IP, CIDR, URL), grabs banners from every
reachable service, cross-references findings against vulnerability intelligence (currently NVD/CVE),
stores everything in a queryable database, and prints a prioritized report with remediation guidance.

> **Only scan systems you are authorized to test.** RedReady requires an explicit authorization
> acknowledgement before its first scan.

## Status

Phase 1 (core engine MVP) of the [master specification](docs/SPEC.md):

- `dns`, `ports` (nmap), `banner` and `tls` recon modules
- NVD/CVE correlation with a local SQLite intelligence cache
- Risk scoring, Rich terminal output and JSON reports
- Persistent scan / finding / raw-data storage with Alembic migrations

## Install

Requirements: Python 3.11+ and [nmap](https://nmap.org/) on `PATH`
(`apt install nmap` / `brew install nmap`).

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Balanced scan with the default profile
redready scan example.com

# Profiles and module selection
redready scan example.com --profile quick
redready scan example.com --disable tls

# Reports
redready scan example.com --output json --out ./reports
redready report show <scan-id> --severity HIGH --severity CRITICAL
redready report export <scan-id> --format json --out ./reports

# Scan history and schema
redready db list
redready db upgrade
redready db path

# Available scan profiles
redready profiles

# Vulnerability intelligence cache
redready intel status
redready intel update            # pulls recent CVEs from NVD
```

Non-interactive contexts must pass `--confirm-authorized` (or set
`scan.confirm_authorized: true` in the config file) to bypass the authorization prompt.

## Configuration

Configuration is resolved highest-priority first: CLI flags, `REDREADY_*` environment variables,
`.redready.yaml` in the working directory, `~/.redready/config.yaml`, then built-in defaults.
See [docs/SPEC.md](docs/SPEC.md#12-configuration) for the full schema.

## Development

```bash
pip install -e ".[dev]"
ruff check .
mypy redready
pytest                       # unit tests, no network access required
```

## License

MIT
