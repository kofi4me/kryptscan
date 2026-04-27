# Sentinel Scope

Sentinel Scope is a commercial-ready MVP for an authorized vulnerability assessment platform aimed at direct customers and MSPs. It focuses on three things that matter on day one:

- authorization guardrails before any scan is launched
- a pluggable scanner layer so you can switch from mock to a production engine
- executive and technical reporting with severity counts, graphs, remediation priorities, and scan history

## Why this architecture

For a resale product, the scanning engine and the commercial wrapper should be separated. This codebase uses a provider abstraction:

- `mock`: boots instantly and generates realistic sample findings so product, sales, and reporting flows can be validated without a scanner
- `greenbone`: real integration path using Greenbone/OpenVAS through the official `python-gvm` library
- `nuclei`: real integration path using the Nuclei CLI for template-driven web and network checks
- `adaptive`: routes website targets to Nuclei when available and network targets to Greenbone when available, otherwise falls back to visible `mock` mode

The app is intentionally structured so you can add an OEM-approved commercial connector later if you secure partner licensing. Tenable currently positions itself as a market leader and exposes API-based integration points for licensed customers, but licensing should be reviewed before embedding it in a commercial multi-tenant product. Greenbone is the better default for a self-hosted MVP because it is documented as open source and has an official Python library.

## Features in this MVP

- Work-email verification with one-time codes
- Domain-based authorization checks before targets can be scanned
- Single target intake for a domain or IP, with backend scan-path selection
- Risk-severity checks and weighted risk scoring
- Executive summary plus technical findings
- Severity, service, and trend graphs in the report UI
- PDF assessment report generation and email delivery to the verified work address
- Multi-tenant organization records keyed off verified work-email domains
- Greenbone/OpenVAS adapter scaffold and refresh flow

## Important authorization note

This MVP enforces same-domain authorization for websites and requires an ownership domain for network targets. For a production launch, strengthen this with at least one of:

- DNS TXT proof for the ownership domain
- signed authorization letters for MSP-managed client environments
- reverse-DNS or contract-backed asset inventory checks for IP ranges

Email-domain verification is a strong first gate, but by itself it is not sufficient proof of IP range ownership in every case.

## Quick start

1. Create a virtual environment and install dependencies:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. Copy `.env.example` to `.env` and adjust the values you need.

3. Run the app:

   ```powershell
   python -m uvicorn app.main:app --reload
   ```

4. Open [http://127.0.0.1:8000](http://127.0.0.1:8000)

In `console` email mode the verification code is printed to the terminal. That keeps local development simple without blocking the auth flow.

If your Windows Python environment ignores user-site packages, this repository also supports a workspace-local install:

```powershell
pip install --target .python_packages -r requirements.txt
$env:PYTHONPATH = ".python_packages"
python -m uvicorn app.main:app --reload
```

## Switching to Greenbone

Install the Greenbone dependency set:

```powershell
pip install -r requirements-greenbone.txt
```

Then set:

```env
SCANNER_BACKEND=greenbone
GREENBONE_CONNECTION=tls
GREENBONE_HOST=your-scanner-host
GREENBONE_PORT=9390
GREENBONE_USERNAME=your-gvmd-user
GREENBONE_PASSWORD=your-gvmd-password
```

The included adapter uses the official Greenbone management protocol flow: create target, create task, start task, then poll for completion and import the report into the app.

## Switching to Nuclei

Install the Nuclei CLI from the official ProjectDiscovery release or package for your platform, ensure it is on `PATH`, then set:

```env
SCANNER_BACKEND=nuclei
NUCLEI_PATH=nuclei
NUCLEI_SEVERITY=critical,high,medium,low
```

If you want automatic backend selection by target type:

```env
SCANNER_BACKEND=adaptive
```

In `adaptive` mode:

- website/domain targets prefer Nuclei
- network/IP targets prefer Greenbone
- if the preferred engine is not installed, the app transparently falls back to `mock` and the dashboard will show that actual backend

This workspace is also configured to support a local Windows install of `nuclei.exe` inside `tools/nuclei`. The app runs Nuclei with workspace-local runtime directories under `data/nuclei` so it does not depend on writable `%APPDATA%` folders.

## Scanner recommendation

For the current codebase I chose Greenbone/OpenVAS as the implemented engine because it is practical to self-host inside your own product. If you want the most recognizable commercial engine for enterprise buyers, keep the provider abstraction and add a partner-approved Tenable connector rather than hard-coding the platform to a single vendor.

## References

- [Greenbone Community Edition architecture](https://greenbone.github.io/docs/latest/architecture.html)
- [Greenbone `python-gvm` library](https://greenbone.github.io/python-gvm/)
- [Greenbone `gvm-tools` scan workflow example](https://greenbone.github.io/gvm-tools/scripting.html)
- [ProjectDiscovery Nuclei running guide](https://docs.projectdiscovery.io/tools/nuclei/running)
- [Tenable Vulnerability Management documentation](https://docs.tenable.com/vulnerability-management.htm)
- [Tenable partner ecosystem](https://www.tenable.com/partners)
- [ProjectDiscovery Nuclei overview](https://docs.projectdiscovery.io/opensource/nuclei)
