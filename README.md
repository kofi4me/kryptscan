# Kryptnet Security Assessment

Kryptnet Security Assessment is a commercial cybersecurity assessment platform for businesses, MSPs, and IT professionals. It focuses on three things that matter on day one:

- authorization guardrails before any scan is launched
- a pluggable scanner layer so free previews, full vulnerability scans, and ethical pen-testing use the right backend
- executive and technical reporting with severity counts, graphs, remediation priorities, and scan history

## Why this architecture

For a resale product, the scanning engine and the commercial wrapper should be separated. This codebase uses a provider abstraction:

- `free_preview`: limited vulnerability preview for free scans with web-only summary output
- `mock`: boots instantly and generates realistic sample findings so product, sales, and reporting flows can be validated without a scanner
- `greenbone`: real integration path using Greenbone/OpenVAS through the official `python-gvm` library
- `nuclei`: real integration path using the Nuclei CLI for template-driven web and network checks
- `adaptive`: routes website targets to Nuclei when available and network targets to Greenbone when available, otherwise falls back to visible `mock` mode

The app is intentionally structured so you can add an OEM-approved commercial connector later if you secure partner licensing. Tenable currently positions itself as a market leader and exposes API-based integration points for licensed customers, but licensing should be reviewed before embedding it in a commercial multi-tenant product. Greenbone is the better default for a self-hosted MVP because it is documented as open source and has an official Python library.

## Features in this MVP

- Work-email verification with one-time codes
- Domain-based authorization checks before targets can be scanned
- Two selectable workflows:
  - Vulnerability Assessment with a free partial scan and a paid full scan
  - Ethical Pen-Testing as a paid-only full-stack testing service
- Single target intake for a domain or IP, with backend scan-path selection
- Risk-severity checks and weighted risk scoring
- Executive summary plus technical findings
- Severity, service, and trend graphs in the report UI
- Web summary for free vulnerability scans
- PDF assessment report generation and email delivery for paid full scans
- Multi-tenant organization records keyed off verified work-email domains
- Greenbone/OpenVAS adapter scaffold and refresh flow

## Important authorization note

This MVP enforces same-domain authorization for websites and requires an ownership domain for network targets. For a production launch, strengthen this with at least one of:

- DNS TXT proof for the ownership domain
- signed authorization letters for MSP-managed client environments
- reverse-DNS or contract-backed asset inventory checks for IP ranges

Email-domain verification is a strong first gate, but by itself it is not sufficient proof of IP range ownership in every case.

The Ethical Pen-Testing mode is intended for MSP-led testing under written authorization and agreed rules of engagement. It should stay scoped, auditable, and non-destructive unless a future production workflow adds explicit human approval and client sign-off for a specific test.

## Ethical Pen-Testing Toolchain

The product now exposes a full-stack ethical testing workflow map for MSP teams:

- Web and API testing with Nuclei, OWASP-style checks, HTTP header review, and session control review
- Network and service review with Greenbone/OpenVAS, service fingerprinting, and TLS posture checks
- Cloud and SaaS posture workflows for public exposure, configuration review, and identity controls
- Identity and access review for MFA, password policy, and privileged access evidence
- AI-assisted triage, remediation queues, PDF reports, and client-ready delivery

## Current User Workflow

The app now supports this production user flow:

1. User verifies email with OTP.
2. New user completes registration with name, title, role, company, address, phone number, reason for testing, and safe-use acceptance.
3. Returning user logs in by verified email.
4. User selects Vulnerability Assessment or Ethical Pen-Testing.
5. Vulnerability Assessment can run a free partial scan with web summary only.
6. Full Vulnerability Scan and Ethical Pen-Testing require one-time KryptNet checkout payment.
7. Paid reports are generated as PDFs and delivered to/downloaded by the verified user.

## KryptNet Payment API Integration Path

The dashboard includes three one-time service package buttons:

- Starter
- Professional
- MSP Scale

Each button creates a KryptNet Payment API checkout link for debit or credit card payment. The app does not collect card numbers, CVC, routing numbers, or bank account numbers.

Production access activates only after `/api/payments/webhook/kryptnet` receives a verified payment event. Configure:

```env
KRYPTNET_PAYMENT_API_URL=https://payments.kryptnet.com/api
KRYPTNET_PAYMENT_WEBHOOK_SECRET=replace-with-payment-webhook-secret
PAYMENT_DEMO_MODE=false
```

## Quick start

1. Create a virtual environment and install dependencies:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

## Virtual Scanner Worker

Kryptnet can bundle its vulnerability assessment and ethical pen-testing tools inside a virtual scanner environment instead of installing scanners on a local workstation.

Use:

```bash
cp .env.scanner.example .env.scanner
docker compose -f docker-compose.scanner.yml build
docker compose -f docker-compose.scanner.yml up -d
```

The scanner worker includes Nuclei, Nmap, OWASP ZAP baseline, Nikto, SSLyze, testssl.sh, Amass, Subfinder, Trivy, httpx, Naabu, dnsx, Katana, wafw00f, WhatWeb, Semgrep, Gitleaks, Grype, Checkov, Prowler, and ScoutSuite. Set `SCANNER_BACKEND=kryptnet_toolkit` so KryptNet runs both Vulnerability Assessment and Ethical Pen-Testing through the bundled tools. Use the Scanner Health dashboard after deployment to confirm readiness.

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
