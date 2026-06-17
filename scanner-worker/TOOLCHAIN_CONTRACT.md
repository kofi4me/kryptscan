# KryptNet Toolchain Contract

KryptNet is the only user-facing interface. Users do not run scanner commands directly.

Flow:

1. User verifies email and completes registration.
2. User selects Vulnerability Assessment or Ethical Pen-Testing.
3. User completes KryptNet payment checkout.
4. User enters the approved target and service-specific fields.
5. KryptNet validates account, payment, target authorization, rate limits, and safe-use controls.
6. KryptNet backend selects the scanner engine.
7. The scanner worker runs bundled tools with fixed, scoped arguments.
8. Tool output is parsed into KryptNet findings.
9. KryptNet generates dashboard results and PDF reports.

The virtual scanner deployment sets:

```env
SCANNER_BACKEND=kryptnet_toolkit
```

With this setting, both Vulnerability Assessment and Ethical Pen-Testing run through the bundled KryptNet toolkit engine. The frontend remains simple, while the backend orchestrates Nuclei, Nmap, OWASP ZAP, Nikto, SSLyze, testssl.sh, Amass, Subfinder, Trivy, httpx, Naabu, dnsx, Katana, wafw00f, WhatWeb, Semgrep, Gitleaks, Grype, Checkov, Prowler, ScoutSuite readiness, cloud checks, and AI triage where configured.

Users never provide arbitrary shell commands. Tools run only against the approved target submitted through KryptNet.
