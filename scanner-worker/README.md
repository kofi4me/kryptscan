# Kryptnet Scanner Worker

This folder defines the virtual scanner environment for Kryptnet. It bundles the vulnerability assessment and ethical pen-testing tools into a container instead of installing them on a local Windows machine.

Bundled tools include:

- Nuclei
- Nmap
- OWASP ZAP baseline
- Nikto
- SSLyze
- testssl.sh
- Amass
- Subfinder
- Trivy
- ProjectDiscovery httpx
- Naabu
- dnsx
- Katana
- wafw00f
- WhatWeb
- Semgrep
- Gitleaks
- Grype
- Checkov
- Prowler

Use this flow on the virtual server:

```bash
cp .env.scanner.example .env.scanner
docker compose -f docker-compose.scanner.yml build
docker compose -f docker-compose.scanner.yml up -d
```

After startup, open the app and check the Scanner Health dashboard. Missing tools should be corrected in the Dockerfile or environment configuration.

Security notes:

- Run this worker only for verified users, completed registration, completed payment, and authorized targets.
- Keep `ALLOW_PRIVATE_NETWORK_TARGETS=false` for public deployments.
- Use a separate isolated scanner worker for internal network testing.
- Store `APP_SECRET`, SMTP credentials, payment webhook secrets, and AI API keys in the hosting secret manager.
