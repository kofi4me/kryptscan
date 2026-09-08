# Kryptnet Security Deployment Checklist

Before commercial deployment, set these values in `.env` or the hosting secret manager:

```env
APP_ENV=production
APP_SECRET=replace-with-a-long-random-secret
SESSION_COOKIE_SECURE=true
CSRF_COOKIE_NAME=kryptnet_csrf
TRUSTED_HOSTS=kryptscan.kryptnet.org
TRUSTED_PROXY_IPS=127.0.0.1,::1
RATE_LIMIT_ENABLED=true
MAX_REQUEST_BODY_BYTES=1048576
ALLOW_PRIVATE_NETWORK_TARGETS=false
KRYPTNET_PAYMENT_API_URL=https://payments.kryptnet.com/api
KRYPTNET_PAYMENT_WEBHOOK_SECRET=replace-with-payment-webhook-secret
PAYMENT_DEMO_MODE=false
```

Use `ALLOW_PRIVATE_NETWORK_TARGETS=true` only when the scanner runs inside an isolated MSP-controlled network where internal IP testing is expected and authorized.

Payment buttons should point to the KryptNet Payment API checkout. Do not collect card numbers, CVV, routing numbers, or account numbers inside this application.

The application rejects direct payment submissions. Use KryptNet debit/credit checkout plus the verified `/api/payments/webhook/kryptnet` webhook before activating real production access. The payment provider must send `X-KryptNet-Webhook-Secret` with the configured `KRYPTNET_PAYMENT_WEBHOOK_SECRET`.

Never deploy production with `PAYMENT_DEMO_MODE=true`. Demo mode is only for local testing because it activates paid access immediately after checkout link creation.

Keep scanner workers isolated from the web application process. Store reports outside the public static directory and require authenticated report downloads.

Reports are served only from the configured reports directory and PDF downloads are marked `no-store`.

Trust forwarded client IP headers only from the reverse proxy itself. Do not expose the FastAPI app port directly to the internet; keep public traffic routed through nginx or Caddy with HTTPS.

## Ethical Tool Connectors

Prefer the bundled virtual scanner worker instead of installing tools on an operator laptop:

```bash
cp .env.scanner.example .env.scanner
docker compose -f docker-compose.scanner.yml build
docker compose -f docker-compose.scanner.yml up -d
```

Scanner tools are installed inside the worker image. Set paths when overriding defaults:

```env
NMAP_PATH=nmap
SSLYZE_PATH=sslyze
TESTSSL_PATH=testssl.sh
ZAP_BASELINE_PATH=zap-baseline.py
NIKTO_PATH=nikto
AMASS_PATH=amass
SUBFINDER_PATH=subfinder
TRIVY_PATH=trivy
HTTPX_PATH=httpx
NAABU_PATH=naabu
DNSX_PATH=dnsx
KATANA_PATH=katana
WAFW00F_PATH=wafw00f
WHATWEB_PATH=whatweb
SEMGREP_PATH=semgrep
GITLEAKS_PATH=gitleaks
GRYPE_PATH=grype
CHECKOV_PATH=checkov
PROWLER_PATH=prowler
SCOUTSUITE_PATH=ScoutSuite
```

Cloud checks are disabled by default because they require client-approved read-only credentials:

```env
CLOUD_CHECKS_ENABLED=false
```

AI triage is enabled only when an API key is configured:

```env
OPENAI_API_KEY=
OPENAI_MODEL=gpt-5-mini
OPENAI_BASE_URL=https://api.openai.com/v1
```

Temporary launch testing can be capped per registered tester account:

```env
LAUNCH_SCAN_LIMIT_PER_USER=3
```

Set `LAUNCH_SCAN_LIMIT_PER_USER=0` only when the public launch limit should be removed.

## Admin Monitoring Console

The admin console is intentionally not linked from the public homepage. Open it directly:

```text
https://kryptscan.kryptnet.org/kryptnet-admin
```

Promote only trusted operator accounts after the user has registered and verified their email:

```bash
cd /opt/kryptnet-services/kryptscan-app
python3 - <<'PY'
import sqlite3

db = "data/vuln_app.db"
email = "kofi4me@gmail.com"

with sqlite3.connect(db) as connection:
    connection.execute("UPDATE users SET role = 'admin' WHERE email = ?", (email,))
    updated = connection.total_changes

print(f"Admin role updates: {updated}")
PY
```

Admin accounts can monitor user registrations, verification status, login failures, locked accounts, scan progress, scan failures, report email delivery, PDF downloads, and audit events. Keep admin access limited to named operator accounts and review failed admin login events regularly.

The Ethical Pen-Testing backend uses conservative connector defaults: passive reconnaissance for Amass/Subfinder, DNS and HTTP fingerprinting, limited-rate service discovery, shallow application crawling, WAF detection, baseline ZAP checks, TLS posture tools, Nikto web server review, Trivy/Semgrep/Gitleaks/Grype/Checkov local posture review, cloud readiness checks, and report-only AI summarization. It must not be used without approved scope and rules of engagement.
