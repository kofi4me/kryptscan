# Deploy Kryptnet on Hetzner Cloud

Hetzner Cloud is a good production target for Kryptnet because the app needs a real Linux server, persistent storage, HTTPS, and eventually scanner tools that may not fit well on serverless-style hosting.

Target domain:

```text
https://kryptscan.kryptnet.org
```

## 1. Recommended Hetzner Server

For the first public deployment:

```text
Ubuntu 24.04 LTS
4 vCPU
8 GB RAM
80 GB disk or larger
Location close to your users
```

If the full scanner toolchain feels slow, upgrade to 8 vCPU / 16 GB RAM.

## 2. Hetzner Firewall

Allow only:

```text
22/tcp    SSH
80/tcp    HTTP for HTTPS certificate issuance
443/tcp   HTTPS
```

Do not expose port `8000` publicly. Caddy will proxy HTTPS traffic to the app internally.

## 3. DNS

After creating the Hetzner server, copy its public IPv4 address.

In the DNS manager for `kryptnet.org`, create:

```text
Type: A
Name: kryptscan
Value: <hetzner-server-ip>
TTL: Auto or 300
```

The result should be:

```text
kryptscan.kryptnet.org -> <hetzner-server-ip>
```

## 4. Server Setup

SSH into the server:

```bash
ssh root@<hetzner-server-ip>
```

Update the server:

```bash
apt update && apt upgrade -y
```

Install Docker:

```bash
apt install -y ca-certificates curl git ufw
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo ${UBUNTU_CODENAME:-$VERSION_CODENAME}) stable" > /etc/apt/sources.list.d/docker.list
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Enable firewall:

```bash
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
```

## 5. Upload Kryptnet

Option A: GitHub private repo:

```bash
cd /opt
git clone <your-private-github-repo-url> kryptnet
cd /opt/kryptnet
```

Option B: copy the project folder from your computer to:

```text
/opt/kryptnet
```

## 6. Production Environment

Create the production env file:

```bash
cd /opt/kryptnet
cp .env.production.example .env.scanner
```

Edit:

```bash
nano .env.scanner
```

Minimum required values:

```env
KRYPTNET_DOMAIN=kryptscan.kryptnet.org
KRYPTNET_EMAIL=security@kryptnet.org
APP_ENV=production
APP_SECRET=<long-random-secret>
TRUSTED_HOSTS=kryptscan.kryptnet.org
SESSION_COOKIE_SECURE=true
EMAIL_DELIVERY=smtp
EMAIL_FROM=security@kryptnet.org
SMTP_HOST=<smtp-host>
SMTP_USERNAME=<smtp-user>
SMTP_PASSWORD=<smtp-password>
KRYPTNET_PAYMENT_WEBHOOK_SECRET=<real-webhook-secret>
PAYMENT_DEMO_MODE=false
PAYMENT_REQUIRED=false
OPENAI_API_KEY=<openai-api-key>
SCANNER_BACKEND=worker
SCANNER_WORKER_URL=http://kryptnet-scanner:8000
SCANNER_MIN_FULL_SCAN_SECONDS=600
ALLOW_PRIVATE_NETWORK_TARGETS=false
```

Generate `APP_SECRET`:

```bash
openssl rand -hex 32
```

## 7. Start Kryptnet

```bash
docker compose --env-file .env.scanner -f docker-compose.production.yml build
docker compose --env-file .env.scanner -f docker-compose.production.yml up -d
```

Caddy will automatically request the HTTPS certificate for `kryptscan.kryptnet.org`.

## 8. Verify Deployment

```bash
docker compose --env-file .env.scanner -f docker-compose.production.yml ps
curl https://kryptscan.kryptnet.org/health
```

Expected:

```json
{"status":"ok","app":"Kryptnet Security Assessment","scanner_backend":"worker"}
```

Open:

```text
https://kryptscan.kryptnet.org
```

## 9. Logs

App logs:

```bash
docker compose --env-file .env.scanner -f docker-compose.production.yml logs -f kryptnet-app
```

HTTPS proxy logs:

```bash
docker compose --env-file .env.scanner -f docker-compose.production.yml logs -f caddy
```

## 10. Live Test

1. Open `https://kryptscan.kryptnet.org`.
2. Verify email with OTP.
3. Complete registration.
4. Select Vulnerability Assessment or Ethical Pen-Testing.
5. Enter an authorized target and confirm target authorization.
6. Confirm the scanner worker health shows the installed tools.
7. For pre-payment testing, keep `PAYMENT_REQUIRED=false`. After payment API integration, set `PAYMENT_REQUIRED=true`.
8. Configure payment webhook:

```text
POST https://kryptscan.kryptnet.org/api/payments/webhook/kryptnet
Header: X-KryptNet-Webhook-Secret
```

9. Confirm the scan progresses through staged scanner work and creates/downloads a PDF report.
10. Check Scanner Health in the dashboard.

## Scanner Worker Quality Controls

Full scans use the scanner worker and should not complete as an instant mock result. The worker uses:

```env
SCANNER_BACKEND=worker
SCANNER_WORKER_URL=http://kryptnet-scanner:8000
SCANNER_TOOL_TIMEOUT_SECONDS=300
SCANNER_MAX_OUTPUT_CHARS=30000
SCANNER_MIN_FULL_SCAN_SECONDS=600
OPENAI_API_KEY=<openai-api-key>
OPENAI_MODEL=gpt-5-mini
OPENAI_BASE_URL=https://api.openai.com/v1
CLOUD_CHECKS_ENABLED=false
```

Set `SCANNER_MIN_FULL_SCAN_SECONDS=600` for a 10-minute professional scan window. Lower it only for development smoke tests.

If Scanner Health still shows missing tools after code updates, rebuild and restart the scanner worker:

```bash
cd /opt/kryptnet-services/kryptscan-app
git pull
docker-compose -f docker-compose.scanner.yml build --no-cache
docker-compose -f docker-compose.scanner.yml up -d
curl -s http://127.0.0.1:5200/health
```

Remaining optional items:

- `OpenAI AI triage` becomes available when `OPENAI_API_KEY` is present in the scanner worker environment.
- `Cloud credential checks` becomes available when `CLOUD_CHECKS_ENABLED=true` and the MSP has a cloud-readiness process.
- `Greenbone/OpenVAS Python client` requires `python-gvm` plus a running Greenbone/OpenVAS service.
- ZAP, Gitleaks, Prowler, and ScoutSuite require the updated scanner worker image to be rebuilt if an older container is still running.

## 11. Updating the App

```bash
cd /opt/kryptnet
git pull
docker compose --env-file .env.scanner -f docker-compose.production.yml build
docker compose --env-file .env.scanner -f docker-compose.production.yml up -d
```

## 12. Backup

```bash
cd /opt/kryptnet
tar -czf kryptnet-data-$(date +%F).tgz data
```

Back up `data/` regularly because it contains the SQLite database and generated reports.
