# Kryptnet Web Deployment Runbook

This runbook deploys Kryptnet to a public HTTPS domain while we continue improving the app.

## 1. Server Requirements

Use a Linux VPS/cloud VM with:

- Ubuntu 22.04 or 24.04 LTS
- Docker and Docker Compose plugin
- At least 4 vCPU and 8 GB RAM for the bundled scanner worker
- Ports 80 and 443 open to the internet
- A domain or subdomain pointed to the server IP

Recommended DNS:

```text
pentest.kryptnet.org  A  <server-public-ip>
```

## 2. Copy Project to Server

From the server:

```bash
git clone <your-private-repo-url> kryptnet
cd kryptnet
```

Or copy the `Vuln_App` folder to the server as `/opt/kryptnet`.

## 3. Create Production Environment

```bash
cp .env.production.example .env.scanner
```

Edit `.env.scanner` and set:

```env
KRYPTNET_DOMAIN=pentest.kryptnet.org
KRYPTNET_EMAIL=security@kryptnet.org
APP_SECRET=<long-random-secret>
TRUSTED_HOSTS=pentest.kryptnet.org
EMAIL_FROM=security@kryptnet.org
SMTP_HOST=<smtp-host>
SMTP_USERNAME=<smtp-user>
SMTP_PASSWORD=<smtp-password>
KRYPTNET_PAYMENT_API_URL=<real-kryptnet-payment-api-url>
KRYPTNET_PAYMENT_WEBHOOK_SECRET=<real-webhook-secret>
PAYMENT_DEMO_MODE=false
OPENAI_API_KEY=<openai-api-key>
```

Do not commit `.env.scanner`.

Generate a strong app secret:

```bash
openssl rand -hex 32
```

## 4. Start Web Deployment

```bash
docker compose --env-file .env.scanner -f docker-compose.production.yml build
docker compose --env-file .env.scanner -f docker-compose.production.yml up -d
```

Caddy automatically requests and renews HTTPS certificates.

## 5. Check Health

```bash
docker compose --env-file .env.scanner -f docker-compose.production.yml ps
curl -I https://pentest.kryptnet.org
curl https://pentest.kryptnet.org/health
```

Expected health response:

```json
{"status":"ok","app":"Kryptnet Security Assessment","scanner_backend":"kryptnet_toolkit"}
```

## 6. Payment Webhook

Configure the KryptNet Payment API to call:

```text
POST https://pentest.kryptnet.org/api/payments/webhook/kryptnet
```

Required header:

```text
X-KryptNet-Webhook-Secret: <KRYPTNET_PAYMENT_WEBHOOK_SECRET>
```

Expected JSON fields:

```json
{
  "provider_reference": "kryptnet_reference_from_checkout",
  "status": "paid",
  "plan": "professional",
  "amount_cents": 29900,
  "currency": "USD",
  "payer_email": "client@example.com"
}
```

Paid access activates only after a verified webhook event.

## 7. Live Test Checklist

1. Open `https://pentest.kryptnet.org`.
2. Enter email and verify OTP.
3. Complete registration and safe-use acceptance.
4. Select Vulnerability Assessment.
5. Run Free Scan and confirm web-only summary appears.
6. Select Full Scan and confirm payment is required.
7. Complete checkout and send/receive payment webhook.
8. Run Full Scan and confirm PDF report delivery/download.
9. Select Ethical Pen-Testing and confirm it is paid-only.
10. Check Scanner Health for missing tools.
11. Confirm report download requires authentication.
12. Confirm `/api/payments/submit` rejects direct payment details.

## 8. Operations

View logs:

```bash
docker compose --env-file .env.scanner -f docker-compose.production.yml logs -f kryptnet-app
docker compose --env-file .env.scanner -f docker-compose.production.yml logs -f caddy
```

Deploy updates:

```bash
git pull
docker compose --env-file .env.scanner -f docker-compose.production.yml build
docker compose --env-file .env.scanner -f docker-compose.production.yml up -d
```

Backup data:

```bash
tar -czf kryptnet-data-backup.tgz data
```
