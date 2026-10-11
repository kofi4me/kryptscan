# KryptScan production hardening

These controls are designed for the Ubuntu deployment at
`/opt/kryptnet-services/kryptscan-app`. Payment remains disabled and private
network targets remain blocked on the public scanner.

## 1. Replace Docker Compose v1

The deployment script intentionally refuses legacy `docker-compose` 1.29.2.
Install the Docker Compose v2 plugin from the Docker repository configured on
the server, then verify:

```bash
docker compose version
```

All future commands must use `docker compose`, with a space.

## 2. Protect secrets

```bash
cd /opt/kryptnet-services/kryptscan-app
sudo chown kryptnetlab:kryptnetlab .env
sudo chmod 600 .env
sudo -u kryptnetlab ./ops/security-preflight.sh
```

Before public launch, rotate the application secret, scanner worker token,
OpenAI key, SMTP password, admin credentials, and any credentials that have
ever appeared in shell history, screenshots, logs, or chat. Never commit the
new values.

## 3. Install backup, retention, and health timers

Review the retention period before installation. The default removes stored
PDF/JSON report artifacts after 30 days while retaining compact scan and audit
records.

```bash
cd /opt/kryptnet-services/kryptscan-app
chmod 750 ops/*.sh

# Preview retention before enabling deletion.
./venv/bin/python -m ops.kryptscan_maintenance cleanup --retention-days 30 --dry-run

sudo install -m 0644 ops/systemd/kryptscan-*.service /etc/systemd/system/
sudo install -m 0644 ops/systemd/kryptscan-*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kryptscan-backup.timer kryptscan-retention.timer kryptscan-health.timer
sudo systemctl list-timers 'kryptscan-*'
```

Backups stored on the same VM protect against application mistakes, not host or
disk loss. Copy them to encrypted storage on another host and test restoration
regularly.

Optional health notifications use `ALERT_WEBHOOK_URL`. Set it through a
systemd override instead of placing it in the script.

## 4. Install Nginx controls

First save the current configuration:

```bash
sudo cp -a /etc/nginx /etc/nginx.backup-before-kryptscan-hardening
sudo install -m 0644 ops/nginx/kryptscan-http-zones.conf /etc/nginx/conf.d/
```

Include `ops/nginx/kryptscan-server-security.conf` inside the existing
`server_name kryptscan.kryptnet.org` TLS server block. Do not create a second
TLS server block. Then validate before reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

The rules add connection/request limits, security headers, small request-body
limits, and early blocking for secret files and common configuration probes.
Keep Certbot's certificate directives unchanged.

Optionally install Fail2ban and the supplied jail after confirming Nginx logs
the real client address (especially when using Cloudflare or another proxy):

```bash
sudo install -m 0644 ops/fail2ban/filter.d/kryptscan.conf /etc/fail2ban/filter.d/
sudo install -m 0644 ops/fail2ban/jail.d/kryptscan.local /etc/fail2ban/jail.d/
sudo fail2ban-client -t
sudo systemctl restart fail2ban
sudo fail2ban-client status kryptscan
```

Do not enable this jail until trusted proxy addresses and real-IP handling are
correct; otherwise every visitor may appear to come from the same proxy.

## 5. Deploy with the hardened workflow

```bash
cd /opt/kryptnet-services/kryptscan-app
git pull --ff-only
sudo ./ops/deploy-hardened.sh
```

The script runs the preflight, creates an SQLite online backup, installs Python
dependencies, rebuilds the worker with Compose v2, restarts the web service,
validates Nginx, and verifies both health endpoints.

## 6. Abuse controls

The free basic assessment is limited to one use per organization, not one use
per member. Existing authentication and scan quote rate limits remain active.
Do not identify users through invasive device fingerprinting. At the edge,
enable managed bot protection and rate limiting for registration, verification,
login, password reset, quote, coupon, and scan-creation endpoints.

## 7. Security assurance

GitHub security checks run unit tests, Bandit, and pip-audit on pushes, pull
requests, and weekly. These checks complement, but do not replace, an
independent authorized assessment of the deployed application, its Nginx/TLS
configuration, tenant isolation, report authorization, SSRF controls, and
scanner-worker trust boundary.

## Verification

```bash
systemctl is-active kryptnet-scan nginx
docker compose -f docker-compose.scanner.yml ps
curl -fsS http://127.0.0.1:5102/health
curl -fsS http://127.0.0.1:5200/health
sudo journalctl -u kryptscan-health.service -n 30 --no-pager
sudo journalctl -u kryptscan-backup.service -n 30 --no-pager
```
