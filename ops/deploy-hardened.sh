#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/kryptnet-services/kryptscan-app}"
cd "$APP_DIR"

docker compose version >/dev/null 2>&1 || {
  echo "Docker Compose v2 is required. Do not deploy with docker-compose 1.29.2." >&2
  exit 1
}

./ops/security-preflight.sh
./venv/bin/python -m ops.kryptscan_maintenance backup --destination "${BACKUP_DIR:-$APP_DIR/backups}" --keep-days "${BACKUP_KEEP_DAYS:-14}"
./venv/bin/python -m pip install -r requirements.txt
docker compose -f docker-compose.scanner.yml build kryptnet-scanner
docker compose -f docker-compose.scanner.yml up -d kryptnet-scanner
systemctl restart kryptnet-scan
nginx -t
systemctl reload nginx
curl --fail --silent --show-error http://127.0.0.1:5102/health >/dev/null
curl --fail --silent --show-error http://127.0.0.1:5200/health >/dev/null
echo "KryptScan hardened deployment completed."
