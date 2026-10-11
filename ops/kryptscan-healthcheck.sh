#!/usr/bin/env bash
set -euo pipefail

APP_HEALTH_URL="${APP_HEALTH_URL:-http://127.0.0.1:5102/health}"
WORKER_HEALTH_URL="${WORKER_HEALTH_URL:-http://127.0.0.1:5200/health}"
DISK_THRESHOLD_PERCENT="${DISK_THRESHOLD_PERCENT:-85}"
ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"

failures=()
systemctl is-active --quiet kryptnet-scan || failures+=("kryptnet-scan service is not active")
curl --fail --silent --show-error --max-time 10 "$APP_HEALTH_URL" >/dev/null || failures+=("application health check failed")
curl --fail --silent --show-error --max-time 15 "$WORKER_HEALTH_URL" >/dev/null || failures+=("scanner worker health check failed")

disk_use="$(df -P / | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
if [[ "$disk_use" -ge "$DISK_THRESHOLD_PERCENT" ]]; then
  failures+=("root filesystem usage is ${disk_use}%")
fi

if [[ ${#failures[@]} -eq 0 ]]; then
  logger -t kryptscan-health "healthy app worker disk=${disk_use}%"
  exit 0
fi

message="KryptScan health alert: $(IFS='; '; echo "${failures[*]}")"
logger -p daemon.err -t kryptscan-health "$message"
if [[ -n "$ALERT_WEBHOOK_URL" ]]; then
  payload="$(python3 -c 'import json,sys; print(json.dumps({"text": sys.argv[1]}))' "$message")"
  curl --fail --silent --show-error --max-time 10 \
    -H 'Content-Type: application/json' -d "$payload" "$ALERT_WEBHOOK_URL" >/dev/null || true
fi
printf '%s\n' "$message" >&2
exit 1
