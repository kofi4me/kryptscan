#!/usr/bin/env bash
set -euo pipefail

APP_HEALTH_URL="${APP_HEALTH_URL:-http://127.0.0.1:5102/health}"
WORKER_HEALTH_URL="${WORKER_HEALTH_URL:-http://127.0.0.1:5200/health}"
DISK_THRESHOLD_PERCENT="${DISK_THRESHOLD_PERCENT:-85}"
ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"

failures=()
systemctl is-active --quiet kryptnet-scan || failures+=("kryptnet-scan service is not active")

app_health=""
if ! app_health="$(curl --fail --silent --show-error --max-time 10 "$APP_HEALTH_URL")"; then
  failures+=("application health check failed")
elif ! python3 -c 'import json,sys; data=json.loads(sys.argv[1]); raise SystemExit(0 if data.get("status") == "ok" and data.get("scanner_backend") == "worker" else 1)' "$app_health"; then
  failures+=("application health response is not production-ready")
fi

worker_health=""
if ! worker_health="$(curl --fail --silent --show-error --max-time 15 "$WORKER_HEALTH_URL")"; then
  failures+=("scanner worker health check failed")
elif ! python3 -c '
import json, sys
data = json.loads(sys.argv[1])
required = {
    "nmap", "sslyze", "testssl.sh", "nuclei", "nikto", "whatweb", "wafw00f",
    "zap-baseline.py", "httpx", "naabu", "dnsx", "katana", "subfinder", "amass",
    "feroxbuster", "ffuf", "gobuster",
}
available = data.get("available_tools") or {}
preflight = data.get("preflight") or {}
ready = (
    data.get("status") == "ok"
    and all(available.get(name) is True for name in required)
    and preflight.get("testssl_dependencies_ready") is True
    and preflight.get("nuclei_templates_ready") is True
    and preflight.get("artificial_scan_delay_enabled") is False
)
raise SystemExit(0 if ready else 1)
' "$worker_health"; then
  failures+=("scanner worker reports missing tools or failed preflight")
fi

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
