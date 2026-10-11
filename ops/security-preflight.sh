#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
failed=0

if [[ ! -f .env ]]; then
  echo "ERROR: .env is missing"
  failed=1
else
  mode="$(stat -c '%a' .env)"
  if [[ "$mode" != "600" && "$mode" != "640" ]]; then
    echo "ERROR: .env permissions are $mode; use 600 or 640"
    failed=1
  fi
  if grep -Eqi '(^|=)(change-me|changeme|your_.+_key|replace-me|example-secret)([[:space:]]|$)' .env; then
    echo "ERROR: .env still contains placeholder secrets"
    failed=1
  fi
fi

command -v docker >/dev/null || { echo "ERROR: docker is not installed"; failed=1; }
docker compose version >/dev/null 2>&1 || { echo "ERROR: Docker Compose v2 is required"; failed=1; }
python3 -c 'import ssl; assert ssl.OPENSSL_VERSION' >/dev/null || { echo "ERROR: Python TLS support is unavailable"; failed=1; }

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi
echo "KryptScan security preflight passed."
