#!/usr/bin/env bash
# setup.sh - Linux/macOS equivalent of scripts/setup.ps1.
# Use it to run the stack on a Linux server / VPS (the recommended way to capture REAL
# internet attacks, and the fallback for Windows versions that cannot run Docker Desktop).
#
#   ./scripts/setup.sh && docker compose up -d --build
#
# Creates .env with random secrets (existing values are never overwritten) and renders
# elastalert/config.yaml.  Needs: bash, sed, tr, head, grep, cut.
set -euo pipefail
cd "$(dirname "$0")/.."

gen() {   # gen <length>  -> random [A-Za-z0-9] string without look-alike characters
  local out
  out=$(LC_ALL=C tr -dc 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789' </dev/urandom | head -c "$1" || true)
  printf '%s' "$out"
}

# name:length   (Kibana encryption keys must be >= 32 characters)
SECRETS="ELASTIC_PASSWORD:24 KIBANA_SYSTEM_PASSWORD:24 LOGSTASH_WRITER_PASSWORD:24 TI_READER_PASSWORD:24 ELASTALERT_PASSWORD:24 KIBANA_SECURITY_KEY:40 KIBANA_ENCRYPTION_KEY:40 KIBANA_REPORTING_KEY:40"

[ -f .env ] || cp .env.example .env
filled=0
for item in $SECRETS; do
  name="${item%%:*}"; len="${item##*:}"
  if grep -qE "^${name}=$" .env; then
    sed "s|^${name}=\$|${name}=$(gen "$len")|" .env > .env.tmp && mv .env.tmp .env
    filled=$((filled + 1))
  fi
done
chmod 600 .env
echo "[setup] .env ready ($filled secrets generated). Keep this file private."

pw=$(grep -E '^ELASTALERT_PASSWORD=' .env | head -n1 | cut -d= -f2-)
[ -n "$pw" ] || { echo "ELASTALERT_PASSWORD missing from .env" >&2; exit 1; }
sed "s|__ES_PASSWORD__|${pw}|" elastalert/config.yaml.template > elastalert/config.yaml
chmod 600 elastalert/config.yaml
mkdir -p reports
echo "[setup] elastalert/config.yaml rendered."
echo "[setup] next:  docker compose up -d --build     (Kibana: http://localhost:5601, user 'elastic', password in .env)"
