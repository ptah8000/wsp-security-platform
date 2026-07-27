#!/usr/bin/env bash
# WSP Compose smoke checks: liveness + setup status.
# Usage (from repo root or deploy/):
#   ./deploy/smoke.sh
#   ADMIN_BASE=http://127.0.0.1:3000 ./deploy/smoke.sh
set -euo pipefail

ADMIN_BASE="${ADMIN_BASE:-http://127.0.0.1:3000}"
TIMEOUT_SEC="${SMOKE_TIMEOUT_SEC:-90}"
SLEEP_SEC=2

log() { printf '[smoke] %s\n' "$*"; }
fail() { printf '[smoke] FAIL: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

need_cmd curl

deadline=$((SECONDS + TIMEOUT_SEC))

# --- healthz (unauthenticated liveness) ---
log "waiting for GET ${ADMIN_BASE}/healthz (timeout ${TIMEOUT_SEC}s)"
health_body=""
while (( SECONDS < deadline )); do
  if health_body="$(curl -fsS --max-time 5 "${ADMIN_BASE}/healthz" 2>/dev/null)"; then
    break
  fi
  sleep "${SLEEP_SEC}"
done
[[ -n "${health_body}" ]] || fail "healthz not reachable at ${ADMIN_BASE}/healthz"

if ! printf '%s' "${health_body}" | grep -q 'ok'; then
  fail "healthz unexpected body: ${health_body}"
fi
log "healthz OK: ${health_body}"

# --- setup status (public while/after wizard) ---
log "GET ${ADMIN_BASE}/api/v1/setup/status"
status_body="$(curl -fsS --max-time 10 "${ADMIN_BASE}/api/v1/setup/status")" \
  || fail "setup/status request failed"
printf '%s' "${status_body}" | grep -q 'setup_completed' \
  || fail "setup/status missing setup_completed field: ${status_body}"
log "setup/status OK: ${status_body}"

log "smoke passed"
exit 0
