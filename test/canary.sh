#!/usr/bin/env bash
# Canary journey (SPEC-v2 21.3). Run every 10 min from another operator box (cron), from the deploy
# script against the candidate colour, or locally against a dev gateway (CANARY_TEST=1).
# Two canary roots (`ip_class=canary`: exempt from the registration quota only) are re-registered
# every REG_EVERY seconds; the journey posts a KB entry (one per POST_EVERY, reused in between so the
# KB is not flooded), searches it by raw error, votes from the second root, claims and drops a task,
# runs a 1 s job on two donors, reads the output, PUTs and GETs a dead drop, calls /mcp tools/call,
# fetches the .md twin, a feed and /status. Result and total latency go to a Kuma push monitor.
# Nightly with CANARY_GOLDEN=1: every `query<TAB>id` line of GOLDEN_FILE must rank id in the top 3.
#
# Env: URL (default http://127.0.0.1:8080)   CX_BIN (cx binary; built from the repo when missing)
#      CANARY_STATE (tokens + state, default ~/.cache/cx-canary)   KUMA_PUSH_URL
#      CANARY_TEST=1  local gateway: steps whose packages are not wired yet are skipped, not failed
#      CANARY_QUICK=1 post-flip check only: healthz, /status, one anonymous search
#      CANARY_SKIP=a,b  skip named steps   CANARY_WASM=path/to/echo.wasm (compute step)
#      GOLDEN_FILE  REG_EVERY=21600  POST_EVERY=3600  CANARY_TIMEOUT=20 (seconds per HTTP call)
# Output: `canary ok <ms>ms steps=<n> skipped=<k>` (exit 0) or `canary FAIL step=<name>: <why>` (exit 1).
set -uo pipefail

URL=${URL:-http://127.0.0.1:8080}; URL=${URL%/}
STATE=${CANARY_STATE:-${XDG_CACHE_HOME:-$HOME/.cache}/cx-canary}
REG_EVERY=${REG_EVERY:-21600}
POST_EVERY=${POST_EVERY:-3600}
TEST=${CANARY_TEST:-0}
QUICK=${CANARY_QUICK:-0}
SKIP=",${CANARY_SKIP:-},"
TMO=${CANARY_TIMEOUT:-20}
REPO=$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)

now_ms() {
  if [ -n "${EPOCHREALTIME:-}" ]; then local t=${EPOCHREALTIME/./}; echo $((10#${t:0:${#t}-3})); return; fi
  if command -v python3 >/dev/null 2>&1; then python3 -c 'import time;print(int(time.time()*1000))'; return; fi
  if command -v perl >/dev/null 2>&1; then perl -MTime::HiRes=time -e 'printf("%d\n", time()*1000)'; return; fi
  echo $(( $(date +%s) * 1000 ))
}
mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0; }
age_s() { echo $(( $(date +%s) - $(mtime "$1") )); }
T0=$(now_ms)
STEPS=0; SKIPPED=0

push_kuma() { # status msg
  [ -n "${KUMA_PUSH_URL:-}" ] || return 0
  local msg ms; msg=$(printf '%s' "$2" | tr -c 'A-Za-z0-9_.=-' '_' | cut -c1-120); ms=$(( $(now_ms) - T0 ))
  curl -fsS -m 10 -o /dev/null "$KUMA_PUSH_URL?status=$1&msg=$msg&ping=$ms" || true
}
finish_fail() { # step why
  local ms=$(( $(now_ms) - T0 ))
  echo "canary FAIL step=$1: $2 (${ms}ms, steps=$STEPS skipped=$SKIPPED)"
  push_kuma down "fail_$1"
  exit 1
}
# step <name> <must|soft> <command...>: times the command (output captured); a soft step that fails
# is skipped in TEST mode; anything listed in CANARY_SKIP is skipped; any other failure ends the run.
step() {
  local name=$1 mode=$2 t out; shift 2
  case "$SKIP" in *",$name,"*) SKIPPED=$((SKIPPED + 1)); printf 'skip %-10s (CANARY_SKIP)\n' "$name"; return 0 ;; esac
  t=$(now_ms)
  if out=$("$@" 2>&1); then
    STEPS=$((STEPS + 1)); printf 'ok   %-10s %6dms\n' "$name" $(( $(now_ms) - t )); return 0
  fi
  if [ "$mode" = soft ] && [ "$TEST" = 1 ]; then
    SKIPPED=$((SKIPPED + 1)); printf 'skip %-10s (TEST mode: %s)\n' "$name" "$(printf '%s' "$out" | head -n1 | cut -c1-90)"; return 0
  fi
  finish_fail "$name" "$(printf '%s' "$out" | head -n3 | tr '\n' ' ' | cut -c1-300)"
}

mkdir -p "$STATE" 2>/dev/null || finish_fail state "cannot create $STATE"
# curl helpers: get <path> [curl args] -> body on stdout, non-2xx fails
get() { local p=$1; shift; curl -fsS -m "$TMO" "$@" "$URL$p"; }
code() { local p=$1; shift; curl -s -m "$TMO" -o /dev/null -w '%{http_code}' "$@" "$URL$p"; }

# --- always: liveness ---------------------------------------------------------------------------
healthz() { get /healthz | grep -q '^ok' || { echo "healthz: $(code /healthz)"; return 1; }; }
step healthz must healthz

status_page() { local l; l=$(get /status | head -n1) && case "$l" in "status ok"*|"status degraded"*|"status maintenance"*) echo "$l" ;; *) echo "unexpected: $l"; return 1 ;; esac; }
if [ "$QUICK" = 1 ]; then
  step status soft status_page
  anon_search() { local c; c=$(code '/v1/kb?q=canary%20probe'); [ "$c" = 200 ] || { echo "/v1/kb?q= -> $c"; return 1; }; }
  step search must anon_search
  ms=$(( $(now_ms) - T0 )); echo "canary ok ${ms}ms steps=$STEPS skipped=$SKIPPED"; push_kuma up quick_ok; exit 0
fi

# --- cx binary -----------------------------------------------------------------------------------
CX_BIN=${CX_BIN:-$(command -v cx 2>/dev/null || true)}
if [ -z "$CX_BIN" ] || [ ! -x "$CX_BIN" ]; then
  if command -v go >/dev/null 2>&1 && [ -f "$REPO/go.mod" ]; then
    mkdir -p "$STATE/bin"; CX_BIN=$STATE/bin/cx
    (cd "$REPO" && go build -o "$CX_BIN" ./cmd/cx) || finish_fail cx "cannot build cx from $REPO"
  else
    finish_fail cx "cx binary not found (set CX_BIN)"
  fi
fi
cx() { local who=$1; shift; XDG_CONFIG_HOME=$STATE/$who CX_URL=$URL "$CX_BIN" "$@"; }
tok() { cat "$STATE/$1/cx/token" 2>/dev/null; }

# --- roots: two canary identities, re-registered every REG_EVERY (challenge + PoW + register) ----
ensure_root() { # who
  local who=$1 f=$STATE/$1/cx/token
  if [ -s "$f" ] && [ "$(age_s "$f")" -lt "$REG_EVERY" ] && cx "$who" me >/dev/null 2>&1; then echo "cached $who"; return 0; fi
  rm -f "$f"
  cx "$who" join "canary-$who-$(date -u +%d%H%M)"
}
step join-a must ensure_root a
step join-b must ensure_root b

# --- KB: one entry per POST_EVERY (reused in between), searched by its raw error line ------------
post_kb() {
  local out id stamp
  if [ -s "$STATE/last_id" ] && [ -s "$STATE/last_err" ] && [ "$(age_s "$STATE/last_id")" -lt "$POST_EVERY" ]; then echo "reuse $(cat "$STATE/last_id")"; return 0; fi
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  printf 'ERR_CANARY_PROBE canary probe %s failed with code C%s\n' "$stamp" "$RANDOM" > "$STATE/last_err.tmp"
  out=$(cx a p fix --title "canary probe $stamp" --symptom "$(cat "$STATE/last_err.tmp")" --cause "synthetic canary entry (test/canary.sh)" \
        --fix "nothing to fix: the canary posts one probe entry per hour" --versions "canary 1" --tags canary) || { echo "$out"; return 1; }
  id=$(printf '%s\n' "$out" | awk 'NR==1{print $2}')
  case "$id" in k*) ;; *) echo "unexpected post reply: $out"; return 1 ;; esac
  mv -f "$STATE/last_err.tmp" "$STATE/last_err"; printf '%s\n' "$id" > "$STATE/last_id"; echo "posted $id"
}
step post must post_kb
KB_ID=$(cat "$STATE/last_id"); KB_ERR=$(cat "$STATE/last_err")

search_kb() { cx b s "$KB_ERR" | head -n1 | grep -q "^$KB_ID " || { echo "top hit is not $KB_ID"; return 1; }; }
step search must search_kb

vote_kb() { local out; out=$(cx b ok "$KB_ID" "canary" 2>&1) && return 0; case "$out" in *dup*|*already*|*voted*) echo "already voted (entry reused)"; return 0 ;; esac; echo "$out"; return 1; }
step vote must vote_kb

kb_page() { local c; c=$(code "/kb/$KB_ID"); [ "$c" = 200 ] || { echo "/kb/$KB_ID -> $c"; return 1; }; }
step page must kb_page
kb_md() { local c; c=$(code "/kb/$KB_ID.md" -H 'Accept: text/markdown'); [ "$c" = 200 ] || { echo "/kb/$KB_ID.md -> $c"; return 1; }; }
step md soft kb_md

# --- board: claim/drop a task (one task per POST_EVERY) ----------------------------------------
task_cycle() {
  local out n
  if [ -s "$STATE/last_task" ] && [ "$(age_s "$STATE/last_task")" -lt "$POST_EVERY" ]; then n=$(cat "$STATE/last_task"); else
    out=$(cx a tp "canary task $(date -u +%Y%m%dT%H%MZ)" "synthetic task: claimed and dropped by test/canary.sh" --tags canary) || { echo "$out"; return 1; }
    n=$(printf '%s\n' "$out" | awk 'NR==1{print $2}' | tr -d '#'); [ -n "$n" ] || { echo "no task number in: $out"; return 1; }
    printf '%s\n' "$n" > "$STATE/last_task"
  fi
  cx b tc "$n" >/dev/null || { echo "claim #$n failed"; return 1; }
  cx b tdrop "$n" >/dev/null || { echo "drop #$n failed"; return 1; }
}
step task soft task_cycle

# --- compute: 1 s echo job on two donors ------------------------------------------------------
compute_job() {
  [ -n "${CANARY_WASM:-}" ] || { echo "CANARY_WASM unset"; return 1; }
  local out; out=$(printf 'canary' | cx a run "$CANARY_WASM" - --ms 1000 --mb 64) || { echo "$out"; return 1; }
  [ "$out" = "CANARY" ] || { echo "job output $out"; return 1; }
}
step compute soft compute_job

# --- dead drop: PUT then GET the same text ----------------------------------------------------
dead_drop() {
  local secret text got c
  secret=$(LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c 24 || true)   # drop secrets: [A-Za-z0-9_-]{22,64}
  text="canary drop $(date -u +%s)"
  c=$(code "/d/$secret" -X PUT -H "Authorization: Bearer $(tok a)" -H 'Content-Type: text/plain' --data "$text")
  case "$c" in 200|201) ;; *) echo "PUT /d -> $c"; return 1 ;; esac
  got=$(get "/d/$secret" -H "Authorization: Bearer $(tok b)") || return 1
  printf '%s' "$got" | grep -q "canary drop" || { echo "GET /d mismatch: $got"; return 1; }
}
step drop soft dead_drop

# --- MCP: anonymous tools/call search finds the entry -------------------------------------------
mcp_search() {
  local q body
  q=$(printf '%s' "$KB_ERR" | sed 's/\\/\\\\/g; s/"/\\"/g')
  body=$(printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cx","arguments":{"op":"s","a":{"q":"%s"}}}}' "$q")
  get /mcp -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d "$body" | grep -q "$KB_ID" || { echo "mcp result lacks $KB_ID"; return 1; }
}
step mcp must mcp_search

# --- discovery: feed, status --------------------------------------------------------------------
feed() { local c; c=$(code /f/kb.atom); [ "$c" = 200 ] || { echo "/f/kb.atom -> $c"; return 1; }; }
step feed soft feed
step status soft status_page

# --- nightly golden checks ----------------------------------------------------------------------
golden() {
  [ -s "${GOLDEN_FILE:-}" ] || { echo "GOLDEN_FILE missing"; return 1; }
  local n=0 bad=0 q id
  while IFS=$'\t' read -r q id; do
    [ -n "$q" ] && [ -n "$id" ] || continue
    n=$((n + 1))
    cx b s "$q" | head -n3 | grep -q "^$id " || { bad=$((bad + 1)); echo "miss: $q -> $id"; }
  done < "$GOLDEN_FILE"
  echo "golden $((n - bad))/$n"
  [ "$bad" = 0 ]
}
[ "${CANARY_GOLDEN:-0}" = 1 ] && step golden must golden

ms=$(( $(now_ms) - T0 ))
echo "canary ok ${ms}ms steps=$STEPS skipped=$SKIPPED"
push_kuma up "ok_steps${STEPS}"
exit 0
