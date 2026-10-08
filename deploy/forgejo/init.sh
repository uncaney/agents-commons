#!/bin/sh
# One-shot Forgejo bootstrap, run inside the forgejo image as user git (same /data volume).
# Waits for Forgejo, creates the gateway admin user if missing, and writes two API tokens, each
# only when its file does not already exist (idempotent):
#   /tokens/forgejo_token     (0600) read/write, used by the mirror writer (gitmirror/forge Import)
#   /tokens/forgejo_ro_token  (0640) read-only, used by the read-only smart-HTTP git proxy (P27).
# The RO token carries only read:* scopes so a leak from the public-facing git proxy cannot write.
set -eu

FORGEJO_URL="${FORGEJO_URL:-http://forgejo:3000}"
USER="${GW_USER:-cx-gateway}"
TOKEN_FILE="${TOKEN_FILE:-/tokens/forgejo_token}"
RO_TOKEN_FILE="${RO_TOKEN_FILE:-/tokens/forgejo_ro_token}"
BIN="${FORGEJO_BIN:-forgejo}"
CONF="${GITEA_CUSTOM:-/data/gitea}/conf/app.ini"
WORK="${GITEA_WORK_DIR:-/data/gitea}"

log() { echo "forgejo-init: $*" >&2; }

i=0
until wget -q -O /dev/null "$FORGEJO_URL/api/healthz" 2>/dev/null; do
  i=$((i + 1))
  [ "$i" -gt 120 ] && { log "forgejo not up after 120 tries"; exit 1; }
  sleep 2
done
log "forgejo is up"

# mint writes <file> (mode) a fresh access token for $USER with <scopes>, atomically, only when the
# file is missing or empty. Idempotent across restarts.
mint() {
  file="$1"; mode="$2"; scopes="$3"; label="$4"
  if [ -s "$file" ]; then
    log "token already present at $file; skipping"
    return 0
  fi
  mkdir -p "$(dirname "$file")"
  tmp="$file.tmp.$$"
  "$BIN" --config "$CONF" --work-path "$WORK" admin user generate-access-token \
    --username "$USER" --token-name "$label-$(date +%Y%m%d-%H%M%S)" \
    --scopes "$scopes" --raw > "$tmp"
  [ -s "$tmp" ] || { rm -f "$tmp"; log "empty $label token"; exit 1; }
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$file"
  log "token written to $file"
}

if [ -s "$TOKEN_FILE" ] && [ -s "$RO_TOKEN_FILE" ]; then
  log "both tokens already present; nothing to do"
  exit 0
fi

if ! "$BIN" --config "$CONF" --work-path "$WORK" admin user list --admin 2>/dev/null | awk 'NR>1 {print $2}' | grep -qx "$USER"; then
  log "creating admin user $USER"
  "$BIN" --config "$CONF" --work-path "$WORK" admin user create \
    --admin --username "$USER" --email cx@agents.invalid \
    --random-password --must-change-password=false >/dev/null
else
  log "admin user $USER exists"
fi

umask 077
mint "$TOKEN_FILE" 0600 write:organization,write:repository,write:issue,write:user rw
mint "$RO_TOKEN_FILE" 0640 read:repository,read:organization ro
