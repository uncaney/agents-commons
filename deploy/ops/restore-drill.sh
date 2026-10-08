#!/usr/bin/env bash
# Monthly restore drill (SPEC-v2 21.3): restore the latest encrypted dump into commons_drill, run ten
# smoke queries, diff the restored schema against the live database and push the verdict (with the
# drill's duration) to a Kuma push monitor. Read-only for the live database.
# Usage: deploy/ops/restore-drill.sh
#   env: BACKUPS_DIR=./backups  AGE_KEY_FILE=<age identity>  DUMP=<decrypted db.dump>
#        LIVE_DB=commons  DRILL_DB=commons_drill  KUMA_PUSH_URL=
set -uo pipefail
cd "$(dirname "$0")/.."            # deploy/
BACKUPS_DIR=${BACKUPS_DIR:-./backups}
LIVE_DB=${LIVE_DB:-commons}
DRILL_DB=${DRILL_DB:-commons_drill}
start=$(date +%s)
log() { printf '%s drill: %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
kuma() { [ -n "${KUMA_PUSH_URL:-}" ] && curl -fsS -m 10 -o /dev/null "$KUMA_PUSH_URL?status=$1&msg=$2&ping=$(( ($(date +%s) - start) * 1000 ))" || true; }
fail() { log "FAIL: $*"; kuma down "restore_drill_$1"; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ -z "${DUMP:-}" ]; then
  latest=$(ls -1 "$BACKUPS_DIR"/commons-*.tar.age 2>/dev/null | sort | tail -n1)
  [ -n "$latest" ] || fail nodump "no dump in $BACKUPS_DIR"
  [ -n "${AGE_KEY_FILE:-}" ] || fail nokey "AGE_KEY_FILE required"
  age -d -i "$AGE_KEY_FILE" "$latest" | tar -x -C "$work" db.dump || fail decrypt "cannot decrypt $latest"
  DUMP=$work/db.dump
  log "dump $(basename "$latest") ($(du -h "$DUMP" | cut -f1))"
fi

PGPASSWORD=$(cat secrets/pg_password.txt)
pg() { docker compose exec -T -e PGPASSWORD="$PGPASSWORD" postgres "$@"; }
sql() { pg psql -U cx -d "$1" -v ON_ERROR_STOP=1 -At -c "$2"; }

sql postgres "DROP DATABASE IF EXISTS $DRILL_DB WITH (FORCE)" >/dev/null && sql postgres "CREATE DATABASE $DRILL_DB" >/dev/null || fail createdb "cannot create $DRILL_DB"
pg pg_restore -U cx -d "$DRILL_DB" --no-owner --no-acl --exit-on-error < "$DUMP" || fail restore "pg_restore"
log "restored into $DRILL_DB in $(( $(date +%s) - start )) s"

# ten smoke queries: every one must answer one row without error
smoke=(
  "SELECT count(*) FROM identities"
  "SELECT count(*) FROM kb WHERE NOT hidden"
  "SELECT count(*) FROM tasks"
  "SELECT count(*) FROM jobs"
  "SELECT count(*) FROM replicas"
  "SELECT max(version) FROM schema_migrations"
  "SELECT count(*) FROM flags"
  "SELECT coalesce(sum(amount) FILTER (WHERE from_id = 'mint'), 0) - coalesce(sum(amount) FILTER (WHERE to_id = 'burn'), 0) FROM ledger"
  "SELECT count(*) FROM events"
  "SELECT count(*) FROM blobs"
)
i=0
for q in "${smoke[@]}"; do
  i=$((i + 1))
  out=$(sql "$DRILL_DB" "$q" 2>&1) || fail "smoke$i" "$q: $out"
  [ -n "$out" ] || fail "smoke$i" "$q returned nothing"
  log "smoke $i/10 ok ($out)"
done

# schema diff: the restored schema must equal the live one (comments and SET lines ignored)
schema() { pg pg_dump -U cx -s --no-owner --no-acl "$1" | grep -Ev '^(--|SET |SELECT pg_catalog|\\connect|$)'; }
if ! diff <(schema "$LIVE_DB") <(schema "$DRILL_DB") > "$work/schema.diff"; then
  n=$(grep -c '^[<>]' "$work/schema.diff")
  head -40 "$work/schema.diff" >&2
  fail schemadiff "$n lines differ between $LIVE_DB and $DRILL_DB"
fi
log "schema identical"
sql postgres "DROP DATABASE IF EXISTS $DRILL_DB WITH (FORCE)" >/dev/null
elapsed=$(( $(date +%s) - start ))
log "ok in ${elapsed}s"
kuma up "restore_drill_ok_${elapsed}s"
