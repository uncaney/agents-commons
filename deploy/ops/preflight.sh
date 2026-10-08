#!/usr/bin/env bash
# Deploy preflight (SPEC-v2 21.1/21.3): restore the latest encrypted dump into commons_preflight and
# run `gateway -migrate-check` from the candidate image against it, so pending migrations are
# exercised (and their longest lock wait reported) before the real database sees them.
# Usage: deploy/ops/preflight.sh <image>
#   env: BACKUPS_DIR=./backups  AGE_KEY_FILE=<age identity>  DUMP=<already decrypted db.dump>
#        PG_NETWORK=commons_data  PREFLIGHT_DB=commons_preflight
set -euo pipefail
cd "$(dirname "$0")/.."            # deploy/
IMG=${1:?usage: preflight.sh <image>}
BACKUPS_DIR=${BACKUPS_DIR:-./backups}
PREFLIGHT_DB=${PREFLIGHT_DB:-commons_preflight}
PG_NETWORK=${PG_NETWORK:-commons_data}
log() { printf '%s preflight: %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ -z "${DUMP:-}" ]; then
  latest=$(ls -1 "$BACKUPS_DIR"/commons-*.tar.age 2>/dev/null | sort | tail -n1)
  [ -n "$latest" ] || { log "no dump in $BACKUPS_DIR (set DUMP=path/to/db.dump)"; exit 1; }
  : "${AGE_KEY_FILE:?AGE_KEY_FILE (age identity able to read the backups) is required}"
  age -d -i "$AGE_KEY_FILE" "$latest" | tar -x -C "$work" db.dump
  DUMP=$work/db.dump
  log "restoring $(basename "$latest")"
fi

PGPASSWORD=$(cat secrets/pg_password.txt)
pg() { docker compose exec -T -e PGPASSWORD="$PGPASSWORD" postgres "$@"; }
pg psql -U cx -d postgres -v ON_ERROR_STOP=1 -q \
  -c "DROP DATABASE IF EXISTS $PREFLIGHT_DB WITH (FORCE)" -c "CREATE DATABASE $PREFLIGHT_DB"
# stream the custom-format dump into pg_restore inside the postgres container
pg pg_restore -U cx -d "$PREFLIGHT_DB" --no-owner --no-acl --exit-on-error < "$DUMP"
log "restored into $PREFLIGHT_DB; running migrate-check from $IMG"

# the candidate binary, on the data network, read-only, with the real pg password and a throwaway
# server secret (migrate-check touches nothing else)
docker run --rm --network "$PG_NETWORK" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --user 65532:65532 --tmpfs /tmp:size=16m \
  -v "$PWD/secrets/pg_password.txt:/run/secrets/pg_password:ro" \
  -e DATABASE_URL="postgres://cx@postgres:5432/$PREFLIGHT_DB?sslmode=disable" \
  -e PG_PASSWORD_FILE=/run/secrets/pg_password \
  -e SERVER_SECRET=preflight-only-not-a-secret-0123456789 -e DATA_DIR=/tmp -e FORGEJO_URL= -e PG_NOTIFY=0 \
  "$IMG" -migrate-check
log "migrate-check ok"
