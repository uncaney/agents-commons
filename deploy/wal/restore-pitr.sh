#!/usr/bin/env bash
# restore-pitr.sh — P121 point-in-time restore drill (SPEC-v2 27.9). RUN ON THE OPERATOR BOX ONLY.
#
# The backup bucket holds, continuously shipped by the courier's wal_ship scanner, ECIES-encrypted WAL
# segments (wal/<f>) and weekly base backups (basebackup/<f>). This drill:
#
#   1. mirrors the bucket's wal/ and basebackup/ objects to a LOCAL directory (read token: operator
#      box only, never on the server),
#   2. decrypts the newest base backup with the WAL private key and unpacks it into a throwaway data
#      directory,
#   3. replays the archived WAL into it to the requested point in time (restore_command = walfetch.sh,
#      which decrypts each segment on the fly),
#   4. promotes the throwaway cluster, renames the recovered database to commons_drill,
#   5. runs the 10 smoke queries of the restore drill,
#   6. pushes the Kuma heartbeat (up on success, down on failure).
#
# Nothing here touches the production cluster. The private key is read once, locally, and never
# written anywhere new.
#
# Usage:
#   restore-pitr.sh --privkey wal_priv.hex [--pitr '2026-10-07 12:00:00+00'] \
#       [--bucket commons-wal] [--endpoint https://s3.example.net] [--mirror ./wal-mirror] \
#       [--drill-db commons_drill] [--kuma https://kuma/api/push/<token>] [--skip-sync] [--keep]
#
# Read credentials for the bucket come from the ambient AWS CLI environment (AWS_ACCESS_KEY_ID /
# AWS_SECRET_ACCESS_KEY / AWS_REGION, or an aws profile); --skip-sync reuses an already-populated
# mirror and needs no bucket access at all.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- defaults (env overridable) ------------------------------------------------------------------
WAL_BUCKET="${WAL_BUCKET:-}"
WAL_S3_ENDPOINT="${WAL_S3_ENDPOINT:-}"
WAL_MIRROR="${WAL_MIRROR:-./wal-mirror}"
WAL_PRIVKEY="${WAL_PRIVKEY:-}"
PITR="${PITR:-}"
DRILL_DB="${DRILL_DB:-commons_drill}"
KUMA_PUSH_URL="${KUMA_PUSH_URL:-}"
SKIP_SYNC=0
KEEP=0
PORT="${WAL_DRILL_PORT:-55433}"

die() { echo "restore-pitr: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --privkey)   WAL_PRIVKEY="$2"; shift 2 ;;
    --pitr)      PITR="$2"; shift 2 ;;
    --bucket)    WAL_BUCKET="$2"; shift 2 ;;
    --endpoint)  WAL_S3_ENDPOINT="$2"; shift 2 ;;
    --mirror)    WAL_MIRROR="$2"; shift 2 ;;
    --drill-db)  DRILL_DB="$2"; shift 2 ;;
    --kuma)      KUMA_PUSH_URL="$2"; shift 2 ;;
    --port)      PORT="$2"; shift 2 ;;
    --skip-sync) SKIP_SYNC=1; shift ;;
    --keep)      KEEP=1; shift ;;
    -h|--help)   sed -n '2,40p' "$0"; exit 0 ;;
    *)           die "unknown argument: $1" ;;
  esac
done

[ -n "$WAL_PRIVKEY" ] || die "--privkey (X25519 private key file) is required"
[ -f "$WAL_PRIVKEY" ] || die "private key file not found: $WAL_PRIVKEY"
command -v go >/dev/null         || die "go toolchain required (to build the decryptor)"
command -v psql >/dev/null       || die "psql required"
command -v pg_ctl >/dev/null     || die "pg_ctl required"
command -v tar >/dev/null        || die "tar required"
[ "$SKIP_SYNC" -eq 1 ] || command -v aws >/dev/null || die "aws CLI required (or pass --skip-sync)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/wal-drill.XXXXXX")"
DATADIR="$WORK/data"
LOGFILE="$WORK/postgres.log"
SOCKDIR="$WORK/sock"
DECRYPT_BIN="$WORK/waldecrypt"
mkdir -p "$DATADIR" "$SOCKDIR" "$WAL_MIRROR/wal" "$WAL_MIRROR/basebackup"

STATUS="down"
MSG="restore drill did not complete"

cleanup() {
  # Always stop the throwaway cluster and (optionally) remove the work dir.
  if [ -f "$DATADIR/postmaster.pid" ]; then
    pg_ctl -D "$DATADIR" -m immediate stop >/dev/null 2>&1 || true
  fi
  push_kuma
  if [ "$KEEP" -eq 1 ]; then
    echo "restore-pitr: work dir kept at $WORK"
  else
    rm -rf "$WORK"
  fi
}

push_kuma() {
  [ -n "$KUMA_PUSH_URL" ] || return 0
  local enc; enc="$(printf '%s' "$MSG" | sed 's/ /%20/g')"
  curl -fsS --max-time 10 "${KUMA_PUSH_URL}?status=${STATUS}&msg=${enc}" >/dev/null 2>&1 \
    || echo "restore-pitr: Kuma push failed (non-fatal)" >&2
}
trap cleanup EXIT

# ---- 1. build the decryptor (same ECIES as cmd/courier/kind_wal.go) ------------------------------
echo "restore-pitr: building decryptor"
go build -o "$DECRYPT_BIN" "$SCRIPT_DIR/decrypt.go"

# ---- 2. mirror the bucket (read-only; operator box only) -----------------------------------------
if [ "$SKIP_SYNC" -eq 0 ]; then
  [ -n "$WAL_BUCKET" ] || die "--bucket is required unless --skip-sync"
  AWS_ENDPOINT_ARGS=()
  [ -n "$WAL_S3_ENDPOINT" ] && AWS_ENDPOINT_ARGS=(--endpoint-url "$WAL_S3_ENDPOINT")
  echo "restore-pitr: syncing s3://$WAL_BUCKET/{wal,basebackup}/ -> $WAL_MIRROR"
  aws "${AWS_ENDPOINT_ARGS[@]}" s3 sync "s3://$WAL_BUCKET/basebackup/" "$WAL_MIRROR/basebackup/"
  aws "${AWS_ENDPOINT_ARGS[@]}" s3 sync "s3://$WAL_BUCKET/wal/"        "$WAL_MIRROR/wal/"
fi

# ---- 3. decrypt + unpack the newest base backup --------------------------------------------------
BASE_ENC="$(ls -1 "$WAL_MIRROR/basebackup"/base-*.tgz 2>/dev/null | sort | tail -n1 || true)"
[ -n "$BASE_ENC" ] || die "no base backup found under $WAL_MIRROR/basebackup (base-*.tgz)"
BASE_NAME="$(basename "$BASE_ENC")"
echo "restore-pitr: restoring base backup $BASE_NAME"
"$DECRYPT_BIN" -key "$WAL_PRIVKEY" -aad "basebackup/$BASE_NAME" -in "$BASE_ENC" -out "$WORK/base.tar.gz"
tar -xzf "$WORK/base.tar.gz" -C "$DATADIR"
chmod 700 "$DATADIR"
rm -f "$DATADIR/postmaster.pid"

# ---- 4. configure recovery -----------------------------------------------------------------------
RESTORE_CMD="WAL_MIRROR='$WAL_MIRROR' WAL_DECRYPT_BIN='$DECRYPT_BIN' WAL_PRIVKEY='$WAL_PRIVKEY' '$SCRIPT_DIR/walfetch.sh' %f %p"
{
  echo "# written by restore-pitr.sh"
  echo "restore_command = '$RESTORE_CMD'"
  echo "recovery_target_action = 'promote'"
  if [ -n "$PITR" ]; then
    echo "recovery_target_time = '$PITR'"
    echo "recovery_target_inclusive = on"
  fi
  echo "listen_addresses = ''"
  echo "port = $PORT"
  echo "unix_socket_directories = '$SOCKDIR'"
  echo "archive_mode = off"
  echo "hot_standby = on"
} >> "$DATADIR/postgresql.auto.conf"
: > "$DATADIR/recovery.signal"
chmod +x "$SCRIPT_DIR/walfetch.sh" 2>/dev/null || true

# ---- 5. start the throwaway cluster and wait for recovery ----------------------------------------
echo "restore-pitr: replaying WAL${PITR:+ to $PITR}"
pg_ctl -D "$DATADIR" -l "$LOGFILE" -w -t 600 start || { echo "--- postgres log ---"; cat "$LOGFILE" >&2; die "recovery did not complete"; }

# Wait until recovery has finished (promotion clears pg_is_in_recovery()).
for _ in $(seq 1 120); do
  inrec="$(psql -h "$SOCKDIR" -p "$PORT" -U cx -d postgres -tAc 'SELECT pg_is_in_recovery()' 2>/dev/null || echo t)"
  [ "$inrec" = "f" ] && break
  sleep 1
done
[ "${inrec:-t}" = "f" ] || die "cluster still in recovery after timeout"

# ---- 6. land the recovered database as commons_drill ---------------------------------------------
psql -h "$SOCKDIR" -p "$PORT" -U cx -d postgres -v ON_ERROR_STOP=1 \
  -c "DROP DATABASE IF EXISTS \"$DRILL_DB\"" \
  -c "ALTER DATABASE commons RENAME TO \"$DRILL_DB\""

# ---- 7. the 10 smoke queries ---------------------------------------------------------------------
echo "restore-pitr: running smoke queries against $DRILL_DB"
SMOKE_SQL="$(cat <<'SQL'
\pset pager off
\echo '1 connectivity'              ; SELECT 1;
\echo '2 server version'            ; SHOW server_version;
\echo '3 recovery finished'         ; SELECT pg_is_in_recovery();
\echo '4 last replayed LSN'         ; SELECT pg_last_wal_replay_lsn();
\echo '5 database size'             ; SELECT pg_size_pretty(pg_database_size(current_database()));
\echo '6 user tables present'       ; SELECT count(*) > 0 FROM information_schema.tables WHERE table_schema='public';
\echo '7 kb rows'                   ; SELECT CASE WHEN to_regclass('public.kb') IS NULL THEN -1 ELSE (SELECT count(*) FROM kb) END;
\echo '8 roots rows'                ; SELECT CASE WHEN to_regclass('public.roots') IS NULL THEN -1 ELSE (SELECT count(*) FROM roots) END;
\echo '9 egress_outbox rows'        ; SELECT CASE WHEN to_regclass('public.egress_outbox') IS NULL THEN -1 ELSE (SELECT count(*) FROM egress_outbox) END;
\echo '10 no invalid indexes'       ; SELECT count(*) FROM pg_index WHERE NOT indisvalid;
SQL
)"
if printf '%s\n' "$SMOKE_SQL" | psql -h "$SOCKDIR" -p "$PORT" -U cx -d "$DRILL_DB" -v ON_ERROR_STOP=1; then
  STATUS="up"
  MSG="restore drill ok: $BASE_NAME${PITR:+ @ $PITR} -> $DRILL_DB"
  echo "restore-pitr: OK"
else
  die "smoke queries failed"
fi
