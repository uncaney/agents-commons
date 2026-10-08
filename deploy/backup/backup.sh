#!/bin/sh
# Encrypted backup loop for the commons stack.
# Every INTERVAL seconds (default 6h): pg_dump -Fc + tar of the forgejo data volume and the
# blobs dir (both mounted read-only), streamed into `age -r $AGE_RECIPIENT`, written atomically
# (tmp + mv) to $OUT, keeping the newest $KEEP files. Only the private age key can read them.
#
# Env: PGHOST PGUSER PGDATABASE PG_PASSWORD_FILE AGE_RECIPIENT [OUT=/backups] [KEEP=28]
#      [INTERVAL=21600] [SRC=/src] [WITH_BLOBS=1] [ONCE=0]
# Blobs expire after 7 days of non-use and may be large (256 MiB per root); set WITH_BLOBS=0
# to keep backups small, they are not needed to restore the service.
set -eu

OUT="${OUT:-/backups}"
KEEP="${KEEP:-28}"
INTERVAL="${INTERVAL:-21600}"
SRC="${SRC:-/src}"
WITH_BLOBS="${WITH_BLOBS:-1}"
: "${AGE_RECIPIENT:?AGE_RECIPIENT (age1...) is required}"
: "${PG_PASSWORD_FILE:?PG_PASSWORD_FILE is required}"

log() { echo "backup: $*" >&2; }

run_once() {
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  work=$(mktemp -d /tmp/bk.XXXXXX)
  trap 'rm -rf "$work"' EXIT
  PGPASSWORD=$(cat "$PG_PASSWORD_FILE")
  export PGPASSWORD
  pg_dump -Fc --no-owner --no-acl -f "$work/db.dump"
  unset PGPASSWORD

  set -- -C "$work" db.dump -C "$SRC" forgejo
  if [ "$WITH_BLOBS" = "1" ] && [ -d "$SRC/blobs" ]; then
    set -- "$@" --exclude=blobs/tmp blobs
  fi
  tmp="$OUT/.commons-$ts.tar.age.tmp"
  # tar warns (exit 1) when a live file changes under it (forgejo sqlite/wal); keep going.
  if ! tar --warning=no-file-changed --exclude=forgejo/ssh -cf - "$@" | age -r "$AGE_RECIPIENT" > "$tmp"; then
    rm -f "$tmp"
    log "backup $ts failed"
    rm -rf "$work"
    trap - EXIT
    return 1
  fi
  mv -f "$tmp" "$OUT/commons-$ts.tar.age"
  rm -rf "$work"
  trap - EXIT
  log "wrote commons-$ts.tar.age ($(du -h "$OUT/commons-$ts.tar.age" | cut -f1))"

  # retention: newest KEEP files survive
  find "$OUT" -maxdepth 1 -name 'commons-*.tar.age' | sort -r | tail -n +"$((KEEP + 1))" | while read -r f; do
    rm -f "$f" && log "pruned $(basename "$f")"
  done
}

mkdir -p "$OUT"
while :; do
  run_once || true
  [ "${ONCE:-0}" = "1" ] && exit 0
  sleep "$INTERVAL"
done
