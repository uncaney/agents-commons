#!/usr/bin/env bash
# Image hygiene that can never remove a rollback target (SPEC-v2 21.3). Keeps every image a running
# container uses, :prev, :latest and the two newest sha tags of the gateway; removes older sha tags;
# prunes DANGLING layers only (never `prune -a`: a forced cleanup once deleted the images under the
# running containers); writes a weekly `docker save` tarball of the gateway images (keeps 4).
# Usage: deploy/ops/prune-safe.sh        env: BACKUPS_DIR=./backups  KEEP_SHAS=2
set -euo pipefail
cd "$(dirname "$0")/.."            # deploy/
IMG=ekaii/commons-gateway
BACKUPS_DIR=${BACKUPS_DIR:-./backups}
KEEP_SHAS=${KEEP_SHAS:-2}
log() { printf 'prune: %s\n' "$*" >&2; }

inuse=$(docker ps -a --format '{{.Image}}' | sort -u)
keep() { printf '%s\n' "$inuse" | grep -qx "$1" || [ "$1" = "$IMG:prev" ] || [ "$1" = "$IMG:latest" ]; }

# sha tags newest first (tag<TAB>created), skipping prev/latest/untagged
n=0
docker image ls "$IMG" --format '{{.Tag}}\t{{.CreatedAt}}' | grep -Ev '^(prev|latest|<none>)	' | sort -t'	' -k2 -r | cut -f1 |
while read -r tag; do
  n=$((n + 1))
  if [ "$n" -le "$KEEP_SHAS" ] || keep "$IMG:$tag"; then
    continue
  fi
  if docker rmi "$IMG:$tag" >/dev/null 2>&1; then log "removed $IMG:$tag"; else log "kept $IMG:$tag (in use)"; fi
done

docker image prune -f >/dev/null && log "dangling layers pruned"

# weekly tarball of the live and previous gateway images (idempotent per ISO week)
week=$(date -u +%G-W%V)
mkdir -p "$BACKUPS_DIR/images"
f="$BACKUPS_DIR/images/gateway-$week.tar.gz"
if [ ! -f "$f" ]; then
  imgs="$IMG:latest"
  docker image inspect "$IMG:prev" >/dev/null 2>&1 && imgs="$imgs $IMG:prev"
  # shellcheck disable=SC2086
  if docker save $imgs | gzip > "$f.tmp"; then mv -f "$f.tmp" "$f"; log "saved $f"; else rm -f "$f.tmp"; log "docker save failed"; fi
fi
ls -1t "$BACKUPS_DIR"/images/gateway-*.tar.gz 2>/dev/null | tail -n +5 | while read -r old; do rm -f "$old" && log "removed $(basename "$old")"; done
