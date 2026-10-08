#!/usr/bin/env bash
# Blue/green deploy of the gateway (SPEC-v2 21.3).
#   build ekaii/commons-gateway:<git-sha> -> tag the live image :prev -> preflight (restore the latest
#   dump into commons_preflight, `gateway -migrate-check`) -> start the idle colour with the new
#   image -> canary journey within 2 min -> flip the edge upstream (atomic file replace + SIGHUP) ->
#   verify through the edge -> drain the old colour 20 s (its long-polls answer Retry-After: 1) and
#   stop it. A failure before the flip stops the candidate; a failure after it flips back and keeps
#   the old colour running; `deploy/ops/deploy.sh --rollback` restarts the previous colour on :prev.
# Usage: deploy/ops/deploy.sh [git-ref]        env: KUMA_PUSH_URL, SKIP_BUILD=1, SKIP_PREFLIGHT=1
#        deploy/ops/deploy.sh --rollback
set -euo pipefail
cd "$(dirname "$0")/.."            # deploy/
IMG=ekaii/commons-gateway
COMPOSE=(docker compose -f compose.yml -f ops/compose.bluegreen.yml --profile bluegreen)
UPSTREAM_FILE=ops/edge/upstream

log() { printf '%s deploy: %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
die() { log "FAIL: $*"; kuma down "deploy_failed_$1"; exit 1; }
kuma() { [ -n "${KUMA_PUSH_URL:-}" ] && curl -fsS -m 10 -o /dev/null "$KUMA_PUSH_URL?status=$1&msg=$2&ping=0" || true; }
set_upstream() { printf 'http://%s:8080\n' "$1" > "$UPSTREAM_FILE.tmp" && mv -f "$UPSTREAM_FILE.tmp" "$UPSTREAM_FILE"; }
reload_edge() { "${COMPOSE[@]}" kill -s HUP edge; }
colour_image() { cat "ops/edge/image.$1" 2>/dev/null || echo "$IMG:latest"; }
other() { case "$1" in gateway) echo gateway-next ;; gateway-next) echo gateway ;; *) return 1 ;; esac; }
# both colours' images are passed on every compose call so neither service is recreated by accident
compose_env() { export GATEWAY_IMAGE; GATEWAY_IMAGE=$(colour_image gateway); export GATEWAY_NEXT_IMAGE; GATEWAY_NEXT_IMAGE=$(colour_image gateway-next); }

mkdir -p ops/edge
[ -f "$UPSTREAM_FILE" ] || set_upstream gateway
LIVE=$(sed -n '1s#^http://\([a-z-]*\):8080.*#\1#p' "$UPSTREAM_FILE")
NEXT=$(other "$LIVE") || die upstream "unknown live upstream in $UPSTREAM_FILE"
compose_env

if [ "${1:-}" = "--rollback" ]; then
  log "rollback: live=$LIVE -> $NEXT on $IMG:prev"
  docker image inspect "$IMG:prev" >/dev/null || die rollback "no $IMG:prev image"
  echo "$IMG:prev" > "ops/edge/image.$NEXT"; compose_env
  "${COMPOSE[@]}" up -d --no-build --no-deps "$NEXT"
  for _ in $(seq 30); do "${COMPOSE[@]}" exec -T "$NEXT" /gateway -healthcheck >/dev/null 2>&1 && break; sleep 2; done
  set_upstream "$NEXT"; reload_edge
  sleep 20; "${COMPOSE[@]}" stop -t 25 "$LIVE"
  log "rolled back to $NEXT ($IMG:prev)"; kuma up rollback
  exit 0
fi

REF=${1:-HEAD}
SHA=$(git -C .. rev-parse --short=12 "$REF")
log "live=$LIVE next=$NEXT sha=$SHA"

# 1. build the candidate image (sha tag; :latest moves only after a successful flip)
if [ "${SKIP_BUILD:-0}" != 1 ]; then
  docker build -f gateway/Dockerfile -t "$IMG:$SHA" .. || die build "docker build"
fi
docker image inspect "$IMG:$SHA" >/dev/null || die build "image $IMG:$SHA missing"
LIVE_IMG=$(docker inspect --format '{{.Image}}' "commons-$LIVE-1" 2>/dev/null || true)
[ -n "$LIVE_IMG" ] && docker tag "$LIVE_IMG" "$IMG:prev"   # rollback target; prune-safe.sh never removes it

# 2. preflight: pending migrations against a restored copy of the latest dump
if [ "${SKIP_PREFLIGHT:-0}" != 1 ]; then
  ops/preflight.sh "$IMG:$SHA" || die preflight "migrate-check on commons_preflight"
fi

# 3. start the idle colour on the candidate image
echo "$IMG:$SHA" > "ops/edge/image.$NEXT"; compose_env
"${COMPOSE[@]}" up -d --no-build --no-deps "$NEXT" || die up "compose up $NEXT"
for _ in $(seq 30); do "${COMPOSE[@]}" exec -T "$NEXT" /gateway -healthcheck >/dev/null 2>&1 && break; sleep 2; done
"${COMPOSE[@]}" exec -T "$NEXT" /gateway -healthcheck >/dev/null 2>&1 || { "${COMPOSE[@]}" stop "$NEXT"; die health "$NEXT never became healthy"; }

# 4. canary journey against the candidate, 2 min budget
if ! CANARY_URL="http://$NEXT:8080" timeout 120 "${COMPOSE[@]}" run --rm --no-deps canary; then
  "${COMPOSE[@]}" stop "$NEXT"
  echo "$(colour_image "$LIVE")" > /dev/null
  die canary "journey failed on $NEXT; candidate stopped, $LIVE still live"
fi

# 5. flip: atomic replace inside the mounted directory, then SIGHUP the edge
set_upstream "$NEXT"
reload_edge || die flip "edge reload"
sleep 1

# 6. verify through the edge (quick journey: healthz, status, one anonymous search)
if ! CANARY_URL="http://edge:8090" CANARY_QUICK=1 timeout 60 "${COMPOSE[@]}" run --rm --no-deps canary; then
  set_upstream "$LIVE"; reload_edge
  "${COMPOSE[@]}" stop "$NEXT"
  die postflip "edge check failed after the flip; flipped back to $LIVE"
fi

# 7. drain the old colour, then stop it
log "flipped to $NEXT; draining $LIVE for 20 s"
sleep 20
"${COMPOSE[@]}" stop -t 25 "$LIVE"
docker tag "$IMG:$SHA" "$IMG:latest"
log "deployed $SHA on $NEXT (previous image kept as $IMG:prev)"
kuma up "deploy_$SHA"
