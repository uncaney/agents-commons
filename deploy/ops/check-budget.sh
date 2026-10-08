#!/usr/bin/env bash
# Storage budget check (SPEC-v2 21.2): `gateway -check-budget` must pass (the storage class caps plus
# PG_MAX_BYTES fit in DISK_BUDGET) and the quota'd volumes (pgdata, blobs) must exist with headroom.
# Run before a deploy and from cron (daily); exit 1 on any failure.
# Usage: deploy/ops/check-budget.sh        env: FREEZE_PCT=90 (the governor's freeze threshold)
set -euo pipefail
cd "$(dirname "$0")/.."            # deploy/
FREEZE_PCT=${FREEZE_PCT:-90}
fail() { echo "check-budget: FAIL $*" >&2; exit 1; }

# 1. the binary's own check (reads DISK_BUDGET, PG_MAX_BYTES and every registered class cap)
docker compose -f compose.yml run --rm --no-deps -T gateway -check-budget || fail "gateway -check-budget"
echo "check-budget: class caps fit DISK_BUDGET"

# 2. the volumes: present, below the freeze threshold
for v in commons_pgdata commons_blobs; do
  mp=$(docker volume inspect "$v" --format '{{.Mountpoint}}' 2>/dev/null) || fail "volume $v missing"
  line=$(df -P "$mp" | tail -n1)
  used=$(echo "$line" | awk '{print $5}' | tr -dc 0-9)
  size=$(echo "$line" | awk '{print $2}')
  avail=$(echo "$line" | awk '{print $4}')
  echo "check-budget: $v size=${size}K avail=${avail}K used=${used}%"
  [ "${used:-0}" -lt "$FREEZE_PCT" ] || fail "$v at ${used}% (>= ${FREEZE_PCT}%: the governor freezes writes)"
done

# 3. DISK_BUDGET (compose env) must not exceed the smallest quota'd volume
budget=$(grep -E '^\s*DISK_BUDGET:' compose.yml | head -n1 | sed -E 's/.*DISK_BUDGET:\s*"?([^"]*)"?.*/\1/')
[ -n "$budget" ] && echo "check-budget: DISK_BUDGET=$budget (see deploy/ops/README.md for the volume quota)"
echo "check-budget: ok"
