#!/usr/bin/env bash
# catalog/verify.sh: runs each module's KAT suite TWICE through cxw donors against a gateway
# and compares stdout between the two passes and with kat/<id>.out (SPEC-v2 15.4: identical
# stdout under the fake clock / constant rand before pinning). Runs on the server (needs the
# modules from build.sh); on the operator machine only against a remote stack (--url).
#
#   catalog/verify.sh [--record] [name...]
#       local mode: builds gateway/cx/cxw from this repo, starts them on 127.0.0.1 with a
#       scratch database (PGURL, default postgres://cx@127.0.0.1:55432) and two donors with
#       distinct roots, like test/e2e.sh. Big modules are stored through PUT /admin/blob and
#       pinned so pin-aware donors (PIN_MAX_MB) accept them.
#   catalog/verify.sh --url URL --token FILE [--admin FILE] [--record] [name...]
#       against a running gateway with donors online; --admin is needed for modules > 16 MiB.
#   --record  writes kat/<id>.out (+ .exit) for KATs that have no expected output yet, from a
#             pass-1 result confirmed by pass 2; then run `python3 -I catalog/check.py gen NAME`.
#   MODULE_DIR=dir  where <name>.wasm files are (default out/<name>/)
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(cd .. && pwd)

die() { echo "verify.sh: $*" >&2; exit 1; }
RECORD=0 URL="" TOKEN_FILE="" ADMIN_FILE="" NAMES=()
while [ $# -gt 0 ]; do
  case $1 in
    --record) RECORD=1 ;;
    --url) URL=$2; shift ;;
    --token) TOKEN_FILE=$2; shift ;;
    --admin) ADMIN_FILE=$2; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    -*) die "unknown flag $1" ;;
    *) NAMES+=("$1") ;;
  esac
  shift
done
command -v curl >/dev/null || die "curl not found"
command -v python3 >/dev/null || die "python3 not found"

if [ ${#NAMES[@]} -eq 0 ]; then
  for d in */; do d=${d%/}; [ -f "$d/manifest.json" ] && [ -f "${MODULE_DIR:-out/$d}/$d.wasm" ] && NAMES+=("$d"); done
fi
[ ${#NAMES[@]} -gt 0 ] || die "no built module found (run catalog/build.sh first) and no name given"

W=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$W"; }
trap cleanup EXIT

# --- local stack --------------------------------------------------------------------------
if [ -z "$URL" ]; then
  [ "$(uname -s)" = Linux ] || [ "${CX_VERIFY_ANYWHERE:-}" = 1 ] || die "local mode runs on the server; on the operator machine use --url against a remote stack"
  command -v go >/dev/null || die "go toolchain needed for local mode"
  command -v psql >/dev/null || die "psql needed for local mode"
  PGURL=${PGURL:-postgres://cx@127.0.0.1:55432}
  PORT=${PORT:-18090}
  URL=http://127.0.0.1:$PORT
  mkdir -p "$W/bin"
  (cd "$ROOT" && for b in gateway cx cxw; do go build -o "$W/bin/$b" "./cmd/$b"; done)
  psql "$PGURL/postgres" -qc "DROP DATABASE IF EXISTS commons_catalog_verify" -c "CREATE DATABASE commons_catalog_verify" >/dev/null
  ADMIN=adm-$RANDOM$RANDOM$RANDOM
  echo "$ADMIN" > "$W/admin"; ADMIN_FILE=$W/admin
  DATABASE_URL="$PGURL/commons_catalog_verify?sslmode=disable" LISTEN=127.0.0.1:$PORT DATA_DIR=$W/data \
    SERVER_SECRET=verify-secret-0123456789abcdef-$RANDOM ADMIN_TOKEN=$ADMIN FORGEJO_URL=http://127.0.0.1:1 FORGEJO_TOKEN=x \
    POW_BITS=14 PUBLIC_URL=$URL ABUSE_CONTACT=abuse@example.invalid SEED_WASM_DIR=$W/noseed \
    "$W/bin/gateway" > "$W/gw.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 60); do curl -fs "$URL/healthz" >/dev/null 2>&1 && break; sleep 0.25; done
  curl -fs "$URL/healthz" >/dev/null || { tail -20 "$W/gw.log" >&2; die "gateway did not start"; }
  for who in sub w1 w2; do
    mkdir -p "$W/id/$who"
    XDG_CONFIG_HOME=$W/id/$who CX_URL=$URL "$W/bin/cx" join "verify-$who" >/dev/null || die "join $who"
  done
  TOKEN_FILE=$W/id/sub/cx/token
  for who in w1 w2; do
    CX_URL=$URL CX_TOKEN_FILE=$W/id/$who/cx/token MAX_MS=30000 MAX_MB=256 PARALLEL=2 PIN_MAX_MB=${PIN_MAX_MB:-64} \
      CACHE_DIR=$W/cache-$who MEM_LIMIT_MB=1200 ACCEPT_NEW=1 ACCEPT_L0=1 "$W/bin/cxw" > "$W/$who.log" 2>&1 &
    PIDS+=($!)
  done
  echo "local stack up: $URL (2 donors)"
fi
[ -n "$TOKEN_FILE" ] && [ -s "$TOKEN_FILE" ] || die "--token FILE required"
TOKEN=$(tr -d '\n' < "$TOKEN_FILE")
ADMIN=""; [ -n "$ADMIN_FILE" ] && ADMIN=$(tr -d '\n' < "$ADMIN_FILE")

api() { curl -sS --max-time 120 -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json' "$@"; }
adm() { curl -sS --max-time 600 -H "Authorization: Bearer $ADMIN" -H 'Accept: application/json' "$@"; }
jget() { python3 -I -c 'import json,sys; d=json.load(sys.stdin); v=d.get(sys.argv[1], ""); print(v if v is not None else "")' "$1"; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
mhint() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

put_blob() { # file -> hash (POST /v1/b, or PUT /admin/blob + pin for big modules)
  local f=$1 size h
  size=$(stat -c %s "$f" 2>/dev/null || stat -f %z "$f")
  h=$(sha "$f")
  if [ "$size" -le 16777216 ]; then
    api -X POST "$URL/v1/b" -H 'Content-Type: application/octet-stream' --data-binary @"$f" | jget hash | grep -qx "$h" || die "blob upload failed for $f"
  else
    [ -n "$ADMIN" ] || die "$f is over 16 MiB: PUT /admin/blob needs --admin FILE"
    adm -X PUT "$URL/admin/blob" -H 'Content-Type: application/octet-stream' --data-binary @"$f" | jget hash | grep -qx "$h" || die "admin blob upload failed for $f"
  fi
  if [ "$size" -gt 4194304 ] && [ -n "$ADMIN" ]; then
    adm -X POST "$URL/admin/pin" -H 'Content-Type: application/json' \
      -d "{\"hash\":\"$h\",\"name\":\"$2\",\"ver\":${3:-1},\"note\":\"verify.sh\"}" >/dev/null || echo "warn: pin failed (donors need PIN_MAX_MB for $2)" >&2
  fi
  echo "$h"
}

run_job() { # wasm_hash input_file ms mb pass -> writes stdout to $6, prints "<status> <code>"
  local wasm=$1 inf=$2 ms=$3 mb=$4 pass=$5 outf=$6 inh id st
  inh=$(put_blob "$inf" "" "")
  local fresh=false; [ "$pass" = 2 ] && fresh=true
  id=$(api -X POST "$URL/v1/j" -H 'Content-Type: application/json' -d "{\"wasm\":\"$wasm\",\"in\":\"$inh\",\"ms\":$ms,\"mb\":$mb,\"fresh\":$fresh}" | jget id)
  [ -n "$id" ] || { echo "submit-failed 0"; return; }
  for _ in $(seq 40); do
    local j; j=$(api "$URL/v1/j/$id?wait=85")
    st=$(echo "$j" | jget status)
    case $st in
      done) api "$URL/v1/b/$(echo "$j" | jget out)" -o "$outf"; echo "done $(echo "$j" | jget code)"; return ;;
      failed) : > "$outf"; echo "failed:$(echo "$j" | jget reason) 0"; return ;;
    esac
  done
  : > "$outf"; echo "timeout 0"
}

total=0 bad=0
for name in "${NAMES[@]}"; do
  mod=${MODULE_DIR:-out/$name}/$name.wasm
  [ -f "$mod" ] || die "$name: $mod missing (run catalog/build.sh $name)"
  ver=1; [ -f "$name/VERSION" ] && ver=$(tr -dc '0-9' < "$name/VERSION")
  ms=$(mhint "$name/manifest.json" ms_hint); mb=$(mhint "$name/manifest.json" mb_hint)
  echo "== $name ($(stat -c %s "$mod" 2>/dev/null || stat -f %z "$mod") bytes, ms=$ms mb=$mb)"
  wasm=$(put_blob "$mod" "$name" "$ver")
  ids=$(python3 -I check.py ids "$name")
  for kid in $ids; do
    total=$((total+1))
    python3 -I check.py frame "$name" "$kid" > "$W/in"
    r1=$(run_job "$wasm" "$W/in" "$ms" "$mb" 1 "$W/o1"); r2=$(run_job "$wasm" "$W/in" "$ms" "$mb" 2 "$W/o2")
    exp=$(python3 -I check.py expect "$name" "$kid"); want_exit=${exp%% *}; want_file=${exp#* }
    s1=${r1%% *}; c1=${r1#* }; s2=${r2%% *}; c2=${r2#* }
    if [ "$s1" != done ] || [ "$s2" != done ]; then
      echo "FAIL $name/$kid: pass1=$r1 pass2=$r2"; bad=$((bad+1)); continue
    fi
    if ! cmp -s "$W/o1" "$W/o2" || [ "$c1" != "$c2" ]; then
      echo "FAIL $name/$kid: passes differ (nondeterministic): exit $c1 vs $c2, $(wc -c < "$W/o1") vs $(wc -c < "$W/o2") bytes"; bad=$((bad+1)); continue
    fi
    if [ -f "$want_file" ]; then
      if cmp -s "$W/o1" "$want_file" && [ "$c1" = "$want_exit" ]; then
        echo "ok   $name/$kid"
      else
        echo "FAIL $name/$kid: differs from kat/$kid.out (exit $c1, want $want_exit); got:"; head -c 600 "$W/o1" | sed 's/^/     | /'; bad=$((bad+1))
      fi
    elif [ "$RECORD" = 1 ]; then
      cp "$W/o1" "$want_file"; [ "$c1" != 0 ] && echo "$c1" > "$name/kat/$kid.exit"
      echo "rec  $name/$kid: recorded $(wc -c < "$W/o1") bytes, exit $c1"
    else
      echo "FAIL $name/$kid: no kat/$kid.out (use --record)"; bad=$((bad+1))
    fi
  done
done
echo
echo "KATs: $total, failures: $bad"
[ "$RECORD" = 1 ] && echo "recorded outputs: run  python3 -I catalog/check.py gen ${NAMES[*]}  then re-run verify.sh"
[ "$bad" -eq 0 ]
