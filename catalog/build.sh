#!/usr/bin/env bash
# catalog/build.sh: builds the catalog modules with Docker (BuildKit) and prints their hashes.
# Runs on the SERVER (or any Linux box with Docker), never on the operator machine (SPEC-v2 15.4).
#
#   catalog/build.sh [name...]        default: every service directory with a Dockerfile
#   REPRO=1 catalog/build.sh cxlua    build twice (second time without cache) and compare hashes
#   NO_CACHE=1                        pass --no-cache to docker build
#
# Output per module: out/<name>/<name>.wasm, out/<name>/manifest.json (publishable manifest:
# the source manifest without the pipeline-only `kat` list), one line
#   <sha256> <name>@<ver> <size> out/<name>/<name>.wasm
# and, for modules over 4 MiB (which need a pin, 14.4), a "pin:" line appended to
# out/PINS.candidate.txt. Then: catalog/verify.sh <name>; cxa blob; cxa pin; cxa publish
# (README.md walks through it).
set -euo pipefail
cd "$(dirname "$0")"

die() { echo "build.sh: $*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || [ "${CX_BUILD_ANYWHERE:-}" = 1 ] || die "builds run on the server (Linux + Docker), never on the operator machine; set CX_BUILD_ANYWHERE=1 to override"
command -v docker >/dev/null || die "docker not found"
command -v python3 >/dev/null || die "python3 not found"
export DOCKER_BUILDKIT=1
export SOURCE_DATE_EPOCH=0

ALL=()
for d in */; do
  d=${d%/}
  [ -f "$d/Dockerfile" ] && [ -f "$d/manifest.json" ] && ALL+=("$d")
done
NAMES=("$@")
[ ${#NAMES[@]} -gt 0 ] || NAMES=("${ALL[@]}")
[ ${#NAMES[@]} -gt 0 ] || die "nothing to build"

mkdir -p out
: > out/PINS.candidate.txt

ver_of() { local v=1; [ -f "$1/VERSION" ] && v=$(tr -dc '0-9' < "$1/VERSION"); echo "${v:-1}"; }

build_once() { # name dest
  local name=$1 dest=$2 extra=()
  [ "${NO_CACHE:-}" = 1 ] && extra+=(--no-cache)
  rm -rf "$dest"
  docker build --progress=plain "${extra[@]}" -f "$name/Dockerfile" --output "type=local,dest=$dest" . \
    > "out/$name.build.log" 2>&1 || { tail -40 "out/$name.build.log" >&2; die "$name: docker build failed (log: catalog/out/$name.build.log)"; }
  [ -s "$dest/$name.wasm" ] || die "$name: Dockerfile did not export /$name.wasm"
  head -c 4 "$dest/$name.wasm" | od -An -c | grep -q '\\0   a   s   m' || die "$name: output is not a wasm module"
}

for name in "${NAMES[@]}"; do
  [ -f "$name/Dockerfile" ] || die "$name: no Dockerfile"
  ver=$(ver_of "$name")
  echo "== $name@$ver"
  build_once "$name" "out/$name"
  f=out/$name/$name.wasm
  hash=$(sha256sum "$f" | cut -d' ' -f1)
  size=$(stat -c %s "$f")
  if [ "${REPRO:-}" = 1 ]; then
    NO_CACHE=1 build_once "$name" "out/$name.repro"
    hash2=$(sha256sum "out/$name.repro/$name.wasm" | cut -d' ' -f1)
    if [ "$hash" = "$hash2" ]; then echo "repro: identical ($hash)"; else echo "repro: DIFFERENT $hash vs $hash2" >&2; exit 1; fi
    rm -rf "out/$name.repro"
  fi
  # publishable manifest: source manifest minus the pipeline-only `kat` list
  python3 -I - "$name/manifest.json" "out/$name/manifest.json" <<'EOF'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
m.pop("kat", None)
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(m, indent=1, ensure_ascii=True) + "\n")
EOF
  echo "$hash $name@$ver $size $f"
  if [ "$size" -gt 4194304 ]; then
    echo "pin: $hash $name@$ver $size" | tee -a out/PINS.candidate.txt
    [ "$size" -gt 16777216 ] && echo "note: over 16 MiB -> upload with \`cxa blob\` (PUT /admin/blob), POST /v1/b refuses it"
  fi
done

echo
echo "next: catalog/verify.sh ${NAMES[*]}   # KAT suite twice through cxw; then cxa blob / cxa pin / cxa publish (README.md)"
