#!/usr/bin/env bash
# build.sh — compile the three Go-native interpreters to wasip1/wasm seed
# modules (SPEC-v2 27.6) and write the measured size table into catalog/SIZES.md.
# Run from the P60a Dockerfile stage (module download happens here, pinned by
# go.sum). Usage: build.sh [SEED_DIR] [SIZES_MD]
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
seed="${1:-/seed}"
sizes="${2:-$here/../catalog/SIZES.md}"

mkdir -p "$seed" "$(dirname "$sizes")"

names=(cx-starlark cx-goja cx-expr)
langs=("go.starlark.net (Python dialect, deterministic)" "dop251/goja (ES5.1+)" "expr-lang/expr (one expression)")

for name in "${names[@]}"; do
	echo "building $name -> $seed/$name.wasm" >&2
	GOOS=wasip1 GOARCH=wasm go build -C "$here" -trimpath -ldflags='-s -w' \
		-o "$seed/$name.wasm" "./cmd/$name"
done

# human-readable MiB of a byte count (portable; wc -c instead of stat).
mib() { LC_NUMERIC=C awk -v b="$1" 'BEGIN{printf "%.1f MiB", b/1048576}'; }

{
	echo "# WASM interpreter sizes"
	echo
	echo "Measured GOOS=wasip1 GOARCH=wasm modules (-trimpath -ldflags='-s -w'),"
	echo "written by catalog-go/build.sh. A module above 4 MiB is auto-pinned so it"
	echo "reaches only big donors (27.6)."
	echo
	echo "## Go-native seeds (this catalog)"
	echo
	echo "| module | language | measured |"
	echo "|--------|----------|----------|"
	for i in "${!names[@]}"; do
		name="${names[$i]}"
		bytes="$(wc -c < "$seed/$name.wasm" | tr -d ' ')"
		printf '| %s | %s | %s (%s bytes) |\n' "$name" "${langs[$i]}" "$(mib "$bytes")" "$bytes"
	done
	echo
	echo "## Reference: other runtimes (not Go)"
	echo
	echo "| runtime | measured |"
	echo "|---------|----------|"
	echo "| QuickJS-ng | ~1.3 MiB |"
	echo "| Lua 5.4 | ~0.4 MiB |"
	echo "| Duktape | ~0.5 MiB |"
	echo "| Janet | ~1 MiB |"
	echo "| mruby | ~1.5-2 MiB |"
	echo "| CPython 3.13 | ~10-15 MiB + stdlib |"
	echo "| RustPython | ~15-25 MiB |"
	echo "| ruby.wasm | ~30-40 MiB |"
	echo "| MicroPython | no WASI port |"
	echo
	echo "The Go runtime floor is why the seeds sit where they do (a trivial Go"
	echo "hello is already ~2.1 MiB). The seeds are deterministic by construction and"
	echo "their known-answer tests run twice through two local workers before a"
	echo "version is marked verified."
} > "$sizes"

echo "wrote $sizes" >&2
