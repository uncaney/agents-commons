#!/usr/bin/env bash
# verify.sh — run every interpreter's known-answer tests twice through two local
# workers against the built wasip1 seeds and confirm the stdout matches the
# sha256 pinned in each cmd/<name>/manifest.json (15.4, 27.6). Two independent
# runs stand in for the 2-donor consensus the gateway requires before a version
# is marked verified.
#
# Usage: verify.sh [SEED_DIR]
# The WASM runner is $WASM_RUN (a command that loads a wasip1 module path given
# as its first argument and feeds the program its stdin); it defaults to
# "wasmtime run". Any runtime honouring the wasip1 ABI works.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
seed="${1:-/seed}"
run_cmd="${WASM_RUN:-wasmtime run}"

names=(cx-starlark cx-goja cx-expr)
fail=0

for name in "${names[@]}"; do
	wasm="$seed/$name.wasm"
	manifest="$here/cmd/$name/manifest.json"
	if [ ! -f "$wasm" ]; then
		echo "MISSING $wasm (run build.sh first)" >&2
		fail=1
		continue
	fi
	n="$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))['tests']))" "$manifest")"
	echo "verify $name: $n KATs x2 workers" >&2
	for worker in A B; do
		for i in $(seq 0 $((n - 1))); do
			# in_text is the raw 15.4 framing payload fed to the program's stdin;
			# out_sha256 is the expected stdout digest.
			want="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tests"][int(sys.argv[2])]["out_sha256"])' "$manifest" "$i")"
			got="$(python3 -c 'import json,sys; sys.stdout.write(json.load(open(sys.argv[1]))["tests"][int(sys.argv[2])]["in_text"])' "$manifest" "$i" | $run_cmd "$wasm" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
			if [ "$got" != "$want" ]; then
				echo "FAIL $name worker=$worker kat=$i got=$got want=$want" >&2
				fail=1
			fi
		done
	done
done

if [ "$fail" -ne 0 ]; then
	echo "verify: FAILED" >&2
	exit 1
fi
echo "verify: all KATs reproduced on both workers" >&2
