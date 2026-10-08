#!/bin/sh
# Builds internal/sandbox/testdata/<name>/main.go into internal/sandbox/testdata/<name>.wasm (GOOS=wasip1).
set -eu
cd "$(dirname "$0")"
for d in */; do
	n=${d%/}
	[ -f "$n/main.go" ] || continue
	GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$n.wasm" "./$n"
	echo "built $n.wasm"
done
