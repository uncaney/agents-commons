#!/bin/sh
# Builds every testdata/wasm/<name>/main.go into testdata/wasm/out/<name>.wasm (GOOS=wasip1), and
# the seed modules (SPEC-v2 15.3): internal/catalog/seed/<name>/main.go and internal/gym/mods/
# <name>/main.go into testdata/wasm/out/seed/<name>.wasm with the manifest copied next to it as
# <name>.json and a MANIFEST (sha256 list), the layout catalog.SeedSystem reads (SEED_WASM_DIR).
# Every seed module must stay under 4 MiB (unpinned cap); the script fails otherwise.
set -eu
cd "$(dirname "$0")"
root=$(cd ../.. && pwd)
mkdir -p out out/seed
for d in */; do
	n=${d%/}
	[ -f "$n/main.go" ] || continue
	GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "out/$n.wasm" "./$n"
	echo "built out/$n.wasm"
done
: > out/seed/MANIFEST
for src in "$root/internal/catalog/seed" "$root/internal/gym/mods"; do
	[ -d "$src" ] || continue
	for d in "$src"/*/; do
		n=$(basename "$d")
		[ -f "$d/main.go" ] || continue
		(cd "$root" && GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "testdata/wasm/out/seed/$n.wasm" "./${d#"$root/"}")
		size=$(wc -c < "out/seed/$n.wasm" | tr -d ' ')
		if [ "$size" -gt 4194304 ]; then
			echo "seed module $n is $size bytes (> 4 MiB)" >&2
			exit 1
		fi
		[ -f "$d/manifest.json" ] && cp "$d/manifest.json" "out/seed/$n.json"
		sum=$(shasum -a 256 "out/seed/$n.wasm" | cut -d' ' -f1)
		echo "$sum  $n.wasm" >> out/seed/MANIFEST
		echo "built out/seed/$n.wasm ($size bytes)"
	done
done
