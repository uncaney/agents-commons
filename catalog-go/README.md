# catalog-go — Go-native interpreters (SPEC-v2 27.6, P106)

A **separate Go module** (`ekaii.fr/commons/catalog-go`, its own `go.mod`/`go.sum`)
holding three interpreters compiled to `wasip1/wasm` seed modules. Keeping them
out of the gateway module is deliberate: the gateway stays on stdlib + pgx +
wazero only, and **never imports this module**.

| command        | engine                    | ABI    |
|----------------|---------------------------|--------|
| `cx-starlark`  | `go.starlark.net`         | Python dialect, deterministic by design |
| `cx-goja`      | `github.com/dop251/goja`  | ES5.1+ |
| `cx-expr`      | `github.com/expr-lang/expr` | one expression |

## Launcher contract (15.4)

Each command reads **stdin** fully. A payload starting with `{` is parsed as
`{"code","stdin","argv"}`; otherwise the bytes before the first NUL are the
code and the bytes after are the program's stdin. Program output goes to
**stdout**; an exception prints a compact traceback to stdout and exits **1**.
Shared in `internal/launch`.

## Determinism

`internal/launch.FakeEpoch` (2026-01-01T00:00:00Z, matching `internal/sandbox`)
is the constant clock the interpreters ride: goja's `Date`/`Math.random` use a
fixed time and a constant splitmix64 source, starlark's `time.now()` uses the
same `NowFunc`, and expr receives it as `clock`. Object output uses ordered
structures only (never Go map iteration order), so a run is reproducible both
natively and under the wasip1 fake clock.

## KATs

Each command ships 20 known-answer tests (`cmd/<name>/kats.go`) covering
arithmetic, strings, json, regex-ish matching, dates under the fake clock and
error paths. `cmd/<name>/manifest.json` is the catalog publish manifest; its
`tests[].out_sha256` pin each KAT's stdout. `go test ./...` runs them natively
through each launcher, twice, and asserts they reproduce the manifest. Regenerate
the manifests with `KAT_WRITE=1 go test -run TestWriteManifest ./cmd/...`.

## Build & verify

- `build.sh [SEED_DIR] [SIZES_MD]` — `GOOS=wasip1 GOARCH=wasm go build -trimpath
  -ldflags='-s -w'` into `SEED_DIR` (default `/seed`) and writes the measured
  size table into `catalog/SIZES.md`. Invoked by the P60a Dockerfile stage.
- `verify.sh [SEED_DIR]` — runs every manifest KAT twice through two local
  workers (`$WASM_RUN`, default `wasmtime run`) against the built seeds and
  checks the stdout digests, standing in for the gateway's 2-donor consensus.

`catalog.SeedSystem` publishes the seeds under the system root at boot; modules
above 4 MiB are auto-pinned (`pins`, `note='seed'`). The op aliases `star{}`,
`jsg{}`, `expr{}` and `GET /wasm/sizes` live in the gateway's
`internal/gointerp`.
