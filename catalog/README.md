# catalog/ : interpreter and toolchain modules for the WASM service catalog

Build side of SPEC-v2 section 15.4. Nothing in this directory is imported by Go code; the
gateway only ever sees the finished `.wasm` modules, uploaded and published by the operator.
Builds run on the **server** (Linux + Docker, x86_64), never on the operator machine.

| service          | what                                             | source pin                 | size (expected) | pin needed | status |
|------------------|--------------------------------------------------|----------------------------|-----------------|------------|--------|
| `cxlua`          | Lua 5.4 + launcher                               | lua 5.4.9                  | ~0.4 MiB        | no         | launcher exercised natively; wasm build on server |
| `cxjs`           | quickjs-ng + launcher                            | quickjs-ng v0.17.0         | ~1.3 MiB        | no         | launcher exercised natively; wasm build on server |
| `cxpy`           | CPython 3.13 + stdlib (wasi-vfs) + launcher      | CPython 3.13.16, wasi-vfs 0.6.3 | 25-40 MiB  | yes (+ `cxa blob`) | launcher exercised natively (CPython 3.14); cross-build on server |
| `cx-wat2wasm`    | WAT text -> wasm binary (wabt library)           | wabt 1.0.42                | < 4 MiB         | no         | unverified build |
| `cx-wasm-validate` | wasm binary -> `ok` or wabt errors             | wabt 1.0.42                | < 4 MiB         | no         | unverified build |
| `cx-wasm-strip`  | drop custom sections (plain C section walker)    | (libc only)                | ~20 KiB         | no         | source exercised natively |
| `cx-wasm-opt`    | binaryen default passes, -Os style               | binaryen version_133       | > 4 MiB         | yes        | unverified build, riskiest (see below) |

All Dockerfiles pin **wasi-sdk 24** (x86_64-linux tarball, sha256 in the file) and share a
byte-identical first stage, so BuildKit downloads and unpacks the SDK once. Every source
tarball is fetched over HTTPS and checked against the sha256 recorded in its Dockerfile.

## Layout

```
catalog/
  README.md            this file
  PINS.txt             pins live on the server: "<sha256> <name>@<ver> <size>" (regex in the header)
  check.py             python3 -I validator / generator (acceptance: manifests, Dockerfiles, PINS, scripts)
  build.sh             docker builds -> out/<name>/<name>.wasm + hashes (+ out/PINS.candidate.txt)
  verify.sh            KAT suite twice through cxw against a (local) gateway; --record fills kat/*.out
  launcher/            launcher.{h,c}: the common stdin framing (JSON or NUL split) in C99
  tools/embed.sh       turns bootstrap.py into C string literals (cxpy)
  <name>/Dockerfile    one reproducible build per service, context = catalog/
  <name>/VERSION       the service version the next publish uses (integer)
  <name>/manifest.json SPEC 15.1 manifest (+ REV3 fields) + `kat`: the KAT program ids
  <name>/kat/          KAT programs: <id>.<js|lua|py> (+ .stdin, .argv) or <id>.in (tools),
                       <id>.out = expected stdout, <id>.exit = expected exit code (absent = 0),
                       TESTS = the ids published as manifest `tests` (<= 10, exit 0, short)
  out/                 build products (git-ignored by the operator; never committed)
```

## The launcher contract (15.4)

The job input (stdin of the module) is either

```
{"code": "<program>", "stdin": "<text>", "argv": ["a", "b"]}      first non-blank byte is "{"
<program> NUL <stdin>                                              otherwise (no NUL: all code)
```

`argv` and `stdin` are optional. A leading `{` that does not parse as that object falls back
to the NUL split, so a program that starts with a brace still runs. The interpreter then runs
the program with the framed stdin as its stdin and `argv` as its arguments (`scriptArgs`,
`arg`, `sys.argv`, with `[0] = "<code>"`), writes the program's stdout, and:

- exits 0 when the program ends normally;
- on an uncaught error prints a **compact traceback on stdout** and exits 1
  (stderr is discarded by the sandbox, so everything a caller needs is on stdout):
  `Uncaught <error>` + stack (cxjs), `<code>:LINE: msg` + `stack traceback:` (cxlua),
  `Traceback (most recent call last): ...` without source lines (cxpy);
- `exit(n)` / `os.exit(n)` / `sys.exit(n)` exit with `n`; `sys.exit("msg")` prints `msg`, exit 1.

When a job fs (REV3 zip mount) is present, `/lib` is the import root: quickjs ES-module
imports, Lua `package.path`, and the first `sys.path` entry. The three manifests set
`fs_override: true` so `py{code, fs:"<lib.zip>"}` works once the gateway supports it.

Determinism comes from the sandbox (fake clock starting 2026-01-01T00:00:00Z advancing 1 ms per
read, constant random source, no environment) and from the launchers: cxpy sets
`use_hash_seed=1, hash_seed=0, isolated=1, site_import=0, buffered_stdio=0, write_bytecode=0`,
no environment; cxjs seeds `Math.random` from the (fake) clock; cxlua's `math.random` seed
derives from the (fake) time. `17-date-clock` in each KAT suite asserts the fake clock contract.

Tools (`cx-*`) read raw stdin and write raw stdout, no framing (`abi: raw`, or `text` for
`cx-wat2wasm`). Errors are `err ...` or wabt's error lines on stdout, exit 1.

## KAT suites

Each interpreter ships **20 programs** under `kat/`, four arithmetic, four string, three json,
three regex, three date, three error (id = `NN-<topic>-<slug>`): integers, floats, big numbers,
numbers from stdin, case/trim/pad, unicode, formatting, splitting with argv, JSON round trip,
nested JSON, JSON from stdin, matching, replacing, groups, fixed dates, date arithmetic, the
sandbox clock, caught errors, an uncaught error (exit 1) and an explicit exit code (3).

Expected outputs were recorded through **native builds of the same launcher sources against
the same engine versions** (Lua 5.4.9, quickjs-ng 0.17.0; CPython 3.14 for the Python suite,
whose programs avoid version-specific output) so that `kat/*.out` is exact, including
tracebacks. The two clock KATs are written by hand from the sandbox constants. Programs avoid
anything host-dependent: local time zones, hash-ordered iteration, addresses, `os.clock`.

`kat/TESTS` names the ids published as manifest `tests` (6 per interpreter, one per topic, all
exit 0): `check.py gen` turns them into `{"in_text": <framing>, "out_sha256":
sha256(kat/<id>.out)}`. The whole program travels inline in `in_text`, and the manifest must
stay under 4 KiB (15.1), so the published KAT of each topic is written compactly (single
quotes, few escapes) while its siblings carry the longer assertions; the generated manifests
are 3.8-4.0 KiB. The server re-runs the tests as KATs of the system root (15.2); with only the
operator's donors online the `trusted` donor counts as `d=1` (14.5).

## Pipeline (operator, on the server)

```
cd ~/agents-commons/catalog
python3 -I check.py                       # manifests, Dockerfiles, PINS.txt, scripts
./build.sh cxlua cxjs                     # docker builds -> out/<name>/<name>.wasm, prints "<sha256> <name>@<ver> <size>"
./verify.sh cxlua cxjs                    # local gateway + 2 donors; every KAT twice; stdout identical and == kat/*.out
./verify.sh --record cx-wat2wasm          # first run of a tool: record kat/*.out that could not be predicted
python3 -I check.py gen cx-wat2wasm       # refresh tests' out_sha256 from the recorded outputs, then re-run verify.sh
```

Then with the vault admin token (a secrets file path in `CX_ADMIN_TOKEN_FILE`, SPEC 18.5):

```
cxa blob out/cxlua/cxlua.wasm                                  # PUT /admin/blob, prints the hash (also for < 16 MiB; required above)
cxa pin <hash> cxpy 1 "cxpy 3.13.16 wasi-sdk 24"               # only modules > 4 MiB (cxpy, cx-wasm-opt)
cxa publish cxlua 1 <hash> out/cxlua/manifest.json             # POST /admin/svc under the system root (reserved names allowed)
```

`out/<name>/manifest.json` is the source manifest minus the pipeline-only `kat` list; the
source file itself is also under 4 KiB and publishable if the server ignores unknown keys.
After `cxa pin`, append the `pin:` line printed by build.sh to `PINS.txt` and commit it: the
repository then records exactly which bytes are live (`GET /v1/pins` shows the same columns).
`cxa unpin` + removing the line retires a module. Bump `<name>/VERSION` before rebuilding a
new version; versions are integers, never reused.

`REPRO=1 ./build.sh <name>` builds twice (second time without cache) and fails on differing
hashes: the flags are `-O2 -ffile-prefix-map=/src=.`, `SOURCE_DATE_EPOCH=0`, link-time strip,
then `cx-wasm-strip` drops the `producers` section. wasi-vfs packing (cxpy) is expected to be
deterministic for a fixed tree; the REPRO run is the proof.

## verify.sh

Local mode (default, Linux): builds `gateway`, `cx`, `cxw` from the repository, creates the
scratch database `commons_catalog_verify` on `PGURL` (default `postgres://cx@127.0.0.1:55432`),
starts the gateway on `127.0.0.1:18090` with a random admin token, joins three identities
(submitter, two donors with distinct roots) and starts the donors with `PIN_MAX_MB=64`
(P32a) so pinned big modules download. Modules over 16 MiB go through `PUT /admin/blob` and
`POST /admin/pin`. Each KAT runs twice (`"fresh": true` on the second submit bypasses the result
cache), stdout and exit code must match between passes and with `kat/<id>.out` / `.exit`.
Remote mode: `--url URL --token FILE [--admin FILE]` against a running stack with donors.
`--record` writes missing `.out`/`.exit` from a pass confirmed by both runs.

## Known risks and fallbacks (to resolve on the server)

- **cxpy**: `Tools/wasm/wasi.py build` cross-compiles CPython (host build-python first);
  wasi-sdk 24 is the version 3.13 is tested with. The launcher links `libpython3.13.a` with
  the `LIBS`/`MODLIBS`/`LDFLAGS` the configure step chose, plus `libwasi_vfs.a`, 8 MiB stack,
  then `wasi-vfs pack --mapdir /usr/local/lib/python3.13::<pruned Lib/>`. If the KAT suite
  cannot be made deterministic or the size is unreasonable, **RustPython** (`wasm32-wasip1`
  target, same launcher contract through a thin Rust `main`) is the documented fallback.
- **cx-wat2wasm / cx-wasm-validate**: wabt builds with `-fno-exceptions` and has no thread
  dependency; the wrappers use the library API (`WastLexer::CreateBufferLexer`, `ParseWatModule`,
  `ResolveNamesModule`, `ValidateModule`, `WriteBinaryModule` / `ReadBinaryIr`). The error-path
  KATs (`04-*`) have no recorded output until `verify.sh --record` runs once.
- **cx-wasm-opt**: binaryen assumes threads and C++ exceptions. The Dockerfile compiles it
  single-threaded through the headers in `cx-wasm-opt/shim/` (`thread`, `mutex`,
  `condition_variable`), replaces `find_package(Threads)` with an empty interface target, and
  uses `-fignore-exceptions` with `cxa_stubs.cc` turning any `throw` into `err ...` + exit 1.
  Expect to iterate. Fallbacks: build binaryen natively and run `wasm-opt` on the server in the
  publish pipeline only (no `cx-wasm-opt` service), or a WASI-native optimizer later.
- **cx-wasm-opt KAT outputs** (`01-empty`, `02-const`) are predictions (binaryen re-encodes
  the module; for these minimal modules the bytes should be identical); confirm or re-record
  with `verify.sh --record` before publishing.
- The sandbox contract the clock KATs rely on is `internal/sandbox` (fake epoch 1767225600 s,
  1 ms per read). If P32a changes it, re-record `17-date-clock` for the three interpreters.
- wasi-sdk tarball pin is x86_64 only (the Dockerfiles refuse other architectures).
- `debian:bookworm-slim` is pinned by tag, not digest: the apt layer is not reproducible; the
  module bytes are (the toolchain is the pinned SDK tarball).
