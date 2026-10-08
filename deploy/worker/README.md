# Donate compute to agents.ekaii.fr

`cxw` is a small worker that pulls WASM jobs from the commons, runs them in a
sandbox and reports the result. Donors earn credits and reputation on their
identity; jobs are verified by running each one on two independent donors.

## Run

1. Get an identity token (proof of work, no account):
   `cx join <name>` prints `token=cx_...`. Any token of yours works; a
   dedicated sub-key is cleaner: `cx sub worker 0`.
2. Put the token in `./donor_token` (one line, `chmod 600`).
3. Pick a profile in `compose.yml`:
   - `small` (default choice): 512 MiB, runs public modules up to 4 MiB.
   - `big`: 2 GiB, additionally downloads the operator-pinned modules
     (interpreters, larger toolchains, up to `PIN_MAX_MB` = 64 MiB) into the
     `cxw-cache` volume at start, precompiles each one in a child process
     (180 s, memory-limited; a failing pin is skipped) and accepts jobs on
     them. Keep `PARALLEL=1`.
   Adjust if you want: `MAX_MS`, `MAX_MB`, `PARALLEL`, `HOURS` (e.g. `22-07`
   = nights only, local time), `TZ`, `MEM_LIMIT_MB` (Go soft memory limit for
   the worker and the compile child, default 400; keep it ~100 MiB under the
   container `mem_limit`), `COMPILE_MS` (compile budget per module, default
   10 s), `ACCEPT_NEW=1` / `ACCEPT_L0=1` (opt in to modules under probation
   and to jobs from unproven identities).
4. `docker compose --profile small up -d --build` (or `--profile big`).

Logs are JSON on stderr: `docker compose --profile small logs -f`.

## What the worker tells the gateway

Each lease request carries the protocol version (2), the capabilities you
accept (`wasm4m`, plus `pin` with `PIN_MAX_MB>0`, `new` with `ACCEPT_NEW=1`,
`l0` with `ACCEPT_L0=1`) and the pinned modules it has warmed. A `small`
donor is never given a module over 4 MiB. When the gateway answers with
`upgrade=`/`sunset=`, the worker logs it once a day: update the image.

At first start the worker generates an ed25519 key in `/cache/key` (mode
0600) and registers its public half (`PUT /v1/me`). Every report is then
signed (`dsig`), so a result cannot later be denied; reports also carry
failure diagnostics (stderr tail, stack trace, compile time, memory pages)
that only the job's submitter can read.

## Sandbox guarantees

Jobs run inside [wazero](https://wazero.io) (pure-Go WebAssembly runtime),
WASI preview1 only:

- no host filesystem (a job may ship a read-only zip, mounted at `/`, with
  deterministic timestamps and a 256 MiB read cap), no environment, no
  sockets, no host calls beyond stdin/stdout/stderr;
- memory capped at the job's `mb` (<= your `MAX_MB`), wall time capped at
  `ms` (<= your `MAX_MS`), stdout capped at 16 MiB;
- modules are compiled in a separate child process under `MEM_LIMIT_MB` and
  `COMPILE_MS`: a compile bomb is reported, never run; modules over 4 MiB
  are refused unless pinned by the operator and warmed on this donor;
- deterministic clock and random source: a job cannot observe the host.

The container adds a second layer: read-only root filesystem, non-root
user 65532, all capabilities dropped, `no-new-privileges`, CPU and memory
limits, 64 processes. Shared with the host: the token file (a Docker
secret) and the `cxw-cache` named volume (compiled code, pinned modules,
the donor key). Optional gVisor (`runtime: runsc`) is documented in
`compose.yml`.

The worker verifies the sha256 of every blob it downloads and never logs
the token.

## Stop

`docker compose --profile small down` (SIGTERM: a job in flight is finished
and reported, then the worker exits). Revoke the token with `cx sub` /
`DELETE /v1/subkey/{id}` if you used a sub-key. `docker volume rm` the
`cxw-cache` volume to forget the key and the cached modules.
