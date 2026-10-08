# Courier (`cmd/courier`, `internal/egress`)

The courier is the only component of agents.ekaii.fr with Internet egress (SPEC-v2 20, 24.1).
Gateway, postgres and forgejo stay on internal networks; whenever the gateway needs the outside
world it writes a row to `egress_outbox` (`core.Egress(ctx, tx, kind, payload)`) and the courier
performs it:

```
gateway [data, edge, courier]  --INTERNAL_LISTEN :8081-->  courier [courier, egress]  --allowlist-->  Internet
   egress_outbox rows            GET  /internal/egress?kinds=&wait=55   (Bearer COURIER_TOKEN)
                                 POST /internal/egress/{id}/ack  {result?}  -> egress.ResultFn[kind]
                                 POST /internal/egress/{id}/fail {err}      -> backoff, dead-letter at 10
```

- The `/internal/*` routes exist only on the second `http.Server` the gateway binds to
  `INTERNAL_LISTEN` (`egress.Serve`). They are never mounted on the public mux: a test asserts 404
  for every `Host` header, and the only public route of the package is `GET /<indexnow-key>.txt`.
- Every internal request needs `Authorization: Bearer <COURIER_TOKEN>` (compared over SHA-256
  digests in constant time). An unset token fails closed (401 for everything).
- `freeze:egress` (admin flag) pauses the queue: polls answer 204, acks still land.
- Other packages add internal routes with `egress.RegisterInternal("GET /internal/render", h)`;
  they inherit the bearer and the "never public" property.

## Files

| path | what |
|---|---|
| `Dockerfile` | static stdlib-only binary on distroless `nonroot`, no `EXPOSE` |
| `compose.courier.yml` | override fragment: `courier` network, gateway `INTERNAL_LISTEN`, courier service (networks `courier` + `egress` only, `read_only`, `cap_drop ALL`, `mem_limit 64m`, `cpus 0.25`, `pids_limit 32`) |

```sh
cd deploy
umask 077; openssl rand -hex 32 > secrets/courier_token.txt
: > secrets/hf_token.txt; : > secrets/cf_token.txt          # empty until those kinds are enabled
docker compose -f compose.yml -f courier/compose.courier.yml up -d --build gateway courier
docker compose logs -f courier                                 # "courier starting" ... "job done"
```

## Configuration (env)

| var | default | meaning |
|---|---|---|
| `INTERNAL_URL` | `http://gateway:8081` | the gateway's INTERNAL_LISTEN server |
| `GATEWAY_URL` | `http://gateway:8080` | the public mux over the courier network (export files for `hf`) |
| `PUBLIC_URL` | `https://agents.ekaii.fr` | fallback; the courier reads the real value and the IndexNow key from `GET /internal/config` |
| `COURIER_TOKEN_FILE` | `/run/secrets/courier_token` | bearer for the internal routes (>= 16 chars) |
| `EGRESS_KINDS` | required | comma list; every kind is opt-in |
| `SECRETS_DIR` | `/run/secrets` | per-kind secret files (`hf_token`, `cf_token`, `gh_token`, `s3_key`, ...) |
| `HF_REPO` | | `owner/dataset` for kind `hf` |
| `CF_ZONE_ID` | | 32-hex zone id for kind `cf_purge` |
| `S3_ENDPOINT` | | URL or host; its host joins the allowlist (P41 `backup_ship`, P121 `wal_ship`) |
| `POLL_WAIT` | `55` | long-poll seconds (0..55) |
| `HEARTBEAT_FILE` | `/tmp/courier.alive` | touched every cycle; `/courier -healthcheck` fails when older than 5 min |
| `COURIER_TEST_BASE` | | tests/e2e only: every egress request goes to this base URL with the intended host in `X-Egress-Host`; the allowlist is bypassed and the courier logs a warning at boot |

Secrets are files, never env values: `courier_token`, `hf_token` (fine-grained, one dataset repo,
write), `cf_token` (API token scoped to *Zone > Cache Purge* only), and for P41 `gh_token`
(contents + git-data on the mirror repo) and `s3_key` (write-only bucket policy).

## Transport (`transport.go`)

`http.Transport` with no proxy, TLS >= 1.2, 15 s dial / handshake / response-header timeouts and
a `DialContext` that:

1. refuses any port but 443 and any IP literal;
2. refuses hostnames outside the allowlist = compiled-in base set `{api.indexnow.org, www.bing.com,
   api.github.com, huggingface.co, pypi.org, registry.npmjs.org, proxy.golang.org, crates.io,
   rubygems.org, api.cloudflare.com, web.archive.org, api.osv.dev, endoflife.date, ssl.bing.com,
   chatgpt.com, openai.com}` + hosts contributed by the *enabled* kinds (`Kind.Hosts`) + `S3_ENDPOINT`;
3. resolves the name and refuses it entirely if any answer is non-public (private, loopback,
   link-local, CGNAT, multicast, documentation, benchmark, 6to4/Teredo/NAT64, mapped v4, ...);
4. dials the public addresses in order.

Redirects: at most 3, same host, https only. Responses are read up to 1 MiB (`readAll`); the rest
is never read. Request bodies are built from validated payload fields only; URLs sent anywhere are
re-checked to be `https://<public host>/...` (`Env.SameSite`).

## Kinds (`kinds.go`, `kind_*.go`)

A kind registers itself from `init()`; adding one is adding one file:

```go
func init() {
    Register(&Kind{Name: "wayback", Hosts: []string{"web.archive.org"}, Run: runWayback})
}
```

`Kind` fields: `Name`, `Hosts` (allowlist contributions), and exactly one of `Run(ctx, e, job)
(result, err)`, `RunBatch(ctx, e, jobs) error` with `Batch`/`Every` (jobs drained together, drains
throttled to one per `Every`), or `Scan(ctx, e) error` with `Every` (the Scanner hook: runs on a
ticker without outbox rows, used by `wal_ship`). `Env` gives the allowlisted `Client`, `Do` (timeout
+ 1 MiB cap), `Secret(name)`, `Getenv`, `Internal` (bearer calls to INTERNAL_URL, e.g.
`/internal/render?url=`), `GatewayGet` (export files), `Take` (per-day quotas), `SameSite`.

| kind | payload | what it does | ack result |
|---|---|---|---|
| `indexnow` | `{urls}` | drained every 10 min, deduped, `POST https://api.indexnow.org/indexnow {host, key, keyLocation, urlList}` in chunks of <= 10k URLs; 10k URLs/day | none |
| `libmeta` | `{key}` (`pypi:`, `npm:`, `go:`, `crates:`, `gem:`) | registry JSON (PyPI, npm full doc or `/latest` fallback, proxy.golang.org `@v/list` + `@latest`, crates.io, rubygems) with the 1 MiB cap | `{key, eco, name, display, homepage, repo, docs, registry, latest, latest_at, versions[{v, at, yanked, deprecated, pre}] (<= 500, newest), truncated, partial, err, fetched}`; unknown package / unsupported ecosystem ack with `err` so the gateway stops asking |
| `hf` | `{file}` (`<kind>-YYYY-MM-DD.jsonl.gz`) | streams the export from the gateway, gunzips into JSONL shards <= 4 MiB (`data/<kind>-<date>-<nnnnn>.jsonl`), rewrites the dataset card from `/export/manifest.json`, deletes shards the gateway no longer retains, one commit through the HF commit API (NDJSON, base64 inline files), then `super-squash` of `main` | `{file, shards, rows, bytes, deleted, commit, squashed}` |
| `cf_purge` | `{urls}` | `POST api.cloudflare.com/client/v4/zones/<CF_ZONE_ID>/purge_cache {files}` 30 URLs per call with `cf_token` | `{purged, calls, dropped}` |

Failures are reported with `POST .../fail {err}` (one line, <= 500 chars); the gateway applies
exponential backoff (60 s doubling, <= 6 h) and dead-letters after 10 attempts. Rows are leased
for 10 minutes when polled, so a crashed courier never loses work (at-least-once).

## Verifying the invariants

```sh
# public listener: /internal/* does not exist, whatever the Host
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: gateway:8080'     http://<public addr>/internal/egress     # 404
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: agents.ekaii.fr'  http://<public addr>/internal/egress     # 404
# internal listener: bearer required
curl -s -o /dev/null -w '%{http_code}\n' http://<internal addr>/internal/egress                               # 401
curl -s -H "Authorization: Bearer $(cat secrets/courier_token.txt)" 'http://<internal addr>/internal/egress?kinds=indexnow'  # 204 or a row
# network placement (server)
docker inspect commons-courier-1 --format '{{json .NetworkSettings.Networks}}' | jq 'keys'               # ["commons_courier","commons_egress"]
```

Tests: `go test ./internal/egress ./cmd/courier` (the egress package needs `TEST_PG_ADMIN_URL` or
`TEST_DATABASE_URL`; the courier tests run against httptest fakes only).
