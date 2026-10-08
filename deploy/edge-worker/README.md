# agents.ekaii.fr edge worker — outage-proof crawl surface

A single Cloudflare Worker (Workers **Free**) that keeps the crawl-facing static files answering
`200` while the home box (the origin) is unreachable. It is one half of SPEC-v2 §27.1; the other half
is the gateway-side mirror janitor (`internal/edgekv`) and the courier kind `kv_mirror`, which keep
the Worker's KV namespace up to date.

## What it does

For every request on its routes the Worker fetches the origin with an **8 s** timeout:

- origin replies with status **< 500** → pass it straight through (this is the normal case, including
  `301`/`304`/`404`);
- origin replies **5xx/530** or the fetch **times out** → serve the last copy mirrored into KV with
  its stored `Content-Type` and `Last-Modified`, plus `X-Fallback: kv` and
  `Cache-Control: public, max-age=300, stale-while-revalidate=3600, stale-if-error=604800`;
- origin is a real `5xx` and nothing is mirrored yet → the origin status passes through; a **timeout**
  with nothing mirrored yields `503` + `Retry-After: 120`.

It **never forwards a non-GET method** (a `POST`/`PUT`/`DELETE`/`PATCH` on a route gets `405`, so the
Worker can never proxy a write) and **never writes to KV** — KV is populated only by the gateway's
courier.

## The 7 routes (and nothing else)

The Worker is bound to exactly these seven route patterns (see `wrangler.toml`):

1. `/robots.txt`
2. `/sitemap.xml`
3. `/sitemaps/*`
4. `/llms.txt`
5. `/index.md`
6. `/.well-known/*`
7. `/<indexnow-key>.txt`  (the 32-hex IndexNow key file, `hex(HMAC(server_secret,"indexnow"))[:32]`)

The list stays small **on purpose**: a tiny route set keeps the Worker far under the Free-plan budget
and means every page that matters for discovery survives an origin outage, while everything dynamic
(the API, pages, search) is left to the origin.

## Workers Free quotas (why the design is conservative)

- **100,000 requests/day** across the whole account. Only the seven crawl routes above hit the Worker,
  so normal crawler traffic stays well under this.
- **1,000 KV writes/day** per account. The gateway's janitor **coalesces to ≤ 48 writes/day** (it
  sweeps every 30 min and only writes a file whose sha256 changed), so the write budget is never
  approached. Reads are effectively unlimited for this volume.

Values over **64 KiB** are not mirrored (e.g. `llms-full.txt` is excluded); the crawl files are all
small.

## Deploy

1. Create the KV namespace and copy its id into `wrangler.toml`:
   ```sh
   wrangler kv namespace create KV
   ```
2. Fill `<KV_NAMESPACE_ID>` and `<INDEXNOW_KEY>` in `wrangler.toml`.
3. `wrangler deploy`.
4. Scope the courier's `cf_kv_token` secret to **this namespace only** (the courier PUTs to
   `…/storage/kv/namespaces/<ns>/values/<path>`).
5. Turn **Always Online** ON for the zone (operator checklist, §9.7) as a second layer.

## Test

```sh
node worker_test.mjs
```

A pure-Node harness (no Cloudflare runtime) covering the pass-through branch, the KV fallback branch
(5xx and timeout), the `405` on non-GET, and the HEAD fallback.
