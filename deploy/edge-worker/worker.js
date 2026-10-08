// agents.ekaii.fr edge worker (SPEC-v2 27.1): an outage-proof crawl surface.
//
// It is bound (via wrangler.toml routes) to ONLY the static crawl files a search/LLM crawler needs:
//   /robots.txt  /sitemap.xml  /sitemaps/*  /llms.txt  /index.md  /.well-known/*  /<indexnow-key>.txt
// For each GET/HEAD it tries the origin (the home box) with an 8 s timeout. A status < 500 passes
// straight through (including 301/304/404), so normal operation is a thin pass-through. On 5xx, 530
// or a timeout it serves the last copy mirrored into KV with its stored Content-Type and
// Last-Modified and an `X-Fallback: kv` header, so these files keep answering 200 while the origin is
// unreachable. It NEVER forwards a non-GET method and never proxies a write: KV is populated only by
// the gateway's courier (kind kv_mirror), never by this worker.
//
// The pure logic lives in handleRequest / isMirrored so it can be unit-tested under Node with a fake
// fetch and KV (worker_test.mjs).

export const ORIGIN_TIMEOUT_MS = 8000;

const INDEXNOW_KEY_RE = /^\/[0-9a-f]{32}\.txt$/;

// isMirrored reports whether a path is one of the seven routes this worker owns.
export function isMirrored(path) {
  return (
    path === "/robots.txt" ||
    path === "/sitemap.xml" ||
    path.startsWith("/sitemaps/") ||
    path === "/llms.txt" ||
    path === "/index.md" ||
    path.startsWith("/.well-known/") ||
    INDEXNOW_KEY_RE.test(path)
  );
}

// fetchWithTimeout aborts the origin subrequest after ms so a hung origin becomes a fallback, not a
// hang. A fetch that throws (including the abort) is reported as a null response.
async function fetchWithTimeout(fetchImpl, request, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetchImpl(request, { signal: controller.signal });
  } catch (e) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// kvFallback serves the mirrored copy of path from KV, or null when nothing is stored.
async function kvFallback(env, path, method) {
  if (!env || !env.KV) return null;
  const { value, metadata } = await env.KV.getWithMetadata(path, { type: "arrayBuffer" });
  if (value === null || value === undefined) return null;
  const headers = new Headers();
  headers.set("Content-Type", (metadata && metadata.ct) || "application/octet-stream");
  if (metadata && metadata.last_modified) headers.set("Last-Modified", metadata.last_modified);
  headers.set("X-Fallback", "kv");
  // The origin's own Cache Rule would normally set these; on fallback the worker sets them itself so
  // the edge and clients keep serving the stale copy for the whole stale-if-error window.
  headers.set("Cache-Control", "public, max-age=300, stale-while-revalidate=3600, stale-if-error=604800");
  const body = method === "HEAD" ? null : value;
  return new Response(body, { status: 200, headers });
}

// handleRequest is the full decision for one request. fetchImpl is injected for tests; in production
// it is the global fetch (a subrequest reaches the origin, not this worker).
export async function handleRequest(request, env, fetchImpl) {
  const doFetch = fetchImpl || fetch;
  const path = new URL(request.url).pathname;

  // A path outside our route set is passed straight to the origin, untouched (wrangler routes mean
  // this is rare, but keep it a transparent proxy if it ever happens).
  if (!isMirrored(path)) {
    return doFetch(request);
  }

  // These are read-only resources: a non-GET/HEAD method is never forwarded and never written to KV.
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("method not allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
  }

  const resp = await fetchWithTimeout(doFetch, request, ORIGIN_TIMEOUT_MS);
  if (resp && resp.status < 500) {
    return resp; // healthy origin (or a normal 3xx/404): pass through
  }

  const fb = await kvFallback(env, path, request.method);
  if (fb) return fb;

  // Origin down and nothing mirrored yet: surface a shed-style 503 rather than the raw 5xx.
  return resp || new Response("origin unavailable", { status: 503, headers: { "Retry-After": "120" } });
}

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, fetch);
  },
};
