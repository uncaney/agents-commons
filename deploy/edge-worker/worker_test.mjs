// Unit tests for the edge worker's pure logic (SPEC-v2 27.1). Run with: node worker_test.mjs
// Uses only node:test + node:assert and a fake fetch + KV, so it needs no Cloudflare runtime.

import test from "node:test";
import assert from "node:assert/strict";

import { handleRequest, isMirrored, ORIGIN_TIMEOUT_MS } from "./worker.js";

// A tiny KV stub backed by a Map of key -> {value: ArrayBuffer, metadata}.
function fakeKV(entries) {
  const store = new Map(Object.entries(entries || {}));
  return {
    async getWithMetadata(key) {
      const e = store.get(key);
      if (!e) return { value: null, metadata: null };
      return { value: e.value, metadata: e.metadata || null };
    },
  };
}

function bytes(s) {
  return new TextEncoder().encode(s).buffer;
}

test("isMirrored matches exactly the seven routes", () => {
  for (const ok of [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemaps/0.xml",
    "/llms.txt",
    "/index.md",
    "/.well-known/agent.json",
    "/.well-known/security.txt",
    "/" + "a".repeat(32) + ".txt",
  ]) {
    assert.equal(isMirrored(ok), true, ok);
  }
  for (const bad of [
    "/",
    "/kb/x",
    "/index.html",
    "/favicon.ico",
    "/" + "A".repeat(32) + ".txt", // uppercase: not the indexnow key shape
    "/" + "a".repeat(31) + ".txt", // wrong length
    "/sitemap.xmlx",
  ]) {
    assert.equal(isMirrored(bad), false, bad);
  }
});

test("healthy origin passes through, KV is never consulted", async () => {
  let kvHit = false;
  const env = {
    KV: {
      async getWithMetadata() {
        kvHit = true;
        return { value: null, metadata: null };
      },
    },
  };
  const origin = async () => new Response("live robots", { status: 200, headers: { "Content-Type": "text/plain" } });
  const resp = await handleRequest(new Request("https://agents.ekaii.fr/robots.txt"), env, origin);
  assert.equal(resp.status, 200);
  assert.equal(await resp.text(), "live robots");
  assert.equal(resp.headers.get("X-Fallback"), null);
  assert.equal(kvHit, false);
});

test("a 404 from origin passes through unchanged (status < 500)", async () => {
  const env = { KV: fakeKV({ "/llms.txt": { value: bytes("mirrored"), metadata: { ct: "text/plain" } } }) };
  const origin = async () => new Response("nope", { status: 404 });
  const resp = await handleRequest(new Request("https://agents.ekaii.fr/llms.txt"), env, origin);
  assert.equal(resp.status, 404);
  assert.equal(resp.headers.get("X-Fallback"), null);
});

test("origin 5xx falls back to KV with stored content-type and Last-Modified", async () => {
  const env = {
    KV: fakeKV({
      "/robots.txt": {
        value: bytes("User-agent: *\nAllow: /\n"),
        metadata: { ct: "text/plain; charset=utf-8", last_modified: "Tue, 07 Oct 2026 10:00:00 GMT" },
      },
    }),
  };
  const origin = async () => new Response("boom", { status: 503 });
  const resp = await handleRequest(new Request("https://agents.ekaii.fr/robots.txt"), env, origin);
  assert.equal(resp.status, 200);
  assert.equal(resp.headers.get("X-Fallback"), "kv");
  assert.equal(resp.headers.get("Content-Type"), "text/plain; charset=utf-8");
  assert.equal(resp.headers.get("Last-Modified"), "Tue, 07 Oct 2026 10:00:00 GMT");
  assert.match(resp.headers.get("Cache-Control"), /stale-if-error=604800/);
  assert.equal(await resp.text(), "User-agent: *\nAllow: /\n");
});

test("origin timeout falls back to KV", async () => {
  const env = { KV: fakeKV({ "/sitemap.xml": { value: bytes("<urlset/>"), metadata: { ct: "application/xml" } } }) };
  // A fetch that never resolves until aborted; the worker's AbortController fires.
  const origin = (request, opts) =>
    new Promise((_resolve, reject) => {
      if (opts && opts.signal) opts.signal.addEventListener("abort", () => reject(new Error("aborted")));
    });
  const resp = await handleRequest(new Request("https://agents.ekaii.fr/sitemap.xml"), env, origin);
  assert.equal(resp.status, 200);
  assert.equal(resp.headers.get("X-Fallback"), "kv");
  assert.equal(resp.headers.get("Content-Type"), "application/xml");
});

test("origin 5xx with nothing in KV passes the origin status through", async () => {
  const env = { KV: fakeKV({}) };
  const origin = async () => new Response("boom", { status: 500 });
  const resp = await handleRequest(new Request("https://agents.ekaii.fr/robots.txt"), env, origin);
  assert.equal(resp.status, 500);
});

test("origin timeout with nothing in KV yields a 503 with Retry-After", async () => {
  const env = { KV: fakeKV({}) };
  const origin = (request, opts) =>
    new Promise((_resolve, reject) => {
      if (opts && opts.signal) opts.signal.addEventListener("abort", () => reject(new Error("aborted")));
    });
  const resp = await handleRequest(new Request("https://agents.ekaii.fr/robots.txt"), env, origin);
  assert.equal(resp.status, 503);
  assert.equal(resp.headers.get("Retry-After"), "120");
});

test("a non-GET method is never forwarded and never written to KV", async () => {
  let forwarded = false;
  let kvHit = false;
  const env = {
    KV: {
      async getWithMetadata() {
        kvHit = true;
        return { value: null, metadata: null };
      },
    },
  };
  const origin = async () => {
    forwarded = true;
    return new Response("should not happen", { status: 200 });
  };
  for (const method of ["POST", "PUT", "DELETE", "PATCH"]) {
    const resp = await handleRequest(new Request("https://agents.ekaii.fr/robots.txt", { method }), env, origin);
    assert.equal(resp.status, 405, method);
    assert.equal(resp.headers.get("Allow"), "GET, HEAD");
  }
  assert.equal(forwarded, false, "origin must never be hit for a non-GET on a mirror route");
  assert.equal(kvHit, false, "KV must never be read for a non-GET");
});

test("HEAD fallback carries headers but no body", async () => {
  const env = { KV: fakeKV({ "/index.md": { value: bytes("# index"), metadata: { ct: "text/markdown" } } }) };
  const origin = async () => new Response("boom", { status: 530 });
  const resp = await handleRequest(new Request("https://agents.ekaii.fr/index.md", { method: "HEAD" }), env, origin);
  assert.equal(resp.status, 200);
  assert.equal(resp.headers.get("X-Fallback"), "kv");
  assert.equal(await resp.text(), "");
});

test("origin timeout is 8 seconds", () => {
  assert.equal(ORIGIN_TIMEOUT_MS, 8000);
});
