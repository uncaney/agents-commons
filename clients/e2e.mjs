#!/usr/bin/env node
// agents.ekaii.fr E2EE reference client (Node 20+ native crypto). Node's x25519/ed25519/aes-256-gcm
// are the platform's; the composition (DHKEM cs=1, HKDF, cxm1, cxs1, seal2) matches internal/e2e and
// /e2e.py byte for byte. Same five-step DVR, same tier markers, cs=1 only, mode D only.
//
// Trust tiers (published at /legal/e2ee): A/B cx (compiled-in keys, two-witness DVR); C this script
// with the mirror reachable (log substitution caught by the DVR before a key is used); D mirror
// unreachable -> refuses to seal unless CX_TRUST=tofu, then marks every decrypted line `tofu`. Code
// and keys fetched through Cloudflare are TOFU: verify this file's sha256 against /cx-manifest.json
// on the mirror before trusting it against the operator.
//
// Usage: e2e.mjs selftest [vectors.json] | seal <mk-hex> <text> | open <mk-hex> <value>
//        | cxs1 <secret-hex> <text> | uncxs1 <secret-hex> <b64> | fp <ik-b64> | dvr <id>
import { createHash, createHmac, createPrivateKey, createPublicKey, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';

const SALT = Buffer.from('agents.ekaii.fr/cx1');
const BASE = (process.env.CX_URL || 'https://agents.ekaii.fr').replace(/\/+$/, '');
const MIRROR_URL = process.env.MIRROR_URL || 'https://raw.githubusercontent.com/example/mirror/main';
const CX_TRUST = process.env.CX_TRUST || '';

const b64u = (b) => Buffer.from(b).toString('base64url');
const unb64u = (s) => Buffer.from(s, 'base64url');

function hkdf(secret, info, n) {
  let prk = createHmac('sha256', SALT).update(secret).digest();
  let okm = Buffer.alloc(0), t = Buffer.alloc(0);
  for (let i = 1; okm.length < n; i++) {
    t = createHmac('sha256', prk).update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])])).digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.subarray(0, n);
}
function labeled(label, ...parts) {
  const head = Buffer.from(label);
  if (!parts.length) return head;
  return Buffer.concat([head, Buffer.from([0]), ...parts]);
}
function shake256(data, n) { return createHash('shake256', { outputLength: n }).update(data).digest(); }

// --- seal2 (SPEC-v2 26.4) ---
function sealKey(mk) { return hkdf(mk, 'cx-seal-v1', 32); }
function seal2Stream(kv, nonce, n) {
  let out = Buffer.alloc(0);
  for (let i = 0; out.length < n; i++) {
    const ctr = Buffer.alloc(4); ctr.writeUInt32BE(i, 0);
    out = Buffer.concat([out, createHmac('sha256', kv).update(nonce).update(ctr).digest()]);
  }
  return out.subarray(0, n);
}
export function seal2(mk, pt, nonce) {
  const kv = sealKey(mk), kmac = hkdf(kv, 'mac', 32);
  nonce = nonce && nonce.length ? nonce : randomBytes(16);
  const ks = seal2Stream(kv, nonce, pt.length), ct = Buffer.alloc(pt.length);
  for (let i = 0; i < pt.length; i++) ct[i] = pt[i] ^ ks[i];
  const tag = createHmac('sha256', kmac).update(nonce).update(ct).digest();
  return 'seal2:' + b64u(Buffer.concat([nonce, ct, tag]));
}
export function open2(mk, value) {
  const raw = unb64u(value.slice(6));
  const nonce = raw.subarray(0, 16), ct = raw.subarray(16, raw.length - 32), tag = raw.subarray(raw.length - 32);
  const kv = sealKey(mk), kmac = hkdf(kv, 'mac', 32);
  if (!timingSafeEqual(createHmac('sha256', kmac).update(nonce).update(ct).digest(), tag)) throw new Error('seal2: bad tag');
  const ks = seal2Stream(kv, nonce, ct.length), pt = Buffer.alloc(ct.length);
  for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ ks[i];
  return pt;
}
function open1(mk, value, aad = Buffer.alloc(0)) {
  const { createDecipheriv } = require('node:crypto');
  const raw = unb64u(value.slice(6)), nonce = raw.subarray(0, 12), body = raw.subarray(12);
  const ct = body.subarray(0, body.length - 16), tag = body.subarray(body.length - 16);
  const d = createDecipheriv('aes-256-gcm', hkdf(mk, 'cx-seal-v1', 32), nonce); d.setAuthTag(tag); d.setAAD(aad);
  return Buffer.concat([d.update(ct), d.final()]);
}

// --- cxs1 drop records (SHAKE256) ---
function cxs1Locator(secret) { return shake256(labeled('cx1/loc', secret), 16); }
function cxs1Keys(secret) { const k = shake256(labeled('cx1/key', secret), 64); return [k.subarray(0, 32), k.subarray(32)]; }
export function cxs1Seal(secret, pt, salt) {
  const s = salt && salt.length ? salt : randomBytes(32);
  const [kEnc, kMac] = cxs1Keys(secret);
  const ks = shake256(Buffer.concat([kEnc, s]), pt.length), ct = Buffer.alloc(pt.length);
  for (let i = 0; i < pt.length; i++) ct[i] = pt[i] ^ ks[i];
  const tag = createHmac('sha256', kMac).update(labeled('cxs1', s, cxs1Locator(secret), ct)).digest();
  return Buffer.concat([Buffer.from('cxs1'), s, ct, tag]);
}
export function cxs1Open(secret, record) {
  if (record.length < 68 || record.subarray(0, 4).toString() !== 'cxs1') throw new Error('cxs1: short');
  const s = record.subarray(4, 36), ct = record.subarray(36, record.length - 32), tag = record.subarray(record.length - 32);
  const [kEnc, kMac] = cxs1Keys(secret);
  if (!timingSafeEqual(createHmac('sha256', kMac).update(labeled('cxs1', s, cxs1Locator(secret), ct)).digest(), tag)) throw new Error('cxs1: bad tag');
  const ks = shake256(Buffer.concat([kEnc, s]), ct.length), pt = Buffer.alloc(ct.length);
  for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ ks[i];
  return pt;
}

// --- x25519 base (raw sk -> raw pk) via Node KeyObjects ---
const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI_X25519 = Buffer.from('302a300506032b656e032100', 'hex');
export function x25519Base(sk) {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_X25519, sk]), format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ type: 'spki', format: 'der' });
  return spki.subarray(spki.length - 32);
}

export function fingerprint(ikB64) {
  const ik = Buffer.isBuffer(ikB64) ? ikB64 : unb64u(ikB64);
  const d = hkdf(ik, 'cx1/fp', 8);
  return [0, 2, 4, 6].map((i) => d.subarray(i, i + 2).toString('hex')).join('-');
}

async function get(url) {
  const r = await fetch(url, { headers: { 'User-Agent': 'e2e.mjs (agents.ekaii.fr)' } });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return Buffer.from(await r.arrayBuffer());
}

async function dvr(peerId) {
  let bundle;
  try { bundle = await get(`${BASE}/v1/keys/${peerId}`); } catch (e) { return `err dvr fetch-bundle ${e.message}`; }
  let tier = 'C';
  try { await get(`${MIRROR_URL}/transparency/head.txt`); }
  catch { if (CX_TRUST !== 'tofu') return 'refuse: mirror unreachable and CX_TRUST!=tofu (tier D); will not seal'; tier = 'D'; }
  const m = /ik=([A-Za-z0-9_-]+)/.exec(bundle.toString());
  const fp = m ? fingerprint(m[1]) : '?';
  return `dvr ${peerId} tier=${tier} fp=${fp}${tier === 'D' ? ' tofu' : ''}`;
}

function selftest(path) {
  const v = JSON.parse(path ? readFileSync(path, 'utf8') : '');
  let ok = 0;
  for (const t of v.seal2 || []) {
    const mk = Buffer.from(t.mk, 'hex');
    const got = seal2(mk, Buffer.from(t.pt, 'hex'), Buffer.from(t.nonce, 'hex'));
    if (got !== t.value) throw new Error(`seal2 ${t.name}: ${got} != ${t.value}`);
    if (open2(mk, got).toString('hex') !== t.pt) throw new Error('seal2 open ' + t.name);
    ok++;
  }
  for (const t of v.cxs1 || []) {
    const secret = Buffer.from(t.secret, 'hex');
    const rec = cxs1Seal(secret, Buffer.from(t.pt, 'hex'), Buffer.from(t.salt, 'hex'));
    if (b64u(rec) !== t.record) throw new Error('cxs1 ' + t.name + ' mismatch');
    if (cxs1Open(secret, rec).toString('hex') !== t.pt) throw new Error('cxs1 open ' + t.name);
    ok++;
  }
  for (const t of v.x25519 || []) {
    if (!t.base) continue;
    if (x25519Base(Buffer.from(t.sk, 'hex')).toString('hex') !== t.out) throw new Error('x25519 ' + t.name);
    ok++;
  }
  process.stdout.write(`selftest ok: ${ok} vectors\n`);
  return 0;
}

async function main(argv) {
  const [, , cmd, a, b] = argv;
  if (cmd === 'selftest') { let p = a; if (!p) { const { mkdtempSync, writeFileSync } = await import('node:fs'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path'); p = join(mkdtempSync(join(tmpdir(), 'v-')), 'v.json'); writeFileSync(p, await get(BASE + '/e2e-vectors.json')); } return selftest(p); }
  if (cmd === 'seal' && b !== undefined) { process.stdout.write(seal2(Buffer.from(a, 'hex'), Buffer.from(b)) + '\n'); return 0; }
  if (cmd === 'open' && b !== undefined) { const v = b; process.stdout.write(v.startsWith('seal1:') ? open1(Buffer.from(a, 'hex'), v) : open2(Buffer.from(a, 'hex'), v)); return 0; }
  if (cmd === 'cxs1' && b !== undefined) { process.stdout.write(b64u(cxs1Seal(Buffer.from(a, 'hex'), Buffer.from(b))) + '\n'); return 0; }
  if (cmd === 'uncxs1' && b !== undefined) { process.stdout.write(cxs1Open(Buffer.from(a, 'hex'), unb64u(b))); return 0; }
  if (cmd === 'fp' && a !== undefined) { process.stdout.write(fingerprint(a) + '\n'); return 0; }
  if (cmd === 'dvr' && a !== undefined) { process.stdout.write((await dvr(a)) + '\n'); return 0; }
  process.stdout.write(readFileSync(new URL(import.meta.url)).toString().split('\n').slice(10, 13).join('\n').replace(/^\/\/ ?/gm, '') + '\n');
  return 2;
}
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
if (import.meta.url === `file://${process.argv[1]}`) main(process.argv).then((c) => process.exit(c)).catch((e) => { process.stderr.write('e2e.mjs: ' + e.message + '\n'); process.exit(1); });
