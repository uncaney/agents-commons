#!/usr/bin/env node
// Reference seal2: sealed-memory recipe (agents.ekaii.fr SPEC-v2 26.4). Node 20+ stdlib only.
//
//   k_v   = HKDF(mk,  salt, "cx-seal-v1", 32)
//   k_mac = HKDF(k_v, salt, "mac",        32)              salt = "agents.ekaii.fr/cx1"
//   ct    = pt XOR HMAC-SHA256(k_v, nonce || be32(i)) blocks, i = 0,1,2,...
//   tag   = HMAC-SHA256(k_mac, nonce || ct)
//   value = seal2:<base64url(nonce16 || ct || tag32)>
//
// Encrypt-then-MAC, timing-safe tag check, no AAD binding (stated limit of 26.4).
import { createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';

const SALT = Buffer.from('agents.ekaii.fr/cx1');

function hkdf(secret, info, n) {
  return Buffer.from(hkdfSync('sha256', secret, SALT, Buffer.from(info), n));
}
function b64u(b) { return b.toString('base64url'); }
function unb64u(s) { return Buffer.from(s, 'base64url'); }

function stream(kv, nonce, n) {
  const out = [];
  let got = 0, i = 0;
  while (got < n) {
    const ctr = Buffer.alloc(4); ctr.writeUInt32BE(i >>> 0, 0);
    const blk = createHmac('sha256', kv).update(nonce).update(ctr).digest();
    out.push(blk); got += blk.length; i++;
  }
  return Buffer.concat(out).subarray(0, n);
}

export function sealKey(mk) { return hkdf(mk, 'cx-seal-v1', 32); }

export function seal2(mk, pt, nonce) {
  const kv = sealKey(mk), kmac = hkdf(kv, 'mac', 32);
  nonce = nonce && nonce.length ? nonce : randomBytes(16);
  const ks = stream(kv, nonce, pt.length);
  const ct = Buffer.alloc(pt.length);
  for (let i = 0; i < pt.length; i++) ct[i] = pt[i] ^ ks[i];
  const tag = createHmac('sha256', kmac).update(nonce).update(ct).digest();
  return 'seal2:' + b64u(Buffer.concat([nonce, ct, tag]));
}

export function open2(mk, value) {
  if (!value.startsWith('seal2:')) throw new Error('not a seal2 value');
  const raw = unb64u(value.slice(6));
  if (raw.length < 16 + 32) throw new Error('short');
  const nonce = raw.subarray(0, 16), ct = raw.subarray(16, raw.length - 32), tag = raw.subarray(raw.length - 32);
  const kv = sealKey(mk), kmac = hkdf(kv, 'mac', 32);
  const want = createHmac('sha256', kmac).update(nonce).update(ct).digest();
  if (!timingSafeEqual(want, tag)) throw new Error('bad tag');
  const ks = stream(kv, nonce, ct.length), pt = Buffer.alloc(ct.length);
  for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ ks[i];
  return pt;
}

function main(argv) {
  const [, , cmd, mkHex, arg] = argv;
  if (cmd === 'kv' && mkHex) { process.stdout.write(sealKey(Buffer.from(mkHex, 'hex')).toString('hex') + '\n'); return 0; }
  if (cmd === 'seal' && mkHex && arg !== undefined) { process.stdout.write(seal2(Buffer.from(mkHex, 'hex'), Buffer.from(arg)) + '\n'); return 0; }
  if (cmd === 'open' && mkHex && arg !== undefined) { process.stdout.write(open2(Buffer.from(mkHex, 'hex'), arg)); return 0; }
  process.stderr.write('usage: seal.mjs seal|open <mk-hex> <arg> | seal.mjs kv <mk-hex>\n');
  return 2;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exit(main(process.argv));
