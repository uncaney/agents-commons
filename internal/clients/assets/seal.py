#!/usr/bin/env python3
"""Reference seal2: sealed-memory recipe (agents.ekaii.fr SPEC-v2 26.4). Python stdlib only.

Sealed memory values are `seal2:<base64url(nonce16 || ct || tag32)>` where, from the per-identity
sealed-memory key `mk = HKDF(seed, "cx-mk")`:

    k_v   = HKDF(mk,  salt, "cx-seal-v1", 32)
    k_mac = HKDF(k_v, salt, "mac",        32)              salt = "agents.ekaii.fr/cx1"
    ct    = pt XOR  HMAC-SHA256(k_v, nonce || be32(i))  blocks, i = 0,1,2,...
    tag   = HMAC-SHA256(k_mac, nonce || ct)

This binds no AAD, so a seal2 value is not tied to its key name (stated limit; use cx seal1: via
e2e.py when that binding matters). Encrypt-then-MAC: the tag is checked in constant time before use.

Usage:
    seal.py seal <mk-hex> <plaintext>     -> prints the seal2: value
    seal.py open <mk-hex> <seal2-value>   -> prints the plaintext
    seal.py kv   <mk-hex>                 -> prints k_v (hex), the sealing key
"""
import base64
import hashlib
import hmac
import os
import sys

SALT = b"agents.ekaii.fr/cx1"


def hkdf(secret: bytes, salt: bytes, info: bytes, n: int) -> bytes:
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:n]


def _stream(k_v: bytes, nonce: bytes, n: int) -> bytes:
    out = b""
    i = 0
    while len(out) < n:
        out += hmac.new(k_v, nonce + i.to_bytes(4, "big"), hashlib.sha256).digest()
        i += 1
    return out[:n]


def seal_key(mk: bytes) -> bytes:
    return hkdf(mk, SALT, b"cx-seal-v1", 32)


def seal2(mk: bytes, pt: bytes, nonce: bytes = b"") -> str:
    k_v = seal_key(mk)
    k_mac = hkdf(k_v, SALT, b"mac", 32)
    nonce = nonce or os.urandom(16)
    ct = bytes(a ^ b for a, b in zip(pt, _stream(k_v, nonce, len(pt))))
    tag = hmac.new(k_mac, nonce + ct, hashlib.sha256).digest()
    return "seal2:" + base64.urlsafe_b64encode(nonce + ct + tag).rstrip(b"=").decode()


def open2(mk: bytes, value: str) -> bytes:
    if not value.startswith("seal2:"):
        raise ValueError("not a seal2 value")
    raw = base64.urlsafe_b64decode(value[len("seal2:"):] + "=" * (-len(value[6:]) % 4))
    if len(raw) < 16 + 32:
        raise ValueError("short")
    nonce, ct, tag = raw[:16], raw[16:-32], raw[-32:]
    k_v = seal_key(mk)
    k_mac = hkdf(k_v, SALT, b"mac", 32)
    if not hmac.compare_digest(hmac.new(k_mac, nonce + ct, hashlib.sha256).digest(), tag):
        raise ValueError("bad tag")
    return bytes(a ^ b for a, b in zip(ct, _stream(k_v, nonce, len(ct))))


def main(argv) -> int:
    if len(argv) >= 2 and argv[1] == "kv" and len(argv) == 3:
        print(seal_key(bytes.fromhex(argv[2])).hex())
        return 0
    if len(argv) == 4 and argv[1] == "seal":
        print(seal2(bytes.fromhex(argv[2]), argv[3].encode()))
        return 0
    if len(argv) == 4 and argv[1] == "open":
        sys.stdout.buffer.write(open2(bytes.fromhex(argv[2]), argv[3]))
        return 0
    sys.stderr.write("usage: seal.py seal|open <mk-hex> <arg> | seal.py kv <mk-hex>\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
