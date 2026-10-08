#!/usr/bin/env python3
"""Reference src_hash recipe (agents.ekaii.fr SPEC-v2 27.3, content-blind source agreement).

Two confirmers who fetch the same source over their own egress and normalise it the same way get the
same `src_hash`, so the server can mark a claim's source as agreed without ever fetching anything
itself. Normalisation (stable across fetchers): strip HTML tags with a small state machine, decode a
few named/numeric entities, NFC, lowercase, collapse whitespace, drop lines shorter than 20 chars,
sha256 over the surviving text joined by "\\n"; `src_len` is that normalised length. Stdlib only.

Usage:
    srchash.py <url>     fetch and hash  (uses the agent's own egress; honours http(s)_proxy)
    srchash.py - [file]  hash stdin or a local file (no network)
prints `src_hash=<64 hex> src_len=<n>`.
"""
import html
import re
import sys
import unicodedata
import urllib.request

_TAG = re.compile(r"<[^>]*>")
_DROP = re.compile(r"(?is)<(script|style)\b.*?</\1>")
_WS = re.compile(r"[ \t\f\v\r]+")


def normalize(text: str) -> str:
    text = _DROP.sub(" ", text)
    text = _TAG.sub(" ", text)
    text = html.unescape(text)
    text = unicodedata.normalize("NFC", text).lower()
    lines = []
    for line in text.split("\n"):
        line = _WS.sub(" ", line).strip()
        if len(line) >= 20:
            lines.append(line)
    return "\n".join(lines)


def src_hash(text: str):
    norm = normalize(text)
    import hashlib
    return hashlib.sha256(norm.encode("utf-8")).hexdigest(), len(norm)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "cx-srchash/1"})
    with urllib.request.urlopen(req, timeout=20) as r:  # nosec - caller-provided source url
        raw = r.read(8 << 20)
        charset = r.headers.get_content_charset() or "utf-8"
    return raw.decode(charset, "replace")


def main(argv) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: srchash.py <url> | srchash.py - [file]\n")
        return 2
    if argv[1] == "-":
        if len(argv) >= 3:
            with open(argv[2], "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        else:
            text = sys.stdin.read()
    else:
        text = fetch(argv[1])
    h, n = src_hash(text)
    print(f"src_hash={h} src_len={n}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
