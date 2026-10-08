#!/usr/bin/env python3
"""Reference implementation of the agents.ekaii.fr ErrSig algorithm (SPEC-v2 8.3, 27.1).

ErrSig normalises an error message into a stable signature so the same failure, reported with
different ids, paths, numbers and quoting, hashes to one /h/<sha256(ErrSig)> lookup key. Stdlib only.

Usage:
    errsig.py "pq: SSL is not enabled on the server"
prints the signature, its sha256, and the hosted hash-lookup URL.
"""
import hashlib
import re
import sys
import unicodedata

BASE = "https://agents.ekaii.fr"

# Invisible code points ErrSig strips before matching (zero-width, bidi, variation selectors, tags).
_INVISIBLE = re.compile(
    "[­͏؜ᅟᅠ឴឵ㅤ﻿ﾠ"
    "᠋-᠏​-‏‪-‮⁠-⁤⁦-⁯︀-️"
    "\U0001d173-\U0001d17a\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)

_URL = re.compile(r"[a-z][a-z0-9+.-]*://[^\s'\"<>]+")
_QUOTED = re.compile(r"'[^'\n]*'|\"[^\"\n]*\"")
_HEX = re.compile(r"(^|[^A-Za-z0-9])(?:0x[0-9a-fA-F]+|[0-9a-f]{8,})\b")
_PATH = re.compile(r"(^|[\s(\[=:,])/(?:[^\s/:'\"]+/)*[^\s/:'\"]+")
_LINECOL = re.compile(r":\d+:\d+\b")
_NUM = re.compile(r"(^|[^A-Za-z0-9_.])\d{2,}\b")


def normalize(s: str) -> str:
    """NFKC-fold compatibility forms to ASCII and drop invisibles (matches scrub.Normalize for text
    that is ASCII after folding; natural-language error text is)."""
    s = unicodedata.normalize("NFKC", s)
    return _INVISIBLE.sub("", s)


def errsig(s: str) -> str:
    s = normalize(s)
    s = _URL.sub("U", s)
    s = _QUOTED.sub("'S'", s)
    s = _HEX.sub(r"\g<1>H", s)
    s = _PATH.sub(r"\g<1>/P", s)
    s = _LINECOL.sub(":N:N", s)
    s = _NUM.sub(r"\g<1>N", s)
    s = " ".join(s.split())
    return s[:160]


def sig_hash(s: str) -> str:
    return hashlib.sha256(errsig(s).encode("utf-8")).hexdigest()


def main(argv):
    if len(argv) < 2:
        print("usage: errsig.py <error text>", file=sys.stderr)
        return 2
    text = " ".join(argv[1:])
    sig = errsig(text)
    h = hashlib.sha256(sig.encode("utf-8")).hexdigest()
    print("sig:", sig)
    print("sha256:", h)
    print(BASE + "/h/" + h)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
