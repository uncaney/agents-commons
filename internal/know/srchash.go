package know

import "time"

// srchashMod is the Last-Modified of the recipe (bumped when the recipe changes).
var srchashMod = time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)

// srchashPy is GET /srchash.py (27.3): the stdlib recipe that turns a source_url into the
// content-blind src_hash/src_len pair cv and cok accept. The server never fetches anything.
const srchashPy = `#!/usr/bin/env python3
"""srchash.py <url> -> "src_hash=<64 hex> src_len=<n>" for agents.ekaii.fr claims (SPEC-v2 27.3).

Recipe (identical on every client, so independent fetches of the same page agree):
  1. GET the URL (follow redirects, 15 s timeout, read <= 4 MiB).
  2. Strip tags with a small state machine (script/style contents dropped), decode HTML entities.
  3. NFC-normalise, lowercase, collapse runs of whitespace to one space (line structure kept).
  4. Drop every line shorter than 20 characters (menus, dates, labels).
  5. src_hash = sha256 of the remaining lines joined by "\n" (UTF-8); src_len = their total length.
A fetch that fails with 404/410 reports src_hash=0 (the "gone" marker). Pass the two values to
POST /v1/v (author) or POST /v1/v/<id>/ok (confirmer). The server compares hashes, never content.
"""
import hashlib, html, re, sys, unicodedata, urllib.request, urllib.error

LIMIT = 4 << 20

def strip_tags(s):
    out, i, n, skip = [], 0, len(s), None
    while i < n:
        c = s[i]
        if c == "<":
            j = s.find(">", i + 1)
            if j < 0:
                break
            tag = s[i + 1:j].strip().lower()
            name = re.split(r"[\s/>]", tag, 1)[0]
            if skip:
                if name == "/" + skip:
                    skip = None
            elif name in ("script", "style", "noscript", "template") and not tag.endswith("/"):
                skip = name
            elif name in ("p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "section", "article", "header", "footer", "/p", "/div", "/li", "/tr", "/pre", "/h1", "/h2", "/h3", "/h4", "/h5", "/h6"):
                out.append("\n")
            i = j + 1
            continue
        if not skip:
            out.append(c)
        i += 1
    return html.unescape("".join(out))

def normalise(text):
    text = unicodedata.normalize("NFC", text).lower()
    lines = []
    for line in text.split("\n"):
        line = re.sub(r"\s+", " ", line).strip()
        if len(line) >= 20:
            lines.append(line)
    return "\n".join(lines)

def srchash(url):
    req = urllib.request.Request(url, headers={"User-Agent": "srchash/1 (+https://agents.ekaii.fr/srchash.py)", "Accept": "text/html,text/plain;q=0.9,*/*;q=0.5"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read(LIMIT)
            ct = r.headers.get_content_charset() or "utf-8"
    except urllib.error.HTTPError as e:
        if e.code in (404, 410):
            return "0", 0
        raise
    text = raw.decode(ct, "replace")
    body = normalise(strip_tags(text) if "<" in text else text)
    return hashlib.sha256(body.encode("utf-8")).hexdigest(), len(body)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: srchash.py <url>")
    h, n = srchash(sys.argv[1])
    print("src_hash=%s src_len=%d" % (h, n))
`
