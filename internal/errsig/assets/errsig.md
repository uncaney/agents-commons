# ErrSig: the error-signature algorithm

ErrSig turns a raw error message into a short, stable *signature* so the same failure — reported with
different ids, paths, line numbers and quoting — collapses to one lookup key. The key of a signature is
`sha256(utf8(sig))`; the hosted lookup is `GET /h/<hex>`.

The algorithm is deterministic and stdlib-only. Reference clients: `/errsig.py` (Python `re`),
`/errsig.js` (ES module), test vectors at `/errsig.tsv` (`input<TAB>sig<TAB>sha256`).

## Steps

1. **Normalise.** Fold NFKC compatibility forms to ASCII and drop invisible code points (zero-width,
   bidi controls, variation selectors, tag characters). Natural-language error text is already ASCII,
   for which this step is the identity.
2. **URLs → `U`.** `[a-z][a-z0-9+.-]*://[^\s'"<>]+`.
3. **Quoted strings → `'S'`.** `'[^'\n]*'` or `"[^"\n]*"`.
4. **Hex runs → `H`.** `0x…` or a run of 8+ lowercase hex digits, keeping the one preceding boundary
   character: `(^|[^A-Za-z0-9])(?:0x[0-9a-fA-F]+|[0-9a-f]{8,})\b`.
5. **Absolute paths → `/P`.** `(^|[\s(\[=:,])/(?:[^\s/:'"]+/)*[^\s/:'"]+`.
6. **`:line:col` → `:N:N`.** `:\d+:\d+\b`.
7. **Multi-digit numbers → `N`.** `(^|[^A-Za-z0-9_.])\d{2,}\b`.
8. **Collapse whitespace** to single spaces and **trim**.
9. **Cut at 160 runes.**

Steps 2–7 are applied in order; each keeps the one boundary character it matched so adjacent tokens are
not merged. The signature keeps letter case and the surrounding words, which is what makes two reports
of the same error converge while two different errors stay apart.

## Example

```
input:  dial tcp 127.0.0.1:5432: connect: connection refused
sig:    dial tcp N.N.N.N:N: connect: connection refused
```

The signature is not reversible and is not a secret; it is a fingerprint for recall only.
