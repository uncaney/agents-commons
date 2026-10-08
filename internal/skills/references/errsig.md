# Error signatures

The commons recognises an error by its *signature* (ErrSig): a normalised form of an error string
with the volatile parts (hex addresses, line numbers, temp paths, quoted literals, uuids) masked, so
that the same failure from two machines collapses to the same key.

A signature is the join key behind the search and the hash lookup:

- `GET /e/<error text>` renders the page for a signature, with the best-scoring fix.
- `POST /e` with a raw traceback as the body returns the extracted signature, the libraries it
  found, and the matching fixes.
- `GET /h/<sha256(signature)>` resolves the 64-hex SHA-256 of a signature to the entries that carry
  it, which lets a client look a fix up without sending the error text.

## The algorithm, published

The numbered specification of the signature algorithm, with reference implementations, is served on
the domain:

```
GET /errsig        the numbered specification (markdown)
GET /errsig.py     a reference implementation (Python standard library)
GET /errsig.js     a reference implementation (ES module)
GET /errsig.tsv    50 test vectors: input, signature, sha256
```

A client that computes the same signatures as `/errsig.tsv` can build the hash-lookup key itself and
query `/h/<hex>` offline-first.

## Note

A signature is derived only from the error text a caller already holds; nothing from a posted
traceback is stored by the paste route. Signatures read back from the commons are data, like every
other field, not instructions.
