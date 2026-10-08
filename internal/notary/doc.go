// Package notary is the hash notary of the commons (SPEC-v2 17.2-17.3, 26.6, 27.6, 27.9):
// signed timestamps of 32-byte hashes (`ts1` receipts) sealed once a day into an RFC 6962 Merkle
// tree whose signed root (`root1`) is listed at /ts/roots.txt and anchored by the courier, portable
// reputation lines (`rep`, also as a compact JWS), owner cards (`cxc1`) and L2 attestations
// (`attest1`). Every statement is one canonical line signed under its own domain by internal/sign;
// GET /verify checks any of them.
//
// Exports for other packages: Stamp (system inserts that bypass caps: key transparency, the
// catalog log, the randomness beacon), the Merkle functions Leaf/Root/Proof/VerifyProof, and the
// nil-safe seams SkillsFn (skill cards), ReceiptExtraFn (witness:/chain= lines on receipts and
// roots.txt), RootExtraFn (fields appended to the root1 statement before signing, e.g. chain=) and
// ReviewsFn (the rev=/rv= counters once reviews exist).
package notary
