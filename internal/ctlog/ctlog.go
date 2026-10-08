// Package ctlog is the catalog transparency log and Wayback witness (SPEC-v2 27.6, P108). A janitor
// stamps every service version that reaches `verified`, every pin and every distinct-donor
// attestation into the notary (internal/notary, system inserts that bypass caps), so the public
// Merkle log of /ts covers the catalog itself; it extends each sealed day with a hash chain
// (`chain = SHA256(prev_chain || root)`, genesis 32 zero bytes) carried in the signed `root1` line
// and readable at /ts/chain.txt, and it witnesses the day's roots and the export files on the
// Internet Archive through the courier kind `wayback`.
//
// Reads: GET /svc/{nameAtVer}/proof is the RFC 6962 inclusion proof of a version's `svc1` leaf;
// GET /ts/chain.txt is one `day chain root` line per sealed day; /svc/<name> pages gain a
// `logged: … day= idx=` (or `unlogged!`) line per version through catalog.PageExtraFn. The chain
// and witness ride the notary seams RootExtraFn / ReceiptExtraFn, and egress.ResultFn["wayback"]
// records the archive URLs into ts_days.witness_url and export_witness.
package ctlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/egress"
	"ekaii.fr/commons/internal/notary"
	"ekaii.fr/commons/internal/sign"
)

const (
	// unloggedAfter is the grace period before a verified version without a leaf is flagged (27.6).
	unloggedAfter = "48 hours"
	stampBatch    = 256 // leaves created per janitor tick per kind
	waybackDaily  = 10  // wayback jobs enqueued per day (27.6)
	maxNote       = notary.MaxNote
)

// svc1 and pin1 statement types are registered by internal/notary's init (it signs them on behalf
// of the log); this package only produces their leaf hashes.

// waybackTargets is the fixed set of public paths witnessed on the Internet Archive after each day
// seal (27.6). The order is stable; /ts/roots.txt carries the day it snapshots.
var waybackTargets = []struct{ path, kind, file string }{
	{"/ts/roots.txt", "ts", ""},
	{"/export/manifest.json", "export", "manifest.json"},
	{"/export/SHA256SUMS.sig", "export", "SHA256SUMS.sig"},
	{"/.well-known/cx-key", "export", "cx-key"},
	{"/.well-known/did.json", "export", "did.json"},
	{"/changelog", "export", "changelog"},
}

type svc struct{ d *core.Deps }

var pageOnce sync.Once

// Register sets the notary and catalog seams, mounts the proof and chain reads, wires the janitor
// and the wayback result handler, and registers scopes + the OpenAPI fragment. The MCP ops are
// returned by Ops for the integration package to merge.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d}
	// The chain rides the root1 line (signed) and the per-day receipt/roots.txt columns.
	notary.RootExtraFn = rootChain
	notary.ReceiptExtraFn = receiptExtra
	egress.ResultFn["wayback"] = WaybackResult
	pageOnce.Do(func() {
		catalog.PageExtraFn = append(catalog.PageExtraFn, pageLines)
	})
	mux.HandleFunc("GET /svc/{nameAtVer}/proof", s.hProof)
	mux.HandleFunc("GET /ts/chain.txt", s.hChain)
	d.RegisterScope("GET /svc/{nameAtVer}/proof", "*")
	d.RegisterScope("GET /ts/chain.txt", "*")
	d.RegisterOpenAPI(openAPI)
	d.Janitor.Add("ctlog", s.janitor)
}

// --- leaf hashes -------------------------------------------------------------------------------

// svcHash is the svc1 leaf: SHA256("svc1\0" || name || "@" || ver || "\0" || wasm) (27.6).
func svcHash(name string, ver int, wasm string) []byte {
	h := sha256.New()
	h.Write([]byte("svc1\x00"))
	h.Write([]byte(name))
	h.Write([]byte("@"))
	h.Write([]byte(strconv.Itoa(ver)))
	h.Write([]byte("\x00"))
	h.Write([]byte(wasm))
	return h.Sum(nil)
}

// pinHash is the pin1 leaf: SHA256("pin1\0" || module-hash) (27.6).
func pinHash(hash string) []byte {
	h := sha256.New()
	h.Write([]byte("pin1\x00"))
	h.Write([]byte(hash))
	return h.Sum(nil)
}

// attHash is the leaf of a distinct-donor attestation: SHA256 of the signed att1 line (27.6).
func attHash(attLine string) []byte {
	s := sha256.Sum256([]byte(attLine))
	return s[:]
}

// --- chain (SPEC-v2 27.6) ----------------------------------------------------------------------

// genesis is the 32-zero-byte seed of the day chain.
var genesis = make([]byte, sha256.Size)

// chainStep folds one root into the running chain: SHA256(prev || root).
func chainStep(prev, root []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(root)
	return h.Sum(nil)
}

// rootChain is notary.RootExtraFn: at seal time it folds every earlier day's root (all already
// sealed, SealPending runs oldest first) into prev_chain and appends `chain=<hex>` to the root1
// statement before it is signed.
func rootChain(ctx context.Context, q core.Q, day string, _ int, root []byte) []sign.KV {
	prev, err := foldBefore(ctx, q, day)
	if err != nil {
		return nil
	}
	return []sign.KV{{K: "chain", V: hex.EncodeToString(chainStep(prev, root))}}
}

// foldBefore returns the chain value of the last sealed day strictly before day (genesis when none).
func foldBefore(ctx context.Context, q core.Q, day string) ([]byte, error) {
	rows, err := q.Query(ctx, `SELECT root FROM ts_days WHERE day < $1 ORDER BY day`, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	running := genesis
	for rows.Next() {
		var r []byte
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		running = chainStep(running, r)
	}
	return running, rows.Err()
}

// receiptExtra is notary.ReceiptExtraFn: the witness URL and the day's chain, shown on /ts/<h>
// receipts and as extra columns on /ts/roots.txt.
func receiptExtra(ctx context.Context, q core.Q, day string) []string {
	var chain []byte
	var witness string
	if err := q.QueryRow(ctx, `SELECT chain, witness_url FROM ts_days WHERE day = $1`, day).Scan(&chain, &witness); err != nil {
		return nil
	}
	var out []string
	if witness != "" {
		out = append(out, "witness: "+witness)
	}
	if len(chain) == sha256.Size {
		out = append(out, "chain="+hex.EncodeToString(chain))
	}
	return out
}

// --- wayback result (egress.ResultFn["wayback"]) -----------------------------------------------

type waybackPayload struct {
	URL  string `json:"url"`
	Kind string `json:"kind"`
	Day  string `json:"day"`
	File string `json:"file"`
}

// WaybackResult records a courier `wayback` ack inside the ack's transaction: the archive URL goes
// to ts_days.witness_url for the day /ts/roots.txt snapshotted, or to export_witness for an export
// file. Both the payload and the result are courier-produced, so the witness URL is validated.
func WaybackResult(ctx context.Context, d *core.Deps, q core.Q, payload, result json.RawMessage) error {
	var p waybackPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil // malformed payload: nothing to record, do not block the ack
	}
	var res struct {
		Witness string `json:"witness"`
	}
	if len(result) > 0 {
		json.Unmarshal(result, &res)
	}
	if !validWitness(res.Witness) {
		return nil
	}
	switch {
	case p.Kind == "ts" && validDay(p.Day):
		_, err := q.Exec(ctx, `UPDATE ts_days SET witness_url = $1 WHERE day = $2`, res.Witness, p.Day)
		return err
	case p.Kind == "export" && validFile(p.File):
		_, err := q.Exec(ctx, `INSERT INTO export_witness (file, url, at) VALUES ($1, $2, now())
			ON CONFLICT (file) DO UPDATE SET url = EXCLUDED.url, at = now()`, p.File, res.Witness)
		return err
	}
	return nil
}
