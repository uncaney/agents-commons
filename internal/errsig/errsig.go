// Package errsig serves the ErrSig hash-lookup surface (SPEC-v2 27.1): GET /h/<sha256(ErrSig)>
// resolves an error signature to the entries and aliases that carry it, the ErrSig algorithm is
// published as a numbered spec with reference clients and test vectors, and a janitor backfills the
// kb.sig/sig_h pair for rows left NULL. The signature algorithm itself lives in internal/kb.ErrSig.
package errsig

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/know"
)

//go:embed vectors.txt
var vectorsTxt string

//go:embed assets/errsig.md
var specMD string

//go:embed assets/errsig.py
var errsigPy string

//go:embed assets/errsig.js
var errsigJS string

// assetMod is the Last-Modified of the embedded spec and clients (bumped when they change).
var assetMod = time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Hit is one resolved entry: title match or alias match (the alias text shows as a marker).
type Hit struct {
	ID, Kind, Title, Aka string
	OkW                  float64
	Fix                  string
}

// HashLookup returns the visible entries whose title ErrSig, or one of whose live alias ErrSigs,
// hashes to h (32 bytes), best first (ok_w then recency), at most 10.
func HashLookup(ctx context.Context, q core.Q, h []byte) ([]Hit, error) {
	rows, err := q.Query(ctx, `
		SELECT k.id, k.kind, k.title, k.ok_w, k.fix, COALESCE(k.sig_h = $1, false) AS by_title,
		       (SELECT a.text FROM kb_aka a WHERE a.kb_id = k.id AND a.sig_h = $1 AND NOT a.quarantine ORDER BY a.created LIMIT 1) AS aka
		FROM kb k
		WHERE NOT k.hidden AND NOT k.quarantine AND k.expires_at > now() AND k.superseded_by = ''
		  AND (k.sig_h = $1 OR EXISTS (SELECT 1 FROM kb_aka a WHERE a.kb_id = k.id AND a.sig_h = $1 AND NOT a.quarantine))
		ORDER BY k.ok_w DESC, k.created DESC
		LIMIT 10`, h)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Hit
	for rows.Next() {
		var hit Hit
		var byTitle bool
		var aka *string
		if err := rows.Scan(&hit.ID, &hit.Kind, &hit.Title, &hit.OkW, &hit.Fix, &byTitle, &aka); err != nil {
			return nil, err
		}
		if !byTitle && aka != nil {
			hit.Aka = *aka
		}
		out = append(out, hit)
	}
	return out, rows.Err()
}

type handlers struct{ d *core.Deps }

// hashParam reads and validates the 64-lowercase-hex path value, stripping a format suffix.
func hashParam(r *http.Request) (string, doc.Format, []byte, error) {
	seg, f := doc.SplitSuffix(r.PathValue("hex"))
	if !hexRe.MatchString(seg) {
		return seg, f, nil, core.Bad("hash must be 64 lowercase hex")
	}
	b, err := hex.DecodeString(seg)
	return seg, f, b, err
}

// h is GET /h/{hex} (+ .md, HEAD): the /e/-shaped reply over the ErrSig hash of entries and akas.
func (h *handlers) h(w http.ResponseWriter, r *http.Request) {
	hx, f, raw, err := hashParam(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	ctx := r.Context()
	hits, err := HashLookup(ctx, h.d.DB, raw)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Robots-Tag", "noindex")
	if len(hits) == 0 {
		_, _, super := core.ClientFrom(ctx)
		know.RecordMiss(ctx, h.d.DB, "h", hx, super, rootOf(h.d, r))
		d := doc.Error("notfound", "no entry for hash "+hx[:12], doc.POST("/v1/kb", "title=<error text>"), doc.GET("/errsig", "the algorithm"), doc.GET("/wanted", ""))
		d.Fields = []doc.F{{Name: "h", Val: hx[:12]}, {Name: "wanted", Val: "error text unknown"}}
		d.Title, d.NoIndex, d.MaxAge = "hash "+hx[:12], true, 300
		doc.ReplyAs(w, r, 404, d, f)
		return
	}
	d := &doc.Doc{
		Head:  fmt.Sprintf("h: %s hits=%d", hx[:12], len(hits)),
		Cols:  []string{"id", "score", "kind", "title"},
		Title: "hash " + hx[:12], NoIndex: true, MaxAge: 300, Budget: 400,
		Desc: "Entries whose error signature hashes to this key.",
	}
	for _, hit := range hits {
		title := hit.Title
		if hit.Aka != "" {
			title += " (aka: " + cutRunes(hit.Aka, 40) + ")"
		}
		d.Rows = append(d.Rows, []string{hit.ID, "1.00", hit.Kind, title})
	}
	top := hits[0]
	d.Fields = []doc.F{{Name: "h", Val: hx[:12]}, {Name: "top", Val: top.ID + " " + top.Title}}
	if fix := cutRunes(doc.CleanMulti(top.Fix), 1500); fix != "" {
		d.Fields = append(d.Fields, doc.F{Name: "fix", Val: fix, Multi: true})
	}
	d.Next = []doc.Action{doc.GET("/k/"+top.ID, ""), doc.GET("/h/"+hx+".md", "")}
	doc.ReplyAs(w, r, 200, d, f)
}

// spec is GET /errsig (+ /errsig.md): the numbered algorithm with reference clients.
func (h *handlers) spec(w http.ResponseWriter, r *http.Request) {
	doc.ServeStatic(w, r, assetMod, []byte(specMD), "text/markdown; charset=utf-8")
}

// tsv is GET /errsig.tsv: `input<TAB>sig<TAB>sha256` for each embedded vector, generated from
// kb.ErrSig so a client can check its own implementation against the server's.
func (h *handlers) tsv(w http.ResponseWriter, r *http.Request) {
	doc.ServeStatic(w, r, assetMod, []byte(VectorsTSV()), "text/tab-separated-values; charset=utf-8")
}

func (h *handlers) py(w http.ResponseWriter, r *http.Request) {
	doc.ServeStatic(w, r, assetMod, []byte(errsigPy), "text/x-python; charset=utf-8")
}

func (h *handlers) js(w http.ResponseWriter, r *http.Request) {
	doc.ServeStatic(w, r, assetMod, []byte(errsigJS), "text/javascript; charset=utf-8")
}

// rootOf resolves the caller's root for the miss record (informational), "" when anonymous.
func rootOf(d *core.Deps, r *http.Request) string {
	id, err := d.AuthOpt(r)
	if err != nil || id == nil {
		return ""
	}
	return id.Root
}

// --- MCP + registration ------------------------------------------------------------------------

// Help is the op list for help{t:kb} (hash lookup).
const Help = `h{hash} resolve a 64-hex sha256(ErrSig(error)) to the entries and aliases that carry it (empty -> records demand). The ErrSig algorithm and clients are at /errsig, /errsig.py, /errsig.js, /errsig.tsv.`

// OpMeta describes the ops of Ops for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"h": {Scope: "kb:r", Cost: 1},
}

var openAPI = json.RawMessage(`{"paths":{
"/h/{hex}":{"get":{"operationId":"h","summary":"Resolve a 64-hex sha256(ErrSig(error text)) to the entries and aliases that carry it (noindex). Compute the hash with /errsig.py or /errsig.js","parameters":[{"name":"hex","in":"path","required":true,"schema":{"type":"string","pattern":"^[0-9a-f]{64}$"}}],"responses":{"200":{"description":"h: <hex12> hits=N, hit lines, top fix, next:"},"400":{"description":"err bad hash"},"404":{"description":"err notfound (demand recorded)"}}}},
"/errsig":{"get":{"summary":"The ErrSig error-signature algorithm (numbered spec)","responses":{"200":{"description":"markdown"}}}},
"/errsig.tsv":{"get":{"summary":"50 ErrSig test vectors: input, sig, sha256","responses":{"200":{"description":"tab-separated values"}}}},
"/errsig.py":{"get":{"summary":"Reference ErrSig implementation (Python stdlib)","responses":{"200":{"description":"python source"}}}},
"/errsig.js":{"get":{"summary":"Reference ErrSig implementation (ES module)","responses":{"200":{"description":"javascript source"}}}}
}}`)

// Register mounts the hash-lookup routes, the spec and clients, wires the kb.FilledHook seam so a
// new entry or alias deletes the wanted(kind h) row it fills, and adds the sig/sig_h backfill
// janitor. cmd/gateway wires Ops into the MCP registry.
func Register(mux *http.ServeMux, d *core.Deps) {
	h := &handlers{d}
	mux.HandleFunc("GET /h/{hex}", h.h)
	mux.HandleFunc("GET /errsig", h.spec)
	mux.HandleFunc("GET /errsig.md", h.spec)
	mux.HandleFunc("GET /errsig.tsv", h.tsv)
	mux.HandleFunc("GET /errsig.py", h.py)
	mux.HandleFunc("GET /errsig.js", h.js)
	d.RegisterScope("GET /h/{hex}", "kb:r")
	d.RegisterScope("GET /errsig", "kb:r")
	d.RegisterScope("GET /errsig.tsv", "kb:r")
	d.RegisterScope("GET /errsig.py", "kb:r")
	d.RegisterScope("GET /errsig.js", "kb:r")
	d.RegisterOpenAPI(openAPI)
	if kb.FilledHook == nil {
		kb.FilledHook = know.FillWantedHash
	}
	d.Janitor.Add("kb_sig_backfill", func(ctx context.Context) error { return Backfill(ctx, d.DB) })
}

// Ops returns the MCP operations owned by this package: h (hash lookup).
func Ops(d *core.Deps) map[string]func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	return map[string]func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error){
		"h": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct{ Hash string }
			if len(a) > 0 {
				if err := json.Unmarshal(a, &in); err != nil {
					return "", core.Bad("a: " + err.Error())
				}
			}
			if !hexRe.MatchString(in.Hash) {
				return "", core.Bad("hash must be 64 lowercase hex")
			}
			raw, _ := hex.DecodeString(in.Hash)
			hits, err := HashLookup(ctx, d.DB, raw)
			if err != nil {
				return "", err
			}
			if len(hits) == 0 {
				_, _, super := core.ClientFrom(ctx)
				know.RecordMiss(ctx, d.DB, "h", in.Hash, super, "")
				return "", core.E(404, "notfound", "no entry for hash "+in.Hash[:12])
			}
			var b []byte
			b = append(b, fmt.Sprintf("h: %s hits=%d\n", in.Hash[:12], len(hits))...)
			for _, hit := range hits {
				title := hit.Title
				if hit.Aka != "" {
					title += " (aka: " + cutRunes(hit.Aka, 40) + ")"
				}
				b = append(b, fmt.Sprintf("%s 1.00 %s %s\n", hit.ID, hit.Kind, doc.SafeLine(title))...)
			}
			return string(b), nil
		},
	}
}

// Backfill fills kb.sig (and thus the generated sig_h) for visible rows left NULL, in batches, so
// the hash lookup and the FilledHook find older and bulk-imported entries (janitor kb_sig_backfill).
func Backfill(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `SELECT id, title FROM kb WHERE sig IS NULL AND title <> '' ORDER BY created DESC LIMIT 500`)
	if err != nil {
		return err
	}
	type row struct{ id, title string }
	var batch []row
	for rows.Next() {
		var rr row
		if err := rows.Scan(&rr.id, &rr.title); err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, rr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, rr := range batch {
		if _, err := q.Exec(ctx, `UPDATE kb SET sig = $2 WHERE id = $1 AND sig IS NULL`, rr.id, kb.ErrSig(rr.title)); err != nil {
			return err
		}
	}
	return nil
}

// cutRunes truncates s to n runes (adding an ellipsis when it had to cut).
func cutRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// --- vectors -----------------------------------------------------------------------------------

// Vector is one ErrSig test vector.
type Vector struct {
	Input, Sig, SHA256 string
}

// Vectors returns the embedded inputs paired with their server-computed signature and hash. The
// signatures are generated from kb.ErrSig, never hand-written, so the spec and the code never drift.
func Vectors() []Vector {
	var out []Vector
	for _, line := range splitLines(vectorsTxt) {
		if line == "" {
			continue
		}
		sig := kb.ErrSig(line)
		sum := sha256.Sum256([]byte(sig))
		out = append(out, Vector{Input: line, Sig: sig, SHA256: hex.EncodeToString(sum[:])})
	}
	return out
}

// VectorsTSV renders Vectors() as `input<TAB>sig<TAB>sha256` lines.
func VectorsTSV() string {
	var b []byte
	for _, v := range Vectors() {
		b = append(b, (v.Input + "\t" + v.Sig + "\t" + v.SHA256 + "\n")...)
	}
	return string(b)
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
