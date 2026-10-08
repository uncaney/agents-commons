package ctlog

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/notary"
)

// --- GET /svc/{nameAtVer}/proof ----------------------------------------------------------------

// hProof serves the RFC 6962 inclusion proof of a version's svc1 leaf (27.6). The line carries
// everything a reader needs to recompute the leaf (h, t, n), walk the proof (idx, size) and match
// the day root at /ts/roots.txt, plus the day's chain value.
func (s *svc) hProof(w http.ResponseWriter, r *http.Request) {
	text, j, err := s.proof(r.Context(), r.PathValue("nameAtVer"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	core.Text(w, r, http.StatusOK, text, j)
}

func (s *svc) proof(ctx context.Context, nameAtVer string) (string, map[string]any, error) {
	nameAtVer = strings.TrimSuffix(nameAtVer, ".txt")
	v, err := catalog.Resolve(ctx, s.d.DB, nameAtVer)
	if err != nil {
		return "", nil, err
	}
	h := svcHash(v.Name, v.Ver, v.Wasm)
	var seq int64
	var t time.Time
	var day time.Time
	var root []byte
	err = s.d.DB.QueryRow(ctx, `SELECT n, t, day, root FROM ts WHERE h = $1`, h).Scan(&seq, &t, &day, &root)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, core.E(404, "notfound", "service "+v.Name+"@"+strconv.Itoa(v.Ver)+" is not in the transparency log yet (unlogged)")
	}
	if err != nil {
		return "", nil, err
	}
	ds := day.UTC().Format("2006-01-02")
	base := []string{
		"svc1",
		"name=" + v.Name,
		"ver=" + strconv.Itoa(v.Ver),
		"wasm=" + v.Wasm,
		"h=" + hex.EncodeToString(h),
		"t=" + strconv.FormatInt(t.UTC().Unix(), 10),
		"n=" + strconv.FormatInt(seq, 10),
		"day=" + ds,
	}
	m := map[string]any{"name": v.Name, "ver": v.Ver, "wasm": v.Wasm, "h": hex.EncodeToString(h),
		"t": t.UTC().Unix(), "n": seq, "day": ds, "sealed": len(root) == notary.HashSize}
	if len(root) != notary.HashSize {
		line := strings.Join(base, " ") + " root=pending"
		return line, m, nil
	}
	leaves, idx, err := s.dayProof(ctx, ds, seq)
	if err != nil {
		return "", nil, err
	}
	if idx < 0 {
		// Sealed marker without rebuildable rows (retention): report as pending-shaped.
		return strings.Join(base, " ") + " root=pending", m, nil
	}
	proof := notary.Proof(leaves, idx)
	chain, err := s.dayChain(ctx, ds, root)
	if err != nil {
		return "", nil, err
	}
	line := strings.Join(append(base,
		"idx="+strconv.Itoa(idx),
		"size="+strconv.Itoa(len(leaves)),
		"root="+hex.EncodeToString(root),
		"proof="+notary.FormatProof(proof),
		"chain="+hex.EncodeToString(chain),
	), " ")
	hashes := make([]string, len(proof))
	for i, p := range proof {
		hashes[i] = hex.EncodeToString(p)
	}
	m["idx"], m["size"], m["root"] = idx, len(leaves), hex.EncodeToString(root)
	m["proof"], m["chain"] = hashes, hex.EncodeToString(chain)
	return line, m, nil
}

// dayProof rebuilds the day's RFC 6962 leaves (sequence order) and returns them with the index of
// the leaf whose timestamp sequence is seq (-1 when the rows no longer rebuild the sealed tree).
func (s *svc) dayProof(ctx context.Context, day string, seq int64) ([][]byte, int, error) {
	rows, err := s.d.DB.Query(ctx, `SELECT n, h, t FROM ts WHERE day = $1 ORDER BY n`, day)
	if err != nil {
		return nil, -1, err
	}
	defer rows.Close()
	var leaves [][]byte
	idx := -1
	for rows.Next() {
		var n int64
		var h []byte
		var t time.Time
		if err := rows.Scan(&n, &h, &t); err != nil {
			return nil, -1, err
		}
		if n == seq {
			idx = len(leaves)
		}
		leaves = append(leaves, notary.Leaf(h, t, n))
	}
	return leaves, idx, rows.Err()
}

// dayChain returns the stored chain of a day, computing it from the roots when not yet backfilled.
func (s *svc) dayChain(ctx context.Context, day string, root []byte) ([]byte, error) {
	var chain []byte
	err := s.d.DB.QueryRow(ctx, `SELECT chain FROM ts_days WHERE day = $1`, day).Scan(&chain)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if len(chain) == 32 {
		return chain, nil
	}
	prev, err := foldBefore(ctx, s.d.DB, day)
	if err != nil {
		return nil, err
	}
	return chainStep(prev, root), nil
}

// --- GET /ts/chain.txt -------------------------------------------------------------------------

// hChain serves one `day chain root` line per sealed day (27.6); the chain is folded on the fly so
// the file is complete even before the janitor backfills the column.
func (s *svc) hChain(w http.ResponseWriter, r *http.Request) {
	rows, err := s.d.DB.Query(r.Context(), `SELECT day, root FROM ts_days ORDER BY day`)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	defer rows.Close()
	var b strings.Builder
	running := genesis
	for rows.Next() {
		var dt time.Time
		var root []byte
		if err := rows.Scan(&dt, &root); err != nil {
			core.Fail(w, r, err)
			return
		}
		running = chainStep(running, root)
		b.WriteString(dt.UTC().Format("2006-01-02") + " " + hex.EncodeToString(running) + " " + hex.EncodeToString(root) + "\n")
	}
	if err := rows.Err(); err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write([]byte(b.String()))
}

// --- /svc/<name> page lines (catalog.PageExtraFn) ----------------------------------------------

// pageLines adds `logged: <name>@<ver> day=<d> idx=<n>` for each verified version in the log, or
// `unlogged!` once a version has been verified for 48 h without a leaf (27.6).
func pageLines(ctx context.Context, q core.Q, name string) []string {
	rows, err := q.Query(ctx, `SELECT ver, wasm, verified_at FROM service_versions
		WHERE name = $1 AND state = 'verified' ORDER BY ver`, name)
	if err != nil {
		return nil
	}
	defer rows.Close()
	type ver struct {
		wasm       string
		ver        int
		verifiedAt *time.Time
	}
	var vers []ver
	for rows.Next() {
		var v ver
		if err := rows.Scan(&v.ver, &v.wasm, &v.verifiedAt); err != nil {
			return nil
		}
		vers = append(vers, v)
	}
	if rows.Err() != nil {
		return nil
	}
	var out []string
	for _, v := range vers {
		var seq int64
		var day time.Time
		err := q.QueryRow(ctx, `SELECT n, day FROM ts WHERE h = $1`, svcHash(name, v.ver, v.wasm)).Scan(&seq, &day)
		switch {
		case err == nil:
			out = append(out, "logged: "+name+"@"+strconv.Itoa(v.ver)+" day="+day.UTC().Format("2006-01-02")+" idx="+strconv.FormatInt(seq, 10))
		case v.verifiedAt != nil && time.Since(*v.verifiedAt) > 48*time.Hour:
			out = append(out, "unlogged! "+name+"@"+strconv.Itoa(v.ver))
		}
	}
	return out
}

// --- validators (courier-produced values) ------------------------------------------------------

func validWitness(u string) bool {
	return len(u) <= 2048 && strings.HasPrefix(u, "https://web.archive.org/") && doc.OneLine(u)
}

func validDay(d string) bool {
	_, err := time.Parse("2006-01-02", d)
	return err == nil
}

func validFile(f string) bool {
	if f == "" || len(f) > 64 {
		return false
	}
	for _, r := range f {
		if !(r == '.' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// --- MCP ops -----------------------------------------------------------------------------------

// Op is an MCP operation (compact text, errors as *core.APIError).
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the ops for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{"svcproof": {Scope: "", Cost: 1}}

// Help is the help{t:ctlog} text (<= 200 tokens).
const Help = `ctlog (catalog transparency log; every verified service, pin and distinct-donor attestation is notarised into /ts):
svcproof{name} inclusion proof of a version's svc1 leaf -> "svc1 name= ver= wasm= h= t= n= idx= size= day= root= proof= chain=" (GET /svc/<name@ver>/proof). Verify it against the day root at GET /ts/roots.txt; the daily chain (SHA256(prev||root)) is at GET /ts/chain.txt. /svc/<name> pages show "logged: day= idx=" per version. Roots and exports are witnessed on web.archive.org.`

// Ops returns the MCP ops of this package (merged by the integration package).
func Ops(d *core.Deps) map[string]Op {
	s := &svc{d: d}
	return map[string]Op{
		"svcproof": func(ctx context.Context, _ *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				Name string `json:"name"`
			}
			if len(a) > 0 && string(a) != "null" {
				if err := json.Unmarshal(a, &in); err != nil {
					return "", core.Bad("a: " + err.Error())
				}
			}
			if in.Name == "" {
				return "", core.Bad("name required")
			}
			text, _, err := s.proof(ctx, in.Name)
			return text, err
		},
	}
}

var openAPI = json.RawMessage(`{"paths":{
"/svc/{nameAtVer}/proof":{"get":{"operationId":"svcproof","summary":"RFC 6962 inclusion proof of a service version's svc1 leaf in the catalog transparency log: svc1 name= ver= wasm= h= t= n= idx= size= day= root= proof= chain= (verify against GET /ts/roots.txt).","parameters":[{"name":"nameAtVer","in":"path","required":true,"schema":{"type":"string","description":"<name> or <name>@<ver>"}}],"responses":{"200":{"description":"proof line (text/plain) or JSON"},"404":{"description":"err notfound (unknown service or not logged yet)"}}}},
"/ts/chain.txt":{"get":{"operationId":"tsChain","summary":"The daily hash chain of the transparency log: one 'day chain root' line per sealed day, chain = SHA256(prev_chain || root).","responses":{"200":{"description":"text/plain"}}}}
}}`)
