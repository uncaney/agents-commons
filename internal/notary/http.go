package notary

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/sign"
)

type handlers struct{ s *svc }

// Register derives the signer, mounts POST /v1/ts, GET /ts/{h}, GET /ts/roots.txt, GET /ts (+
// twins), GET /v1/rep/{root}, GET /v1/card and POST /v1/attest, and registers scopes, costs, the
// OpenAPI fragment, the llms-full section, the storage class, the janitor tasks (daily seal,
// 1-year row retention), the purge hook and the export-me writer.
func Register(mux *http.ServeMux, d *core.Deps) {
	signerP.Store(sign.MustNew(d.Cfg))
	s := newSvc(d)
	h := &handlers{s}
	mux.HandleFunc("POST /v1/ts", h.post)
	mux.HandleFunc("GET "+rootsPath, h.roots)
	mux.HandleFunc("GET /ts/{h}", h.get)
	mux.HandleFunc("GET "+tsPath, h.page)
	for _, ext := range []string{".txt", ".md", ".json", ".html", ".sh", ".jsonld"} {
		mux.HandleFunc("GET "+tsPath+ext, h.page) // wildcards cannot glue to literals: one route per twin
	}
	mux.HandleFunc("GET /v1/rep/{root}", h.rep)
	mux.HandleFunc("GET /v1/card", h.card)
	mux.HandleFunc("POST /v1/attest", h.attest)
	d.RegisterScope("POST /v1/ts", "kb:w")
	d.RegisterScope("GET /v1/card", "me:r")
	d.RegisterScope("POST /v1/attest", "sub")
	d.RegisterCost("GET "+rootsPath, 1)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("notary", func(context.Context) string { return llmsText })
	d.StorageClass("ts", 256<<20, `SELECT pg_total_relation_size('ts') + pg_total_relation_size('ts_days')`)
	d.Janitor.Add("notary_seal", func(ctx context.Context) error { _, err := SealPending(ctx, d); return err })
	d.Janitor.Add("notary_retention", func(ctx context.Context) error {
		_, err := d.DB.Exec(ctx, `DELETE FROM ts WHERE t < now() - $1::interval`, RowsKeep)
		return err
	})
	// Leaves stay (every other proof of the day hashes over them); the owner and note go.
	d.OnPurge(func(ctx context.Context, root string) error {
		_, err := d.DB.Exec(ctx, `UPDATE ts SET owner = '', note = '' WHERE owner = $1`, root)
		return err
	})
	d.OnExport("ts", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// input is the POST /v1/ts body (JSON) or query parameters.
type input struct {
	H    string `json:"h"`
	Note string `json:"note"`
	PoW  string `json:"pow,omitempty"` // MCP only: "<challenge>:<nonce>"
}

// post implements POST /v1/ts: token or anonymous X-PoW; the reply is the two wire lines.
func (h *handlers) post(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	d := h.s.d
	if !d.CheckFrozen(w, r, "write") {
		return
	}
	var in input
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if in.H == "" {
		in.H, in.Note = r.URL.Query().Get("h"), r.URL.Query().Get("note")
	}
	if in.PoW != "" {
		doc.Fail(w, r, core.Bad("pow is an MCP argument; send the X-PoW header over HTTP"))
		return
	}
	hash, err := ParseHash(in.H)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	id, err := d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if id != nil && id.Banned {
		doc.Fail(w, r, core.ErrBanned)
		return
	}
	if id == nil && r.Header.Get("X-PoW") == "" {
		d.PoWAuthenticate(w, r)
		doc.Fail(w, r, core.ErrAuth, doc.POST("/v1/challenge?for=w", ""), doc.POST("/v1/ts", "+X-PoW"), doc.GET(tsPath, ""))
		return
	}
	ctx := r.Context()
	var rc *Receipt
	var fresh bool
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		grp := d.IPGroup(r)
		if id == nil {
			g, _, err := xpow(ctx, d, tx, r)
			if err != nil {
				return err
			}
			if g != "" {
				grp = g
			}
		}
		var err error
		rc, fresh, err = write(ctx, tx, id, grp, hash, in.Note)
		return err
	})
	if err != nil {
		doc.Fail(w, r, err, doc.GET(tsPath, ""), doc.GET("/help", ""))
		return
	}
	doc.RawActions(w, r, doc.GET("/ts/"+hex.EncodeToString(hash), "receipt"), doc.GET(tsPath, ""))
	core.OK(w, r, rc.Line()+"\n"+rc.Sig(), stampJSON(rc, fresh))
}

// xpow verifies the anonymous X-PoW through the core seam (fails closed until auth installs it).
func xpow(ctx context.Context, d *core.Deps, q core.Q, r *http.Request) (grp, super string, err error) {
	if core.XPoWFn == nil {
		return "", "", core.E(400, "pow", "X-PoW required")
	}
	return core.XPoWFn(ctx, q, r)
}

// get implements GET /ts/{h}(.json|.txt): the first-seen receipt plus root, index and proof.
func (h *handlers) get(w http.ResponseWriter, r *http.Request) {
	seg, f := doc.SplitSuffix(r.PathValue("h"))
	hash, err := ParseHash(seg)
	if err != nil {
		doc.Fail(w, r, err, doc.GET(tsPath, ""), doc.GET("/help", ""))
		return
	}
	rc, err := h.s.receipt(r.Context(), h.s.d.DB, hash)
	if errors.Is(err, core.ErrNotFound) {
		doc.Err(w, r, 404, "notfound", "no timestamp for this hash", doc.POST("/v1/ts", "timestamp it"), doc.GET(tsPath, ""))
		return
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if f == "" {
		f = doc.Negotiate(r)
	}
	mod := rc.T
	if rc.IsSealed() {
		mod = rc.Sealed
	}
	doc.RawActions(w, r, doc.GET(rootsPath, "roots"), doc.GET(tsPath, ""))
	if f == doc.JSON {
		doc.ServeStatic(w, r, mod, jsonBody(rc.JSON()), "application/json")
		return
	}
	doc.ServeStatic(w, r, mod, []byte(rc.Text()), "text/plain; charset=utf-8")
}

// roots implements GET /ts/roots.txt: every signed daily root, one line per day, oldest first.
func (h *handlers) roots(w http.ResponseWriter, r *http.Request) {
	body, mod, err := h.s.cachedRoots(r.Context())
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.ServeStatic(w, r, mod, body, "text/plain; charset=utf-8")
}

// cachedRoots renders roots.txt at most once per rootsTTL per instance.
func (s *svc) cachedRoots(ctx context.Context) ([]byte, time.Time, error) {
	if b, ok := s.leaves.Get("roots"); ok && len(b) >= 8 {
		var mod time.Time
		if err := mod.UnmarshalBinary(b[1 : 1+int(b[0])]); err == nil {
			return b[1+int(b[0]):], mod, nil
		}
	}
	body, mod, err := s.rootsText(ctx, s.d.DB)
	if err != nil {
		return nil, time.Time{}, err
	}
	if mb, err := mod.MarshalBinary(); err == nil && len(mb) < 256 {
		packed := append([]byte{byte(len(mb))}, mb...)
		s.leaves.Put("roots", append(packed, body...), rootsTTL)
	}
	return body, mod, nil
}

// rep implements GET /v1/rep/{root}(.json) and ?f=jws (anonymous).
func (h *handlers) rep(w http.ResponseWriter, r *http.Request) {
	seg, f := doc.SplitSuffix(r.PathValue("root"))
	p, err := loadRep(r.Context(), h.s.d.DB, seg)
	if errors.Is(err, core.ErrNotFound) {
		doc.Err(w, r, 404, "notfound", "unknown root", doc.GET("/v1/rep/<root>", ""), doc.GET("/help", ""))
		return
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.RawActions(w, r, doc.GET("/a/"+p.Root, "profile"), doc.GET("/v1/rep/"+p.Root+"?f=jws", "jws"))
	if strings.EqualFold(r.URL.Query().Get("f"), "jws") {
		doc.ServeStatic(w, r, time.Time{}, []byte(p.JWS()+"\n"), "application/jose")
		return
	}
	if f == "" {
		f = doc.Negotiate(r)
	}
	if f == doc.JSON {
		doc.ServeStatic(w, r, time.Time{}, jsonBody(p.JSON()), "application/json")
		return
	}
	doc.ServeStatic(w, r, time.Time{}, []byte(p.Line()+"\n"+p.Sig()+"\n"), "text/plain; charset=utf-8")
}

// card implements GET /v1/card (owner): the signed cxc1 card of the caller's root.
func (h *handlers) card(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := h.s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	c, err := loadCard(r.Context(), h.s.d.DB, id)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.RawActions(w, r, doc.GET("/v1/rep/"+c.Root, "public rep"), doc.GET("/v1/me", ""))
	core.OK(w, r, c.Line()+"\n"+c.Sig(), c.JSON())
}

// attest implements POST /v1/attest {"text"} (L2 only).
func (h *handlers) attest(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	d := h.s.d
	id, err := d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		Text string `json:"text"`
	}
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if in.Text == "" {
		in.Text = r.URL.Query().Get("text")
	}
	var a *Attestation
	err = core.Tx(r.Context(), d.DB, func(tx pgx.Tx) error {
		var err error
		a, err = attest(r.Context(), tx, id, in.Text)
		return err
	})
	if err != nil {
		doc.Fail(w, r, err, doc.GET("/v1/me", ""), doc.GET(tsPath, ""))
		return
	}
	doc.RawActions(w, r, doc.GET("/v1/rep/"+a.Root, "public rep"), doc.GET("/verify", "verify"))
	core.OK(w, r, a.Line()+"\n"+a.Sig(), a.JSON())
}

func jsonBody(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(fmt.Sprintf(`{"err":"internal","msg":%q}`, err.Error()))
	}
	return append(b, '\n')
}
