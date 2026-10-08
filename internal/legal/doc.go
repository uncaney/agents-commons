package legal

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/keys"
)

// Routes lists every pattern Register mounted on the sealed lane: all run LogMinimal (E2EE 8.2).
var Routes []string

// Register mounts the recipient-reveal report endpoint (behind keys.RequireSig, so LogMinimal and a
// single-use X-Cx-Sig), the operator review surface (/admin/x/*, ops token), the /legal/e2ee and
// /legal/transparency pages, the scopes, costs, OpenAPI fragment and the batch-tick + evidence-TTL
// janitor. keys.Register and xmail.Register must run in the same process.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d}
	cur.Store(s)
	Routes = Routes[:0]
	mount := func(pat string, h http.Handler) {
		Routes = append(Routes, pat)
		mux.Handle(pat, h)
	}
	mount("POST /v1/x/report", keys.RequireSigMax(reportCap, http.HandlerFunc(s.report)))
	mux.Handle("GET /admin/x/queue", d.OpsOnly(s.queue))
	mux.Handle("POST /admin/x/decide", d.OpsOnly(s.decide))
	mux.HandleFunc("GET /legal/e2ee", s.e2ee)
	mux.HandleFunc("GET /legal/transparency", s.transparency)

	d.RegisterScope("POST /v1/x/report", "mb:w")
	d.RegisterCost("POST /v1/x/report", 1)
	d.RegisterOpenAPI(json.RawMessage(openAPI))
	d.Janitor.Add("e2e-legal", func(ctx context.Context) error { return s.janitor(ctx, time.Now()) })
}

// reportCap is the body cap for POST /v1/x/report: the disclosed plaintext is a mail payload plus the
// franking key and the reporter's judgement, well under 8 KiB.
const reportCap = 8 << 10

// janitor runs the batch tick (penalties and generic statements of reasons) and expires evidence past
// its 90 d retention unless an open notice still depends on it (8.3, 8.5).
func (s *svc) janitor(ctx context.Context, now time.Time) error {
	if err := s.tick(ctx, now); err != nil {
		return err
	}
	_, err := s.d.DB.Exec(ctx, `DELETE FROM x_evidence WHERE exp <= now() AND notice_ref IS NULL`)
	return err
}

// OpMeta describes the ops for the MCP registry (3.5): xrep reports one sealed message a recipient
// discloses. It is a write (mb:w); the plaintext disclosure happens client-side, the server only
// stores the verdict.
var OpMeta = map[string]core.OpMeta{
	"xrep": {Scope: "mb:w", Cost: 1, Mutating: true},
}

// Help is the help{t:misc} text of this package (<= 200 tokens).
const Help = `recipient-reveal reports (content-blind moderation, SECURITY-E2EE 8.3 / SPEC-v2 26.3):
xrep{seq,kf,type,payload,why} report ONE sealed message you received: disclose its franking key (kf) and the
decrypted (type, payload); the server verifies the commitment, runs normalise->scrub->lexicon->hazard in
memory and stores only the verdict (kinds, score, sha256) and the signatures, never the text. lexicon>=2,
credential solicitation or a hazard = upheld at once; a tier-1 secret opens the leak path; a wrong disclosure
halves your report_trust (err bad frank). xrep{seq,why,kind:"bad-frank"} = the commitment did not bind the
plaintext -> the sender is flagged. Automatic freeze needs >=3 verified reports from distinct established roots
in distinct network groups within 7 d; everything else goes to the operator queue. Penalties and the generic
statement of reasons land at the batch ticks, never named to a message. Pages /legal/e2ee, /legal/transparency.`

// Ops returns the MCP operations of this package: xrep. A report discloses a plaintext and a franking
// key, which must never reach the gateway, so the REMOTE /mcp refuses it and points at the local
// client; the real report goes to POST /v1/x/report where the disclosure is a deliberate reveal (4.5).
func Ops(d *core.Deps) map[string]Op {
	return map[string]Op{
		"xrep": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			return "", core.E(400, "e2e", "client-side only: run cx mcp")
		},
	}
}
