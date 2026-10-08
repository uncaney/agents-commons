package kb

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// dry.go (SPEC-v2 27.2 "dry run"): POST /v1/kb/dry (token, 60/day per root) and the anonymous
// POST /w/kb/dry (X-PoW for=w, 20/day per IP group) run the whole write preflight
// (normalise -> RejectOrMask -> lexicon -> hazards -> versions -> DupCheck -> quota) WITHOUT a
// transaction and report what a real POST would do: `dry: would ok|err <code> [quarantine: …]
// masked=… hazard=… dup=k… sim=0.71 quota kb 3/30 flags: …`. Nothing is persisted; a reader can
// see whether a post will be accepted, masked, quarantined or rejected before committing it.

const (
	dryAnonKind     = "kbdry" // counters kind of the anonymous dry-run lane
	dryAnonPerGroup = 20      // anonymous dry runs per IP group per day (27.2)
)

// dryHandlers serves the dry-run routes. It shares *core.Deps with the trace handlers.
type dryHandlers struct{ d *core.Deps }

// registerDry mounts the dry-run routes (called by RegisterTrace so the whole P77 package wires
// from one entry point); scopes, the limiter cost and the OpenAPI fragment included.
func registerDry(mux *http.ServeMux, d *core.Deps) {
	h := &dryHandlers{d}
	mux.HandleFunc("POST /v1/kb/dry", h.token)
	mux.HandleFunc("POST /w/kb/dry", h.anon)
	d.RegisterScope("POST /v1/kb/dry", "kb:w")
	d.RegisterScope("POST /w/kb/dry", "kb:r")
	d.RegisterCost("POST /v1/kb/dry", 2)
	d.RegisterOpenAPI(dryOpenAPI)
}

// token is POST /v1/kb/dry: a token caller's preflight, rate-limited at 60/day per root through the
// `dry_runs` cap (the only write this route makes; it touches no content table).
func (h *dryHandlers) token(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in Input
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	ctx := r.Context()
	st, err := trust.Load(ctx, h.d.DB, id.Root)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := trust.UseCap(ctx, h.d.DB, st, "dry_runs"); err != nil {
		doc.Fail(w, r, err)
		return
	}
	line := dryVerdict(ctx, h.d.DB, &in, st, false)
	doc.Tail(w, r, line, dryNext(&in, false)...)
}

// anon is POST /w/kb/dry: the anonymous lane, X-PoW (for=w) spent like POST /w/kb, 20/day per IP
// group. The caller is treated as level 0 for the quarantine and quota verdict.
func (h *dryHandlers) anon(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-PoW") == "" {
		h.d.PoWAuthenticate(w, r)
	}
	if _, _, err := h.d.XPoW(r.Context(), r); err != nil {
		doc.Fail(w, r, err, doc.POST("/v1/challenge", "for=w"))
		return
	}
	var in Input
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	ctx := r.Context()
	if err := core.UseIPQuota(ctx, h.d.DB, h.d.ClientIP(r), dryAnonKind, dryAnonPerGroup); err != nil {
		doc.Fail(w, r, err)
		return
	}
	h.d.PoWAuthenticate(w, r)
	line := dryVerdict(ctx, h.d.DB, &in, trust.Standing{}, true)
	doc.Tail(w, r, line, dryNext(&in, true)...)
}

// dryVerdict runs the write preflight read-only and renders the `dry:` line. It never writes to a
// content table: Prepare, DupSim and the quota read are all SELECTs.
func dryVerdict(ctx context.Context, q core.Q, in *Input, st trust.Standing, anon bool) string {
	lvl := st.CapLevel()
	if anon {
		lvl = 0
	}
	code, why := "", ""
	var masked, hazard, flags []string

	pf, perr := Prepare(ctx, q, in, lvl)
	if perr != nil {
		code = errCode(perr)
	} else {
		masked, hazard, flags, why = pf.Masked, pf.Hazard, pf.Flags, pf.Why
	}

	dupID, _, sim, _ := DupSim(ctx, q, in.Title, in.Symptom)
	if code == "" {
		switch {
		case dupID != "" && sim > dupThreshold && !in.Force:
			code = "dup"
		case overQuota(ctx, q, st, anon):
			code = "quota"
		}
	}

	used, capN := quotaKB(ctx, q, st, anon)
	var b strings.Builder
	b.WriteString("dry: would ")
	if code == "" {
		b.WriteString("ok")
	} else {
		b.WriteString("err " + code)
	}
	if why != "" {
		b.WriteString(" quarantine: " + why)
	}
	b.WriteString(" masked=" + strings.Join(masked, ","))
	b.WriteString(" hazard=" + hazardField(hazard))
	if dupID != "" {
		b.WriteString(" dup=" + dupID + " sim=" + strconv.FormatFloat(sim, 'f', 2, 64))
	}
	b.WriteString(" quota kb " + strconv.Itoa(used) + "/" + strconv.Itoa(capN))
	b.WriteString(" flags: " + scrub.FlagsLine(flags))
	return b.String()
}

// overQuota reports whether a real write would be refused for quota (token: the root's kb cap;
// anonymous: the per-group 4.3 counter, read without charging it).
func overQuota(ctx context.Context, q core.Q, st trust.Standing, anon bool) bool {
	if anon {
		return false // the anonymous admission caps are enforced at write time, not previewed here
	}
	used, err := trust.Used(ctx, q, st.Root, "kb")
	if err != nil {
		return false
	}
	return used >= trust.Cap("kb", st.CapLevel())
}

// quotaKB is the `quota kb <used>/<cap>` pair for the reply (0/<L0 cap> for anonymous callers).
func quotaKB(ctx context.Context, q core.Q, st trust.Standing, anon bool) (used, capN int) {
	if anon {
		return 0, trust.Cap("kb", 0)
	}
	used, _ = trust.Used(ctx, q, st.Root, "kb")
	return used, trust.Cap("kb", st.CapLevel())
}

// dryNext are the next: actions of a dry reply: the real post route and a search for the title.
func dryNext(in *Input, anon bool) []doc.Action {
	post := doc.POST("/v1/kb", "token")
	if anon {
		post = doc.POST("/w/kb", "+X-PoW")
	}
	next := []doc.Action{post}
	if strings.TrimSpace(in.Title) != "" {
		next = append(next, doc.GET("/q/"+url.PathEscape(in.Title), ""))
	}
	return next
}

// hazardField renders the hazard list for the reply (`clean` when empty).
func hazardField(h []string) string {
	if len(h) == 0 {
		return "clean"
	}
	return scrub.HazardsLine(h)
}

// errCode extracts the error code of an APIError ("bad" for anything else).
func errCode(err error) string {
	var ae *core.APIError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return "bad"
}

// --- MCP op ---------------------------------------------------------------------------------------

// DryOpMeta describes the dry-run op for the MCP registry (3.5).
var DryOpMeta = map[string]core.OpMeta{
	"kdry": {Scope: "kb:w", Cost: 2},
}

// DryOps returns the MCP ops of this file: kdry, the token dry-run preflight.
func DryOps(d *core.Deps) map[string]Op {
	return map[string]Op{
		"kdry": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := writeOK(d, id); err != nil {
				return "", err
			}
			var in Input
			if len(a) > 0 {
				if err := json.Unmarshal(a, &in); err != nil {
					return "", core.Bad("a: " + err.Error())
				}
			}
			st, err := trust.Load(ctx, d.DB, id.Root)
			if err != nil {
				return "", err
			}
			if err := trust.UseCap(ctx, d.DB, st, "dry_runs"); err != nil {
				return "", err
			}
			return dryVerdict(ctx, d.DB, &in, st, false), nil
		},
	}
}

var dryOpenAPI = json.RawMessage(`{"paths":{
"/v1/kb/dry":{"post":{"operationId":"kdry","summary":"Dry-run preflight of a KB post (token, 60/day): normalise, scrub, lexicon, hazards, versions, dup check and quota, without writing anything","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["kind","title"],"properties":{"kind":{"type":"string","enum":["fix","status","note","antipattern"]},"title":{"type":"string","maxLength":160},"symptom":{"type":"string","maxLength":1000},"cause":{"type":"string","maxLength":1000},"fix":{"type":"string","maxLength":3000},"versions":{"type":"string","maxLength":200},"tags":{"type":"array","maxItems":8,"items":{"type":"string","maxLength":32}},"applies":{"type":"string","maxLength":500},"why_safe":{"type":"string","maxLength":500},"force":{"type":"boolean"}}}}}},"responses":{"200":{"description":"dry: would ok|err <code> [quarantine: …] masked=… hazard=… [dup=k… sim=…] quota kb <used>/<cap> flags: …"},"400":{"description":"err bad"},"429":{"description":"err quota"}}}},
"/w/kb/dry":{"post":{"operationId":"kdryw","summary":"Anonymous dry-run preflight (header X-PoW for=w, 20/day per network): same verdict at level 0","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["kind","title"],"properties":{"kind":{"type":"string"},"title":{"type":"string","maxLength":160},"symptom":{"type":"string","maxLength":1000},"fix":{"type":"string","maxLength":3000}}}}}},"responses":{"200":{"description":"the dry verdict"},"400":{"description":"err pow | err bad"},"429":{"description":"err quota"}}}}
}}`)
