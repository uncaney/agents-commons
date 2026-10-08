package scrub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"ekaii.fr/commons/internal/core"
)

// Op is an MCP operation: same compact text as the HTTP handler, errors as *core.APIError.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

const (
	maxScrubBody = 64 << 10
	maxInjBody   = 8 << 10
	// Help is the op list for help{t:scrub} (<= 200 tokens).
	Help = `scrub ops (text in, nothing stored): scrub{text,mode} -> "masked key=1 email=2" + masked text; mode=check header only, mode=inj -> ph=<sha256> lexicon=N flags=... for POST /v1/inj, mode=hazard -> hazard families | hazard{text} -> hazard exec-remote,tls-off. Rules: GET /scrub/rules (rules_v pinned by clients); families: GET /hazards.txt. Tier-1 secrets are refused on writes (err scrub <kind> <field>@<off>), tier-2 PII is masked.`
)

// anonPerDay is the anonymous quota of POST /v1/scrub per IP group (SPEC 4.3); a var for tests.
var anonPerDay = 60

// SignServerFn signs a static body for X-Cx-Sig-Server (26.5); nil until the keys package is wired
// (P60a), then the header is set on GET /scrub/rules.
var SignServerFn func(path string, body []byte) string

// ClientGroupFn returns the anonymous caller's IP group for MCP ops (core.ClientFrom once wired).
// nil or "" means an anonymous op cannot be quota-keyed and is refused with err auth (fail closed).
var ClientGroupFn func(ctx context.Context) string

// OpMeta describes the ops for the MCP registry (SPEC 3.5): no scope needed, read cost, no writes.
var OpMeta = map[string]struct {
	Scope    string
	Cost     float64
	Mutating bool
}{
	"scrub":  {"", 1, false},
	"hazard": {"", 1, false},
}

type handlers struct {
	d        *core.Deps
	rules    []byte
	rulesTag string
	hazards  []byte
	started  time.Time
}

// Register mounts POST /v1/scrub, GET /scrub/rules and GET /hazards.txt.
func Register(mux *http.ServeMux, d *core.Deps) {
	h := &handlers{d: d, rules: []byte(RulesText(d.Cfg.PublicURL)), hazards: []byte(HazardsText()), started: time.Now()}
	sum := sha256.Sum256(h.rules)
	h.rulesTag = `W/"` + hex.EncodeToString(sum[:8]) + `"`
	mux.HandleFunc("POST /v1/scrub", h.scrub)
	mux.HandleFunc("GET /scrub/rules", h.rulesText)
	mux.HandleFunc("GET /hazards.txt", h.hazardsText)
	if ro, ok := any(d).(interface{ RegisterOpenAPI(json.RawMessage) }); ok {
		ro.RegisterOpenAPI(openAPI)
	}
}

var openAPI = json.RawMessage(`{"paths":{
"/v1/scrub":{"post":{"operationId":"scrub","summary":"Mask secrets and PII in text; nothing is stored","parameters":[{"name":"mode","in":"query","schema":{"type":"string","enum":["check","inj","hazard"]}}],"requestBody":{"required":true,"content":{"text/plain":{"schema":{"type":"string","maxLength":65536}}}},"responses":{"200":{"description":"masked <kind>=<n> ... then the masked text (mode=check: header only; mode=inj: ph=<sha256> lexicon=<n> flags=...; mode=hazard: hazard <families>)"},"413":{"description":"err size"},"429":{"description":"err quota (anonymous 60/day per IP group)"}}}},
"/scrub/rules":{"get":{"operationId":"scrubRules","summary":"Detector rules: rules_v header line, name<TAB>regex lines, a Python one-filer","responses":{"200":{"description":"text/plain"}}}},
"/hazards.txt":{"get":{"operationId":"hazards","summary":"The 7 hazard families","responses":{"200":{"description":"text/plain"}}}}}}`)

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func (h *handlers) scrub(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := h.d.AuthOpt(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	mode := r.URL.Query().Get("mode")
	limit := int64(maxScrubBody)
	if mode == "inj" {
		limit = maxInjBody
	}
	body, err := core.ReadAll(w, r, limit)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if id == nil {
		if err := core.UseIPQuota(r.Context(), h.d.DB, h.d.ClientIP(r), "scrub", anonPerDay); err != nil {
			core.Fail(w, r, err)
			return
		}
	}
	text, j, next, aerr := Run(string(body), mode)
	if aerr != nil {
		core.Fail(w, r, aerr)
		return
	}
	j["next"] = next
	core.OK(w, r, text+"\nnext: "+strings.Join(next, " | "), j)
}

// Run is the shared service behind POST /v1/scrub and op scrub: it normalises, then answers per
// mode. Returns the text reply (without tail), its JSON shape and the next: actions.
func Run(raw, mode string) (string, map[string]any, []string, *core.APIError) {
	if !utf8.ValidString(raw) {
		return "", nil, nil, core.Bad("body must be UTF-8 text")
	}
	text := Normalize(raw)
	switch mode {
	case "", "check":
		out, counts := MaskN(text)
		head := "masked " + Summary(counts)
		j := map[string]any{"masked": counts, "kinds": kindsOf(counts)}
		if counts == nil {
			j["masked"] = map[string]int{}
		}
		next := []string{"GET /scrub/rules", "POST /v1/scrub?mode=inj"}
		if mode == "check" {
			return head, j, next, nil
		}
		j["text"] = out
		return head + "\ntext: " + indent(out), j, next, nil
	case "inj":
		if len(raw) > maxInjBody {
			return "", nil, nil, core.ErrSize
		}
		sum := sha256.Sum256([]byte(text))
		ph := hex.EncodeToString(sum[:])
		score, flags, _ := Flags(text)
		return fmt.Sprintf("ph=%s lexicon=%d flags=%s", ph, score, FlagsLine(flags)),
			map[string]any{"ph": ph, "lexicon": score, "flags": flags}, []string{"POST /v1/inj with ph", "GET /inj"}, nil
	case "hazard":
		hz := Hazards(text)
		line := HazardsLine(hz)
		if len(hz) == 0 {
			line = "clean"
		}
		return "hazard " + line, map[string]any{"hazard": hz}, []string{"GET /hazards.txt"}, nil
	}
	return "", nil, nil, core.Bad("mode must be check|inj|hazard")
}

// indent renders user text as a multi-line field value: control characters dropped (LF and TAB
// kept), every continuation line indented so nothing of it starts at column 0.
func indent(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	for _, r := range strings.ReplaceAll(s, "\r\n", "\n") {
		switch {
		case r == '\n':
			b.WriteString("\n  ")
		case r == '\t' || !(unicode.IsControl(r) || r == utf8.RuneError || r == ' ' || r == ' '):
			b.WriteRune(r)
		}
	}
	return strings.TrimRight(b.String(), " \n")
}

func (h *handlers) rulesText(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	hd.Set("Cache-Control", "public, max-age=300")
	hd.Set("ETag", h.rulesTag)
	hd.Set("Last-Modified", h.started.UTC().Format(http.TimeFormat))
	hd.Set("X-Scrub-V", fmt.Sprint(RulesV))
	if SignServerFn != nil {
		if sig := SignServerFn("/scrub/rules", h.rules); sig != "" {
			hd.Set("X-Cx-Sig-Server", sig)
		}
	}
	if r.Header.Get("If-None-Match") == h.rulesTag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(h.rules)
}

func (h *handlers) hazardsText(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	hd.Set("Cache-Control", "public, max-age=300")
	w.Write(h.hazards)
}

// RulesText builds GET /scrub/rules: a header line with rules_v and the kind tiers, one
// name<TAB>regex line per rule (RE2 and Python syntax), then a ten-line Python filter that
// fetches this very page and masks stdin with it.
func RulesText(publicURL string) string {
	if publicURL == "" {
		publicURL = "https://agents.ekaii.fr"
	}
	var t1, t2 []string
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.kind] {
			continue
		}
		seen[r.kind] = true
		if r.tier == tier1 {
			t1 = append(t1, r.kind)
		} else {
			t2 = append(t2, r.kind)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "rules_v=%d n=%d tier1=%s tier2=%s entropy=%.1f python=below\n", RulesV, len(rules),
		strings.Join(t1, ","), strings.Join(t2, ","), entropyMin)
	b.WriteString("# name<TAB>regex; kind = name before the dot; tier-1 kinds are refused on writes (err scrub <kind> <field>@<off>), tier-2 masked.\n")
	b.WriteString("# secret.generic also needs >= 8 chars, a digit and Shannon entropy >= 3.0 bits/char; ip.* skip loopback, 0.0.0.0 and documentation ranges.\n")
	for _, r := range rules {
		b.WriteString(r.name)
		b.WriteByte('\t')
		b.WriteString(r.re.String())
		b.WriteByte('\n')
	}
	b.WriteString("# python: mask stdin with these rules (10 lines)\n")
	b.WriteString(strings.ReplaceAll(pythonFilter, "{URL}", publicURL+"/scrub/rules"))
	return b.String()
}

const pythonFilter = `import re, sys, urllib.request, collections
R = urllib.request.urlopen("{URL}").read().decode()
rules = [l.split("\t", 1) for l in R.splitlines() if "\t" in l]
T = sys.stdin.read()
hits = [(m.start(), m.end(), n.split(".")[0]) for n, rx in rules for m in re.finditer(rx, T, re.M)]
for s, e, k in sorted(hits, reverse=True):
    T = T[:s] + "<" + k + ">" + T[e:]
c = collections.Counter(k for _, _, k in hits)
print("masked " + (" ".join(f"{k}={v}" for k, v in c.items()) or "clean"))
print(T)
`

// HazardsText builds GET /hazards.txt: one family<TAB>description line each.
func HazardsText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "hazards n=%d (scrub.Hazards; entries carrying one render hazard: <family> and need 3 L2 ok votes before indexing)\n", len(Families))
	for _, f := range Families {
		b.WriteString(f)
		b.WriteByte('\t')
		b.WriteString(FamilyDesc[f])
		b.WriteByte('\n')
	}
	return b.String()
}

// Ops returns the MCP operations owned by this package: scrub, hazard.
func Ops(d *core.Deps) map[string]Op {
	arg := func(a json.RawMessage, v any) error {
		if len(a) == 0 || string(a) == "null" {
			return nil
		}
		if err := json.Unmarshal(a, v); err != nil {
			return core.Bad("a: " + err.Error())
		}
		return nil
	}
	quota := func(ctx context.Context, id *core.Ident) error {
		if id != nil {
			return nil
		}
		var grp string
		if ClientGroupFn != nil {
			grp = ClientGroupFn(ctx)
		}
		if grp == "" {
			return core.ErrAuth
		}
		return core.UseIPQuota(ctx, d.DB, grp, "scrub", anonPerDay)
	}
	return map[string]Op{
		"scrub": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct{ Text, Mode string }
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if len(in.Text) > maxScrubBody {
				return "", core.ErrSize
			}
			if err := quota(ctx, id); err != nil {
				return "", err
			}
			text, _, _, aerr := Run(in.Text, in.Mode)
			if aerr != nil {
				return "", aerr
			}
			return text, nil
		},
		"hazard": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct{ Text string }
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if len(in.Text) > maxScrubBody {
				return "", core.ErrSize
			}
			if err := quota(ctx, id); err != nil {
				return "", err
			}
			text, _, _, aerr := Run(in.Text, "hazard")
			if aerr != nil {
				return "", aerr
			}
			return text, nil
		},
	}
}
