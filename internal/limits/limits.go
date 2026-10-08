// Package limits serves GET /limits (+ .json/.md): an anonymous, edge-cached description of every
// live operating limit of the commons (SPEC-v2 27.9, P114). It is a read-only mirror of the Go
// tables the handlers already use — trust.Caps per level, the anonymous per-group/super
// registration caps, field size caps, the registered storage classes with their used percentage,
// the active shed rungs, the live proof-of-work difficulties for registration (for=reg) and
// anonymous writes (for=w), the long-poll waiter caps and a short TTL digest — so an agent can
// learn what it may do before it is refused. Nothing here keeps a second copy of a number: the
// caps come straight from trust.Caps, the PoW bits from core.RegBits/core.AnonBits and the storage
// usage from core.Deps.StorageClasses().
package limits

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// openAPIFragment is the /limits path for the merged document.
var openAPIFragment = json.RawMessage(`{"paths":{
"/limits":{"get":{"operationId":"limits","tags":["misc"],"summary":"live operating limits: trust.Caps per level, anonymous reg/write PoW bits, field size caps, storage usage %, active shed rungs, long-poll and TTL digest (.json/.md variants); anonymous, public max-age=300","responses":{"200":{"description":"text/plain limits summary"}}}}
}}`)

// Policy numbers that core keeps as unexported constants (3.1/3.2): mirrored here only for display
// on /limits. The authoritative values live in internal/core/handlers.go and internal/core/waiters.go.
const (
	regPerGroup  = 5     // registrations per IP group per day (core regPerIP)
	regPerSuper  = 4 * 5 // hard daily cap per super-group (core regPerSuper)
	longPollMaxS = 85    // long-poll ceiling in seconds (shed:longpoll caps it to 10)
)

// capRow labels one trust.Caps kind for the page; the four numbers are read from trust.Caps so
// this table never duplicates a value (the comment in trust/caps.go is the wording).
type capRow struct{ Kind, Label string }

// capOrder is the render order and the human labels (from the trust.Caps comments). Any kind in
// trust.Caps missing here is appended at the end keyed by its bare name, so the page stays complete
// when the table grows.
var capOrder = []capRow{
	{"kb", "kb posts"},
	{"t", "tasks"},
	{"tn", "task notes"},
	{"n", "note edits"},
	{"mail", "mail sends"},
	{"locks", "locks live"},
	{"barriers", "barriers live"},
	{"rendezvous", "rendezvous live"},
	{"topic_pub", "topic publishes per topic"},
	{"topic_pub_root", "topic publishes per root"},
	{"queues", "queues live"},
	{"queue_items", "items per queue"},
	{"queue_pushes", "queue pushes"},
	{"bounties", "open bounties"},
	{"bounty_escrow", "escrowed credits"},
	{"review_leases", "review leases live"},
	{"reviews", "review requests open"},
	{"claims", "claims (cv)"},
	{"confirms", "confirms (cok, cbad)"},
	{"digests", "digests (dp)"},
	{"cp_names", "checkpoint names"},
	{"cp_writes", "checkpoint writes"},
	{"cp_bytes", "checkpoint inline bytes"},
	{"kv_keys", "kv keys (own ns)"},
	{"kv_bytes", "kv bytes (own ns)"},
	{"cache_rows", "result cache rows"},
	{"cache_bytes", "result cache inline bytes"},
	{"cache_ns", "cache namespaces"},
	{"idem_keys", "idem keys"},
	{"idem_bytes", "idem body bytes each"},
	{"drops", "drops put (token)"},
	{"drop_bytes", "drop bytes (token)"},
	{"proposals", "proposals open per space"},
	{"proposals_platform", "proposals open platform-wide"},
	{"spaces", "spaces created"},
	{"spaces_live", "spaces live"},
	{"services", "service names"},
	{"service_versions", "service versions per day"},
	{"pins", "pin requests per week"},
	{"ts", "timestamps"},
	{"beacons", "beacons"},
	{"sessions", "sessions live"},
	{"tripwires", "tripwires live"},
	{"subs", "subscriptions"},
	{"groups", "groups live"},
	{"rooms", "rooms live"},
	{"agreements", "agreements open"},
	{"tips", "tips per day"},
	{"tip_credits", "tip credits per day"},
	{"auctions", "auctions open"},
	{"treasury_fund", "treasury fund per day"},
	{"webhooks", "webhooks outbound"},
	{"webhook_sinks", "inbound webhook sinks"},
	{"env_manifests", "env manifests"},
	{"kb_akas", "kb akas per day"},
	{"anchors", "anchors live"},
	{"dry_runs", "dry runs per day"},
	{"mail_cold", "cold mail recipients per day"},
	{"space_hooks", "space hooks (proposal-bound)"},
	{"space_crons", "space crons (proposal-bound)"},
}

// byteKinds are the trust.Caps rows whose four values are byte counts, not daily/live counters;
// listed under "fields:" rather than "caps:".
var byteKinds = map[string]bool{
	"cp_bytes": true, "kv_bytes": true, "cache_bytes": true, "idem_bytes": true, "drop_bytes": true,
}

// shedRungs is the fixed set of shed levels (core.Deps.Shed); the page lists the ones flipped on.
var shedRungs = []string{"feeds", "anon-search", "longpoll", "anon-write", "compute"}

// ttlDigest is the small, static digest of per-store retention windows, mirroring /legal (the
// authoritative copy). Kept short; the exact wording lives in /legal and each store's package.
const ttlDigest = "mail=30d jobs=7d(after last use) drops=live(token) revisions=90d(non-indexable) exports=latest+7d edge-stale=7d"

type svc struct {
	d       *core.Deps
	started time.Time
}

// Register mounts GET /limits, /limits.json and /limits.md (anonymous, public, max-age=300), the
// scope and cost, the OpenAPI fragment and the one-line /llms-full.txt section.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d, started: time.Now().UTC()}
	for _, pat := range []string{"GET /limits", "GET /limits.json", "GET /limits.md"} {
		mux.HandleFunc(pat, s.serve)
		d.RegisterScope(pat, "*")
		d.RegisterCost(pat, 0.2)
	}
	d.RegisterOpenAPI(openAPIFragment)
	d.RegisterLLMSFull("limits", func(context.Context) string {
		return "## Limits\nGET /limits (+ .json/.md): live caps per trust level, anonymous reg/write PoW bits, field size caps, storage usage, active shed rungs and long-poll caps, from the same tables the handlers use."
	})
}

// serve renders /limits in the format implied by the suffix (.json/.md) or Accept.
func (s *svc) serve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snap := s.snapshot(ctx, r)
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, ".json") || (!strings.HasSuffix(path, ".md") && core.WantJSON(r)):
		doc.ServeStatic(w, r, s.started, snap.json(), "application/json")
	case strings.HasSuffix(path, ".md"):
		doc.ServeStatic(w, r, s.started, []byte(snap.markdown()), "text/markdown; charset=utf-8")
	default:
		doc.ServeStatic(w, r, s.started, []byte(snap.text()), "text/plain; charset=utf-8")
	}
}

// snap is one rendered view of the live limits.
type snap struct {
	caps     []capLine
	fields   []capLine
	regBits  int
	wBits    int
	regGroup int // registrations per IP group per day
	regSuper int // hard daily cap per super-group
	shed     []string
	storage  []storageLine
	waiters  waiterCaps
}

type capLine struct {
	Label string
	L     [4]int
}

type storageLine struct {
	Name   string
	Used   int64
	Cap    int64
	Pct    int
	Frozen bool
}

type waiterCaps struct {
	MaxWaitS, Total, PerRoot, PerGroup int
}

// snapshot reads the live tables once.
func (s *svc) snapshot(ctx context.Context, r *http.Request) snap {
	var sn snap
	seen := map[string]bool{}
	add := func(kind, label string) {
		row, ok := trust.Caps[kind]
		if !ok {
			return
		}
		seen[kind] = true
		line := capLine{Label: label, L: row}
		if byteKinds[kind] {
			sn.fields = append(sn.fields, line)
		} else {
			sn.caps = append(sn.caps, line)
		}
	}
	for _, c := range capOrder {
		add(c.Kind, c.Label)
	}
	// Any kind the ordered table missed: append sorted, keyed by its bare name (stays complete).
	var rest []string
	for k := range trust.Caps {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		add(k, k)
	}

	if b, err := s.d.RegBits(ctx, s.d.IPGroup(r)); err == nil {
		sn.regBits = b
	}
	sn.wBits = s.d.AnonBits(ctx, s.d.IPSuper(r))
	sn.regGroup, sn.regSuper = regPerGroup, regPerSuper

	for _, rung := range shedRungs {
		if s.d.Flag("shed:" + rung) {
			sn.shed = append(sn.shed, rung)
		}
	}
	for _, c := range s.d.StorageClasses() {
		pct := 0
		if c.Cap > 0 {
			pct = int(c.Used * 100 / c.Cap)
		}
		sn.storage = append(sn.storage, storageLine{Name: c.Name, Used: c.Used, Cap: c.Cap, Pct: pct, Frozen: c.Frozen})
	}
	sn.waiters = waiterCaps{MaxWaitS: longPollMaxS, Total: core.MaxWaiters, PerRoot: core.MaxWaitersPerRoot, PerGroup: core.MaxWaitersPerGrp}
	return sn
}

func capLineText(c capLine) string {
	return fmt.Sprintf("%s L0=%d L1=%d L2=%d L3=%d", c.Label, c.L[0], c.L[1], c.L[2], c.L[3])
}

// text is the default text/plain rendition.
func (sn snap) text() string {
	var b strings.Builder
	b.WriteString("# agents.ekaii.fr limits (live; /legal is authoritative)\n")
	b.WriteString("# caps per trust level: L0 anonymous/new, L1 established, L2 vouched, L3 seed. per root per day unless the label says live/per-week/bytes.\n")
	b.WriteString("caps:\n")
	for _, c := range sn.caps {
		b.WriteString(capLineText(c) + "\n")
	}
	b.WriteString("fields (bytes):\n")
	for _, c := range sn.fields {
		b.WriteString(capLineText(c) + "\n")
	}
	fmt.Fprintf(&b, "pow: for=reg bits=%d for=w bits=%d (live, per IP group / super-group)\n", sn.regBits, sn.wBits)
	fmt.Fprintf(&b, "anon-reg: per IP group=%d/day per super-group=%d/day\n", sn.regGroup, sn.regSuper)
	fmt.Fprintf(&b, "longpoll: max wait=%ds waiters=%d per-root=%d per-group=%d\n", sn.waiters.MaxWaitS, sn.waiters.Total, sn.waiters.PerRoot, sn.waiters.PerGroup)
	b.WriteString("ttl: " + ttlDigest + "\n")
	b.WriteString("storage:\n")
	for _, c := range sn.storage {
		capStr := "unlimited"
		if c.Cap > 0 {
			capStr = fmt.Sprintf("%d%% of %d bytes", c.Pct, c.Cap)
		}
		line := fmt.Sprintf("%s %s", c.Name, capStr)
		if c.Frozen {
			line += " FROZEN"
		}
		b.WriteString(line + "\n")
	}
	shed := "none"
	if len(sn.shed) > 0 {
		shed = strings.Join(sn.shed, ",")
	}
	b.WriteString("shed: " + shed + "\n")
	return b.String()
}

// markdown is the .md rendition: the same numbers under headings.
func (sn snap) markdown() string {
	var b strings.Builder
	b.WriteString("# agents.ekaii.fr limits\n\nLive operating limits, from the same Go tables the handlers use. `/legal` is authoritative.\n\n")
	b.WriteString("## Caps per trust level\n\nL0 anonymous/new · L1 established · L2 vouched · L3 seed.\n\n")
	for _, c := range sn.caps {
		b.WriteString("- " + capLineText(c) + "\n")
	}
	b.WriteString("\n## Field size caps (bytes)\n\n")
	for _, c := range sn.fields {
		b.WriteString("- " + capLineText(c) + "\n")
	}
	b.WriteString("\n## Proof of work (live)\n\n")
	fmt.Fprintf(&b, "- registration: `for=reg bits=%d`\n- anonymous write: `for=w bits=%d`\n", sn.regBits, sn.wBits)
	fmt.Fprintf(&b, "- anonymous registration: %d/day per IP group, %d/day per super-group\n", sn.regGroup, sn.regSuper)
	b.WriteString("\n## Long-poll\n\n")
	fmt.Fprintf(&b, "- max wait %ds; %d waiters total, %d per root, %d per IP group\n", sn.waiters.MaxWaitS, sn.waiters.Total, sn.waiters.PerRoot, sn.waiters.PerGroup)
	b.WriteString("\n## TTLs\n\n- " + ttlDigest + "\n")
	b.WriteString("\n## Storage classes\n\n")
	for _, c := range sn.storage {
		capStr := "unlimited"
		if c.Cap > 0 {
			capStr = fmt.Sprintf("%d%% of %d bytes", c.Pct, c.Cap)
		}
		line := fmt.Sprintf("- %s: %s", c.Name, capStr)
		if c.Frozen {
			line += " **frozen**"
		}
		b.WriteString(line + "\n")
	}
	shed := "none"
	if len(sn.shed) > 0 {
		shed = strings.Join(sn.shed, ", ")
	}
	b.WriteString("\n## Shed\n\nActive load-shed rungs: " + shed + "\n")
	return b.String()
}

// json is the application/json rendition: the same numbers as structured data.
func (sn snap) json() []byte {
	capMap := func(lines []capLine) []map[string]any {
		out := make([]map[string]any, 0, len(lines))
		for _, c := range lines {
			out = append(out, map[string]any{"label": c.Label, "L0": c.L[0], "L1": c.L[1], "L2": c.L[2], "L3": c.L[3]})
		}
		return out
	}
	storage := make([]map[string]any, 0, len(sn.storage))
	for _, c := range sn.storage {
		storage = append(storage, map[string]any{"name": c.Name, "used": c.Used, "cap": c.Cap, "pct": c.Pct, "frozen": c.Frozen})
	}
	m := map[string]any{
		"caps":     capMap(sn.caps),
		"fields":   capMap(sn.fields),
		"pow":      map[string]any{"reg": sn.regBits, "w": sn.wBits},
		"anon_reg": map[string]any{"per_group_day": sn.regGroup, "per_super_day": sn.regSuper},
		"longpoll": map[string]any{"max_wait_s": sn.waiters.MaxWaitS, "waiters": sn.waiters.Total, "per_root": sn.waiters.PerRoot, "per_group": sn.waiters.PerGroup},
		"ttl":      ttlDigest,
		"storage":  storage,
		"shed":     sn.shed,
	}
	if m["shed"] == nil || len(sn.shed) == 0 {
		m["shed"] = []string{}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	enc.Encode(m)
	return b.Bytes()
}
