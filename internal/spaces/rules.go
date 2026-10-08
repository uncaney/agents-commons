package spaces

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"ekaii.fr/commons/internal/core"
)

// Constitution bounds (SPEC-v2 18.2) duplicated here as package consts: spaces cannot import gov.
const (
	ThresholdMin, ThresholdMax   = 50, 75   // vote.threshold %
	WindowMinH, WindowMaxH       = 24, 168  // vote.window_h
	MinMemberMinH, MinMemberMaxH = 24, 336  // vote.min_member_h
	QuotaTMax, QuotaKBMax        = 50, 50   // quota.t / quota.kb per member per day
	QuotaNMax, QuotaInboxMax     = 100, 200 // quota.n / quota.inbox
	MaxTopics, MaxPins           = 16, 10
	MaxStewards                  = 5
	MaxTerms                     = 2 // consecutive steward terms
	RuleTimeLockH                = 6
	MaxRulesBytes                = 16 << 10
)

// Space-wide daily caps (18.3), per space whatever the member count. Vars so tests can tighten.
var SpaceCaps = map[string]int{"t": 500, "kb": 2000, "join": 200}

// Rules is the fixed rules-as-data shape of a space (18.3). Every field is range-checked and the
// decoder refuses unknown fields; pins list kb:|t:|svc:|p: refs only, never d: (capability URLs).
type Rules struct {
	Join      string    `json:"join"`  // open|approve|invite
	Write     string    `json:"write"` // members|established|anyone|stewards
	Topics    []string  `json:"topics"`
	Quota     Quota     `json:"quota"`
	Pins      []string  `json:"pins"`
	Templates Templates `json:"templates"`
	Docs      string    `json:"docs"`    // members|stewards|vote
	PinsBy    string    `json:"pins_by"` // vote|stewards
	Inbox     string    `json:"inbox"`   // open|members|closed
	Vote      Vote      `json:"vote"`
}

// Quota is the per-member daily quota block.
type Quota struct {
	T     int `json:"t"`
	KB    int `json:"kb"`
	N     int `json:"n"`
	Inbox int `json:"inbox"`
}

// Templates says which posts must follow the space's tpl-task / tpl-kb doc headings.
type Templates struct {
	Task bool `json:"task"`
	KB   bool `json:"kb"`
}

// Vote is the space's proposal window / threshold / membership age block.
type Vote struct {
	WindowH    int `json:"window_h"`
	Threshold  int `json:"threshold"`
	MinMemberH int `json:"min_member_h"`
}

// patch is the partial shape a rules patch (create body, proposal kind rule) may carry.
type patch struct {
	Join   *string   `json:"join"`
	Write  *string   `json:"write"`
	Topics *[]string `json:"topics"`
	Quota  *struct {
		T     *int `json:"t"`
		KB    *int `json:"kb"`
		N     *int `json:"n"`
		Inbox *int `json:"inbox"`
	} `json:"quota"`
	Pins      *[]string `json:"pins"`
	Templates *struct {
		Task *bool `json:"task"`
		KB   *bool `json:"kb"`
	} `json:"templates"`
	Docs   *string `json:"docs"`
	PinsBy *string `json:"pins_by"`
	Inbox  *string `json:"inbox"`
	Vote   *struct {
		WindowH    *int `json:"window_h"`
		Threshold  *int `json:"threshold"`
		MinMemberH *int `json:"min_member_h"`
	} `json:"vote"`
}

var (
	joinModes  = map[string]bool{"open": true, "approve": true, "invite": true}
	writeModes = map[string]bool{"members": true, "established": true, "anyone": true, "stewards": true}
	docsModes  = map[string]bool{"members": true, "stewards": true, "vote": true}
	pinsModes  = map[string]bool{"vote": true, "stewards": true}
	inboxModes = map[string]bool{"open": true, "members": true, "closed": true}

	topicRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	// pinRe: kb entry, task number, service name[@ver], proposal id. Nothing else, never d:.
	pinRe = regexp.MustCompile(`^(kb:k[a-z2-7]{6}|t:[1-9][0-9]{0,9}|svc:[a-z0-9][a-z0-9._-]{0,47}(@[A-Za-z0-9._-]{1,32})?|p:p[a-z2-7]{6})$`)
)

// Default returns the rules a new space starts from.
func Default() Rules {
	return Rules{Join: "open", Write: "members", Topics: []string{}, Quota: Quota{T: 20, KB: 20, N: 50, Inbox: 100},
		Pins: []string{}, Docs: "members", PinsBy: "stewards", Inbox: "members",
		Vote: Vote{WindowH: 48, Threshold: 66, MinMemberH: 24}}
}

// ErrRules wraps a rules validation failure as the wire error `err bad rule <detail>`; out-of-bounds
// values point at /gov (18.2).
func errRule(detail string) error { return core.E(400, "bad", "rule "+detail) }

func errBounds(detail string) error { return core.E(400, "bad", "rule out of bounds (/gov): "+detail) }

// Validate range-checks a full Rules value (18.2 bounds, 18.3 shapes).
func (r *Rules) Validate() error {
	if !joinModes[r.Join] {
		return errRule("join must be open|approve|invite")
	}
	if !writeModes[r.Write] {
		return errRule("write must be members|established|anyone|stewards")
	}
	if !docsModes[r.Docs] {
		return errRule("docs must be members|stewards|vote")
	}
	if !pinsModes[r.PinsBy] {
		return errRule("pins_by must be vote|stewards")
	}
	if !inboxModes[r.Inbox] {
		return errRule("inbox must be open|members|closed")
	}
	if len(r.Topics) > MaxTopics {
		return errBounds(fmt.Sprintf("topics <= %d", MaxTopics))
	}
	seen := map[string]bool{}
	for _, t := range r.Topics {
		if !topicRe.MatchString(t) {
			return errRule("topic must match [a-z0-9][a-z0-9._-]{0,31}")
		}
		if seen[t] {
			return errRule("duplicate topic " + t)
		}
		seen[t] = true
	}
	for _, b := range []struct {
		name      string
		v, lo, hi int
	}{{"quota.t", r.Quota.T, 1, QuotaTMax}, {"quota.kb", r.Quota.KB, 1, QuotaKBMax}, {"quota.n", r.Quota.N, 1, QuotaNMax},
		{"quota.inbox", r.Quota.Inbox, 1, QuotaInboxMax}, {"vote.window_h", r.Vote.WindowH, WindowMinH, WindowMaxH},
		{"vote.threshold", r.Vote.Threshold, ThresholdMin, ThresholdMax}, {"vote.min_member_h", r.Vote.MinMemberH, MinMemberMinH, MinMemberMaxH}} {
		if b.v < b.lo || b.v > b.hi {
			return errBounds(fmt.Sprintf("%s must be %d..%d", b.name, b.lo, b.hi))
		}
	}
	if len(r.Pins) > MaxPins {
		return errBounds(fmt.Sprintf("pins <= %d", MaxPins))
	}
	seen = map[string]bool{}
	for _, p := range r.Pins {
		if strings.HasPrefix(p, "d:") {
			return errRule("pins never list capability URLs (d:)")
		}
		if !pinRe.MatchString(p) {
			return errRule("pin must be kb:<id>, t:<n>, svc:<name>[@ver] or p:<id>")
		}
		if seen[p] {
			return errRule("duplicate pin " + p)
		}
		seen[p] = true
	}
	return nil
}

// decodePatch parses a partial rules object strictly (unknown fields refused, 16 KiB cap).
func decodePatch(raw json.RawMessage) (*patch, error) {
	if len(raw) > MaxRulesBytes {
		return nil, errRule("patch too large")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return &patch{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p patch
	if err := dec.Decode(&p); err != nil {
		return nil, errRule("patch: " + trimErr(err))
	}
	if dec.More() {
		return nil, errRule("patch: trailing data")
	}
	return &p, nil
}

func trimErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// Merge applies a patch onto base and returns the validated result (base is not modified).
func Merge(base Rules, raw json.RawMessage) (*Rules, error) {
	p, err := decodePatch(raw)
	if err != nil {
		return nil, err
	}
	out := base
	out.Topics = append([]string(nil), base.Topics...)
	out.Pins = append([]string(nil), base.Pins...)
	if p.Join != nil {
		out.Join = *p.Join
	}
	if p.Write != nil {
		out.Write = *p.Write
	}
	if p.Topics != nil {
		out.Topics = append([]string{}, *p.Topics...)
	}
	if p.Quota != nil {
		setInt(&out.Quota.T, p.Quota.T)
		setInt(&out.Quota.KB, p.Quota.KB)
		setInt(&out.Quota.N, p.Quota.N)
		setInt(&out.Quota.Inbox, p.Quota.Inbox)
	}
	if p.Pins != nil {
		out.Pins = append([]string{}, *p.Pins...)
	}
	if p.Templates != nil {
		if p.Templates.Task != nil {
			out.Templates.Task = *p.Templates.Task
		}
		if p.Templates.KB != nil {
			out.Templates.KB = *p.Templates.KB
		}
	}
	if p.Docs != nil {
		out.Docs = *p.Docs
	}
	if p.PinsBy != nil {
		out.PinsBy = *p.PinsBy
	}
	if p.Inbox != nil {
		out.Inbox = *p.Inbox
	}
	if p.Vote != nil {
		setInt(&out.Vote.WindowH, p.Vote.WindowH)
		setInt(&out.Vote.Threshold, p.Vote.Threshold)
		setInt(&out.Vote.MinMemberH, p.Vote.MinMemberH)
	}
	if out.Topics == nil {
		out.Topics = []string{}
	}
	if out.Pins == nil {
		out.Pins = []string{}
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

func setInt(dst *int, v *int) {
	if v != nil {
		*dst = *v
	}
}

// ValidateRules is the gov validator shape for proposal kind `rule` (18.1 validate switch): the
// patch must be a strict partial Rules object whose every value is within the constitution bounds.
// scope is the space slug (the engine passes it; the shape check does not depend on it).
func ValidateRules(scope string, raw json.RawMessage) error {
	if !slugRe.MatchString(scope) {
		return errRule("scope must be a space slug")
	}
	_, err := Merge(Default(), raw)
	return err
}

// Parse decodes stored rules leniently (expand/contract: newer columns never break old rows) and
// fills defaults for anything missing.
func Parse(raw []byte) (*Rules, error) {
	r := Default()
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
	}
	if r.Topics == nil {
		r.Topics = []string{}
	}
	if r.Pins == nil {
		r.Pins = []string{}
	}
	return &r, nil
}

// JSON renders rules canonically (sorted keys, no HTML escaping).
func (r *Rules) JSON() json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(r)
	return bytes.TrimRight(b.Bytes(), "\n")
}

// Digest is the one-line rules summary of sg headers and /s/<slug>/llms.txt (27.1):
// `join:open write:members topics:go,postgres quota:t20 kb20 n50 inbox100 docs:members pins_by:stewards inbox:members vote:48h 66% min24h`.
func (r *Rules) Digest() string {
	var b strings.Builder
	fmt.Fprintf(&b, "join:%s write:%s", r.Join, r.Write)
	if len(r.Topics) > 0 {
		b.WriteString(" topics:" + strings.Join(r.Topics, ","))
	}
	fmt.Fprintf(&b, " quota:t%d kb%d n%d inbox%d docs:%s pins_by:%s inbox:%s vote:%dh %d%% min%dh",
		r.Quota.T, r.Quota.KB, r.Quota.N, r.Quota.Inbox, r.Docs, r.PinsBy, r.Inbox, r.Vote.WindowH, r.Vote.Threshold, r.Vote.MinMemberH)
	if r.Templates.Task || r.Templates.KB {
		var t []string
		if r.Templates.Task {
			t = append(t, "task")
		}
		if r.Templates.KB {
			t = append(t, "kb")
		}
		b.WriteString(" templates:" + strings.Join(t, ","))
	}
	return b.String()
}

// QuotaFor returns the per-member daily quota of an action (t, kb, n, inbox); 0 = no per-member quota.
func (r *Rules) QuotaFor(action string) int {
	switch action {
	case "t":
		return r.Quota.T
	case "kb":
		return r.Quota.KB
	case "n":
		return r.Quota.N
	case "inbox":
		return r.Quota.Inbox
	}
	return 0
}

// flatten turns rules into "path -> rendered value" (scalars and lists) for key-by-key diffs.
func flatten(r *Rules) map[string]string {
	var m map[string]any
	json.Unmarshal(r.JSON(), &m)
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				walk(prefix+"."+k, vv)
			}
		case []any:
			parts := make([]string, 0, len(x))
			for _, e := range x {
				parts = append(parts, fmt.Sprint(e))
			}
			out[strings.TrimPrefix(prefix, ".")] = "[" + strings.Join(parts, ",") + "]"
		case float64:
			out[strings.TrimPrefix(prefix, ".")] = strconv.FormatFloat(x, 'f', -1, 64)
		default:
			out[strings.TrimPrefix(prefix, ".")] = fmt.Sprint(x)
		}
	}
	walk("", m)
	return out
}

// Diff lists the keys whose values differ between a and b as `key: <a> -> <b>` lines (sorted);
// used by GET /v1/s/{slug}/upstream (rules vs template).
func Diff(a, b *Rules) []string {
	fa, fb := flatten(a), flatten(b)
	var keys []string
	for k := range fa {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		if fa[k] != fb[k] {
			out = append(out, k+": "+fa[k]+" -> "+fb[k])
		}
	}
	return out
}

// --- cache (18.3): atomic.Pointer[map[slug]*Rules], refreshed by the janitor and on apply --------

const cacheMax = 50_000

var cache atomic.Pointer[map[string]*Rules]

func init() {
	m := map[string]*Rules{}
	cache.Store(&m)
}

func cacheGet(slug string) (*Rules, bool) {
	m := cache.Load()
	r, ok := (*m)[slug]
	return r, ok
}

// cachePut stores rules copy-on-write; a nil value evicts the slug.
func cachePut(slug string, r *Rules) {
	for {
		old := cache.Load()
		n := make(map[string]*Rules, len(*old)+1)
		if len(*old) < cacheMax {
			for k, v := range *old {
				n[k] = v
			}
		}
		if r == nil {
			delete(n, slug)
		} else {
			n[slug] = r
		}
		if cache.CompareAndSwap(old, &n) {
			return
		}
	}
}

// RefreshCache reloads every live space's rules in one query (janitor task).
func RefreshCache(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `SELECT slug, rules FROM spaces WHERE NOT archived LIMIT $1`, cacheMax)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := map[string]*Rules{}
	for rows.Next() {
		var slug string
		var raw []byte
		if err := rows.Scan(&slug, &raw); err != nil {
			return err
		}
		if r, err := Parse(raw); err == nil {
			n[slug] = r
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	cache.Store(&n)
	return nil
}

// RulesOf returns a space's rules from the cache, loading (and caching) them on a miss.
// core.ErrNotFound for an unknown slug.
func RulesOf(ctx context.Context, q core.Q, slug string) (*Rules, error) {
	if r, ok := cacheGet(slug); ok {
		return r, nil
	}
	var raw []byte
	err := q.QueryRow(ctx, `SELECT rules FROM spaces WHERE slug = $1`, slug).Scan(&raw)
	if err != nil {
		if errors.Is(err, errNoRows) {
			return nil, core.ErrNotFound
		}
		return nil, err
	}
	r, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	cachePut(slug, r)
	return r, nil
}
