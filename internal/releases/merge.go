package releases

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/diff3"
)

// docNames are the documents a release snapshots and a delta merges (SPEC-v2 27.5): the two post
// templates, the home page and the per-space llms.txt. Order is stable for deterministic output.
var docNames = []string{"home", "tpl-task", "tpl-kb", "llms"}

// tagRe is the release tag shape ^v[0-9]+(\.[0-9]+)?$ (also enforced by the 0186 CHECK).
var tagRe = regexp.MustCompile(`^v[0-9]+(\.[0-9]+)?$`)

// parseTag splits vMAJOR[.MINOR] into its two integers; ok is false for a malformed tag.
func parseTag(t string) (maj, min int, ok bool) {
	if !tagRe.MatchString(t) {
		return 0, 0, false
	}
	body := strings.TrimPrefix(t, "v")
	maj64, minor := body, "0"
	if i := strings.IndexByte(body, '.'); i >= 0 {
		maj64, minor = body[:i], body[i+1:]
	}
	a, err1 := strconv.Atoi(maj64)
	b, err2 := strconv.Atoi(minor)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return a, b, true
}

// tagLess reports whether tag a sorts strictly before tag b (vMAJOR.MINOR order).
func tagLess(a, b string) bool {
	am, an, _ := parseTag(a)
	bm, bn, _ := parseTag(b)
	if am != bm {
		return am < bm
	}
	return an < bn
}

// KeyDelta is one rules key the upstream release changed relative to the fork's pinned base.
type KeyDelta struct {
	Key, Base, Ours, Theirs string
	Conflict                bool // ours changed the key away from base differently than upstream
}

// DocDelta is one document the upstream release changed relative to the base.
type DocDelta struct {
	Name     string
	Merged   string // diff3 of (base, ours, theirs); carries conflict markers when Conflict
	Conflict bool
}

// Delta is the three-way comparison of a fork against a target release (SPEC-v2 27.5): base is the
// snapshot the fork is pinned to (spaces.upstream_tag), theirs is the target release, ours is the
// fork's current state. Only keys/docs the upstream actually changed appear.
type Delta struct {
	BaseTag, ToTag string
	Rules          []KeyDelta
	Docs           []DocDelta
}

// Conflicts lists the keys (rules keys then doc names) still in conflict, in display order.
func (d *Delta) Conflicts() []string {
	var out []string
	for _, k := range d.Rules {
		if k.Conflict {
			out = append(out, k.Key)
		}
	}
	for _, dd := range d.Docs {
		if dd.Conflict {
			out = append(out, dd.Name)
		}
	}
	return out
}

// computeDelta builds the three-way delta of base (pinned snapshot), ours (current) and theirs
// (target release). base/ours/theirs each carry rules JSON and the doc texts.
func computeDelta(baseTag, toTag string, base, ours, theirs snapshot) *Delta {
	d := &Delta{BaseTag: baseTag, ToTag: toTag}

	fb, fo, ft := flatten(base.Rules), flatten(ours.Rules), flatten(theirs.Rules)
	keys := unionKeys(fb, fo, ft)
	for _, k := range keys {
		bv, ov, tv := fb[k], fo[k], ft[k]
		if tv == bv {
			continue // upstream did not touch this key
		}
		kd := KeyDelta{Key: k, Base: bv, Ours: ov, Theirs: tv}
		// upstream changed the key; a conflict is only when ours also moved it elsewhere.
		if ov != bv && ov != tv {
			kd.Conflict = true
		}
		d.Rules = append(d.Rules, kd)
	}

	for _, name := range docNames {
		bt, ot, tt := base.Docs[name], ours.Docs[name], theirs.Docs[name]
		if tt == bt {
			continue // upstream did not touch this doc
		}
		merged, conflict := diff3.MergeText(bt, ot, tt)
		d.Docs = append(d.Docs, DocDelta{Name: name, Merged: merged, Conflict: conflict})
	}
	return d
}

// resolveMap is the proposal's {key: ours|upstream} resolution of conflicting keys/docs.
type resolveMap map[string]string

// remainingConflicts returns the conflicting keys/docs a resolution does not settle. A resolution
// value must be "ours" or "upstream"; anything else leaves the conflict standing.
func (d *Delta) remainingConflicts(r resolveMap) []string {
	var out []string
	for _, k := range d.Rules {
		if k.Conflict && !resolved(r[k.Key]) {
			out = append(out, k.Key)
		}
	}
	for _, dd := range d.Docs {
		if dd.Conflict && !resolved(r[dd.Name]) {
			out = append(out, dd.Name)
		}
	}
	return out
}

func resolved(v string) bool { return v == "ours" || v == "upstream" }

// merged produces the adopted rules JSON and the documents to write after applying resolution.
// It assumes remainingConflicts(r) is empty. docs holds only the documents that change.
func (d *Delta) merged(ours snapshot, theirs snapshot, r resolveMap) (rules json.RawMessage, docs map[string]string, err error) {
	// Start from ours (current rules) as a nested object, then apply each upstream-changed key.
	var m map[string]any
	if err := json.Unmarshal(ours.Rules, &m); err != nil {
		return nil, nil, err
	}
	var tm map[string]any
	if err := json.Unmarshal(theirs.Rules, &tm); err != nil {
		return nil, nil, err
	}
	for _, k := range d.Rules {
		take := "upstream"
		if k.Conflict {
			take = r[k.Key] // guaranteed ours|upstream by the caller
		}
		if take == "ours" {
			continue // keep ours (already in m)
		}
		setPath(m, k.Key, getPath(tm, k.Key))
	}
	rules, err = json.Marshal(m)
	if err != nil {
		return nil, nil, err
	}

	docs = map[string]string{}
	for _, dd := range d.Docs {
		var text string
		switch {
		case !dd.Conflict:
			text = dd.Merged
		case r[dd.Name] == "ours":
			text = ours.Docs[dd.Name]
		default: // upstream
			text = theirs.Docs[dd.Name]
		}
		if strings.Contains(text, diff3.MarkOurs) || strings.Contains(text, diff3.MarkUpstream) {
			return nil, nil, fmt.Errorf("doc %s still carries conflict markers", dd.Name)
		}
		docs[dd.Name] = text
	}
	return rules, docs, nil
}

// --- flatten / path helpers ----------------------------------------------------------------------

// flatten renders a rules JSON object as dotted-key -> stringified value, matching spaces' own
// key-by-key diff (quota.t, vote.window_h, topics as [a,b,c]).
func flatten(raw json.RawMessage) map[string]string {
	var m map[string]any
	out := map[string]string{}
	if json.Unmarshal(raw, &m) != nil {
		return out
	}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				walk(join(prefix, k), vv)
			}
		case []any:
			parts := make([]string, 0, len(x))
			for _, e := range x {
				parts = append(parts, fmt.Sprint(e))
			}
			out[prefix] = "[" + strings.Join(parts, ",") + "]"
		case float64:
			out[prefix] = strconv.FormatFloat(x, 'f', -1, 64)
		case nil:
			out[prefix] = ""
		default:
			out[prefix] = fmt.Sprint(x)
		}
	}
	walk("", m)
	return out
}

func join(prefix, k string) string {
	if prefix == "" {
		return k
	}
	return prefix + "." + k
}

func unionKeys(ms ...map[string]string) []string {
	seen := map[string]bool{}
	for _, m := range ms {
		for k := range m {
			seen[k] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// getPath reads a dotted key from a nested map, returning nil when absent.
func getPath(m map[string]any, key string) any {
	parts := strings.Split(key, ".")
	var cur any = m
	for _, p := range parts {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

// setPath writes val at a dotted key in a nested map, creating intermediate objects as needed.
func setPath(m map[string]any, key string, val any) {
	parts := strings.Split(key, ".")
	cur := m
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = val
}
