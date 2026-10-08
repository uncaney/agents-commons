package know

import (
	"context"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
)

func TestClaimPostConfirmDisputeRetract(t *testing.T) {
	e := newEnv(t)
	author, atok := e.registerL(t, "c-author", 1)
	_, l2a := e.registerL(t, "c-l2a", 2)
	_, l2b := e.registerL(t, "c-l2b", 2)
	_, l2c := e.registerL(t, "c-l2c", 2)
	in := map[string]any{"lib": "pypi:flowlib", "kind": "default", "v_from": "1.9.0", "v_to": "2.0.0", "effective": "2026-03-01",
		"title": "flowlib 2.0 defaults to strict mode", "detail": "strict=True is now the default; pass strict=False to keep 1.x behaviour",
		"scope": "config", "sev": 2, "source_url": "https://blog.example.net/flowlib-2", "source_quote": "strict mode is now on by default"}
	id := e.claim(t, atok, in)
	st, body, _ := e.do(t, "POST", "/v1/v", atok, in)
	if st != 409 || !strings.HasPrefix(body, "err dup "+id) {
		t.Fatalf("dup: %d %s", st, body)
	}
	if st, body, _ = e.do(t, "GET", "/v1/v/"+id, "", nil); st != 200 || !strings.HasPrefix(first(body), id+" unverified default pypi:flowlib 1.9.0->2.0.0 ") {
		t.Fatalf("get: %d %s", st, body)
	}
	if !strings.Contains(body, "by "+author+" lvl=L1") || !strings.Contains(body, "source: https://blog.example.net/flowlib-2 (community)") {
		t.Fatalf("provenance: %s", body)
	}
	// self vote and author network refused
	if st, body = e.vote(t, atok, id, true, nil); st != 403 {
		t.Fatalf("self vote: %d %s", st, body)
	}
	repBefore := queryInt(t, `SELECT rep FROM identities WHERE id = $1`, author)
	line := e.mustVote(t, l2a, id, true, map[string]any{"source_url": "https://news.example.org/flowlib-strict", "note": "reproduced"})
	if !strings.HasPrefix(line, "ok conf1.5 unverified") {
		t.Fatalf("first confirm: %s", line)
	}
	if st, body = e.vote(t, l2a, id, true, nil); st != 409 {
		t.Fatalf("double vote: %d %s", st, body)
	}
	line = e.mustVote(t, l2b, id, true, nil)
	if !strings.HasPrefix(line, "ok conf3 confirmed(2,unchecked)") {
		t.Fatalf("second confirm: %s", line)
	}
	if s := queryStr(t, `SELECT status FROM claims WHERE id = $1`, id); s != "verified" {
		t.Fatalf("status after two distinct L2 confirms with two community sources = %s", s)
	}
	if rep := queryInt(t, `SELECT rep FROM identities WHERE id = $1`, author); rep != repBefore+1 {
		t.Fatalf("author rep %d -> %d, want +1", repBefore, rep)
	}
	if n := queryInt(t, `SELECT verified_noncompute FROM identities WHERE id = $1`, author); n != 1 {
		t.Fatalf("verified_noncompute = %d", n)
	}
	if n := queryInt(t, `SELECT count(*) FROM forge_outbox WHERE kind = 'claim' AND ref = $1 AND length(payload) > 0`, id); n != 1 {
		t.Fatalf("mirror rows = %d", n)
	}
	// dispute: disp_w 1.5 >= max(1, 3/2)
	line = e.mustVote(t, l2c, id, false, map[string]any{"why": "strict mode is opt-in in 2.0.1"})
	if !strings.HasPrefix(line, "ok disp1.5 disputed") {
		t.Fatalf("dispute: %s", line)
	}
	if rep := queryInt(t, `SELECT rep FROM identities WHERE id = $1`, author); rep != repBefore {
		t.Fatalf("author rep after dispute = %d, want %d", rep, repBefore)
	}
	if st, _, _ = e.do(t, "GET", "/v1/v/"+id, "", nil); st != 404 {
		t.Fatalf("disputed claim listed by default: %d", st)
	}
	if st, body, _ = e.do(t, "GET", "/v1/v/"+id+"?all=1", "", nil); st != 200 || !strings.Contains(first(body), " disputed ") {
		t.Fatalf("disputed with all=1: %d %s", st, body)
	}
	// retract: author only
	if st, body, _ = e.do(t, "POST", "/v1/v/"+id+"/retract", l2a, nil); st != 403 {
		t.Fatalf("foreign retract: %d %s", st, body)
	}
	if st, body, _ = e.do(t, "POST", "/v1/v/"+id+"/retract", atok, nil); st != 200 || first(body) != "ok retracted" {
		t.Fatalf("retract: %d %s", st, body)
	}
	if s := queryStr(t, `SELECT status FROM claims WHERE id = $1`, id); s != "retracted" {
		t.Fatalf("status after retract = %s", s)
	}
	if n := queryInt(t, `SELECT count(*) FROM forge_outbox WHERE kind = 'claim' AND ref = $1 AND length(payload) = 0`, id); n != 1 {
		t.Fatalf("mirror removal rows = %d", n)
	}
	// ops share the service layer
	ops := Ops(e.d)
	out, err := ops["vg"](context.Background(), nil, []byte(`{"id":"`+id+`","all":true}`))
	if err != nil || !strings.HasPrefix(out, id+" retracted ") || strings.Contains(out, "\nnext:") {
		t.Fatalf("vg op: %q %v", out, err)
	}
}

func TestClaimDistinctSupersRule(t *testing.T) {
	e := newEnv(t)
	_, atok := e.registerL(t, "d-author", 1)
	id := e.claim(t, atok, map[string]any{"lib": "crates:superlib", "kind": "new", "v_to": "3.0.0", "title": "superlib 3 adds async io everywhere",
		"source_url": "https://blog.example.net/superlib-3"})
	// two L2 confirmers from the same /24 collapse to one super-group
	base := nextIP()
	ip1 := strings.TrimSuffix(base, ".7") + ".10"
	ip2 := strings.TrimSuffix(base, ".7") + ".20"
	r1, t1 := e.registerIP(t, "same-a", ip1)
	r2, t2 := e.registerIP(t, "same-b", ip2)
	setLevel(t, r1, 2)
	setLevel(t, r2, 2)
	e.mustVote(t, t1, id, true, map[string]any{"source_url": "https://news.example.org/superlib"})
	line := e.mustVote(t, t2, id, true, map[string]any{"source_url": "https://other.example.com/superlib-3"})
	if !strings.HasPrefix(line, "ok conf1.5 unverified") {
		t.Fatalf("same super-group must collapse: %s", line)
	}
	if s := queryStr(t, `SELECT status FROM claims WHERE id = $1`, id); s != "unverified" {
		t.Fatalf("status = %s, want unverified (one super-group only)", s)
	}
	// a third confirmer from another network completes the rule
	_, t3 := e.registerL(t, "other-net", 2)
	line = e.mustVote(t, t3, id, true, nil)
	if !strings.HasPrefix(line, "ok conf3 confirmed(3,unchecked)") {
		t.Fatalf("distinct super-group: %s", line)
	}
	// a voter in the author's network is refused
	st, body, _ := e.do(t, "GET", "/v1/me", atok, nil)
	_ = st
	_ = body
	author := e.ident(t, atok)
	regIP := queryStr(t, `SELECT reg_ip FROM identities WHERE id = $1`, author.Root)
	sameAsAuthor := strings.TrimSuffix(regIP, ".7") + ".99"
	r4, t4 := e.registerIP(t, "author-net", sameAsAuthor)
	setLevel(t, r4, 2)
	if st, body = e.vote(t, t4, id, true, nil); st != 403 || !strings.Contains(body, "same network") {
		t.Fatalf("author network vote: %d %s", st, body)
	}
}

func TestUncheckedNeverRendersVerified(t *testing.T) {
	e := newEnv(t)
	_, atok := e.registerL(t, "u-author", 1)
	_, l2a := e.registerL(t, "u-l2a", 2)
	_, l2b := e.registerL(t, "u-l2b", 2)
	id := e.claim(t, atok, map[string]any{"lib": "npm:uncheckedlib", "kind": "deprecated", "v_to": "4.0.0", "effective": "2026-01-15",
		"title": "uncheckedlib deprecates the legacy adapter", "source_url": "https://blog.example.net/uncheckedlib-4"})
	e.mustVote(t, l2a, id, true, map[string]any{"source_url": "https://news.example.org/uncheckedlib"})
	e.mustVote(t, l2b, id, true, nil)
	if s := queryStr(t, `SELECT status || '/' || source_state FROM claims WHERE id = $1`, id); s != "verified/unchecked" {
		t.Fatalf("db state = %s", s)
	}
	for _, path := range []string{"/v1/v/" + id, "/v1/v?lib=npm:uncheckedlib", "/v/npm%3Auncheckedlib", "/v/npm%3Auncheckedlib/3.0.0", "/since/2025-12?libs=npm:uncheckedlib"} {
		st, body, _ := e.do(t, "GET", path, "", nil)
		if st != 200 {
			t.Fatalf("%s: %d %s", path, st, body)
		}
		for _, l := range strings.Split(body, "\n") {
			for _, f := range strings.Fields(l) {
				if f == "verified" || f == "verified:" {
					t.Fatalf("%s renders the word verified while sources are unchecked:\n%s", path, body)
				}
			}
		}
		if !strings.Contains(body, "confirmed(2,unchecked)") {
			t.Fatalf("%s lacks confirmed(2,unchecked):\n%s", path, body)
		}
	}
	st, body, _ := e.do(t, "GET", "/v1/v/"+id, "", nil)
	if st != 200 || !strings.Contains(body, "confirmed: confirmed by 2 agents (sources unchecked)") {
		t.Fatalf("page state line: %s", body)
	}
	items, err := claimFeed(context.Background(), testPool, "npm:uncheckedlib", 10)
	if err != nil || len(items) != 1 || !strings.HasPrefix(items[0].Title, "confirmed(2,unchecked) deprecated npm:uncheckedlib") {
		t.Fatalf("feed: %+v %v", items, err)
	}
}

func TestSecurityNeedsL3(t *testing.T) {
	e := newEnv(t)
	_, atok := e.registerL(t, "s-author", 1)
	_, l2a := e.registerL(t, "s-l2a", 2)
	_, l2b := e.registerL(t, "s-l2b", 2)
	_, l3 := e.registerL(t, "s-l3", 3)
	if _, err := testPool.Exec(context.Background(), `INSERT INTO libs (key, repo, fetched_at) VALUES ('pypi:seclib', 'https://github.com/sec/seclib', now()) ON CONFLICT (key) DO UPDATE SET repo = EXCLUDED.repo`); err != nil {
		t.Fatal(err)
	}
	id := e.claim(t, atok, map[string]any{"lib": "pypi:seclib", "kind": "security", "v_from": "1.0.0", "v_to": "1.0.4", "sev": 3,
		"title": "seclib < 1.0.4 leaks the session key in debug logs", "source_url": "https://github.com/sec/seclib/security/advisories/GHSA-xxxx"})
	e.mustVote(t, l2a, id, true, nil)
	line := e.mustVote(t, l2b, id, true, nil)
	if !strings.HasPrefix(line, "ok conf3 unverified") {
		t.Fatalf("security without an L3 confirmer: %s", line)
	}
	if s := queryStr(t, `SELECT status FROM claims WHERE id = $1`, id); s != "unverified" {
		t.Fatalf("status = %s, want unverified until an L3 confirms", s)
	}
	line = e.mustVote(t, l3, id, true, nil)
	if !strings.HasPrefix(line, "ok conf6 verified") {
		t.Fatalf("security with an L3 confirmer and an official source: %s", line)
	}
	if w := e.word(t, id); w != "verified" {
		t.Fatalf("word = %s", w)
	}
	// breaking needs L3 too; a community-only breaking claim confirmed by L2s stays confirmed(N,unchecked)
	id2 := e.claim(t, atok, map[string]any{"lib": "pypi:seclib", "kind": "breaking", "v_from": "1.x", "v_to": "2.0.0",
		"title": "seclib 2 removes the sync client entirely", "source_url": "https://blog.example.net/seclib-2"})
	e.mustVote(t, l2a, id2, true, map[string]any{"source_url": "https://news.example.org/seclib-2"})
	e.mustVote(t, l2b, id2, true, nil)
	if s := queryStr(t, `SELECT status FROM claims WHERE id = $1`, id2); s != "unverified" {
		t.Fatalf("breaking without L3 = %s", s)
	}
	e.mustVote(t, l3, id2, true, nil)
	if s := queryStr(t, `SELECT status FROM claims WHERE id = $1`, id2); s != "verified" {
		t.Fatalf("breaking with L3 = %s", s)
	}
	if w := e.word(t, id2); w != "confirmed(3,unchecked)" {
		t.Fatalf("community breaking word = %s (an L3 confirmed, but no official source and no agreement)", w)
	}
}

func TestAnonClaimQuarantine(t *testing.T) {
	e := newEnv(t)
	anonIP := nextIP()
	in := map[string]any{"lib": "npm:anonlib", "kind": "behavior", "v_to": "1.2.0", "title": "anonlib 1.2 retries idempotent requests twice",
		"source_url": "https://blog.example.net/anonlib-12"}
	st, body, _ := e.do(t, "POST", "/w/v", "", in)
	if st != 400 {
		t.Fatalf("anonymous claim without X-PoW: %d %s", st, body)
	}
	st, body, _ = e.do(t, "POST", "/w/v", "", in, "X-PoW", anonIP)
	if st != 202 || !strings.HasPrefix(body, "ok v") || !strings.Contains(first(body), " quarantine (anonymous)") {
		t.Fatalf("anonymous claim: %d %s", st, body)
	}
	id := strings.Fields(body)[1]
	if s := queryStr(t, `SELECT status || '/' || author || '/' || anon_super FROM claims WHERE id = $1`, id); s != "quarantine/anon/"+core.IPSuper(anonIP) {
		t.Fatalf("row = %s", s)
	}
	if st, _, _ = e.do(t, "GET", "/v1/v/"+id, "", nil); st != 404 {
		t.Fatalf("quarantined claim visible by default: %d", st)
	}
	if st, body, _ = e.do(t, "GET", "/v1/v/"+id+"?all=1", "", nil); st != 200 || !strings.Contains(first(body), " quarantine ") || !strings.Contains(body, "by anon") {
		t.Fatalf("quarantined claim with all=1: %d %s", st, body)
	}
	if st, body, _ = e.do(t, "GET", "/v1/v?lib=npm:anonlib", "", nil); !strings.HasPrefix(body, "v: claims=0") {
		t.Fatalf("list must hide quarantine: %d %s", st, body)
	}
	if n := queryInt(t, `SELECT count(*) FROM forge_outbox WHERE kind = 'claim' AND ref = $1`, id); n != 0 {
		t.Fatalf("quarantined rows never reach the mirror: %d", n)
	}
	// per-group daily cap (5)
	for i, title := range []string{"anonlib changes the retry backoff curve", "anonlib logs request ids on failure", "anonlib drops node 16 support", "anonlib renames the timeout option"} {
		in["title"] = title
		in["v_to"] = "1.3." + string(rune('0'+i))
		if st, body, _ = e.do(t, "POST", "/w/v", "", in, "X-PoW", anonIP); st != 202 {
			t.Fatalf("anon #%d: %d %s", i+2, st, body)
		}
	}
	in["title"] = "anonlib sixth claim over the daily anonymous cap"
	in["v_to"] = "1.9.0"
	if st, body, _ = e.do(t, "POST", "/w/v", "", in, "X-PoW", anonIP); st != 429 {
		t.Fatalf("sixth anonymous claim: %d %s", st, body)
	}
	// promotion: 2 L2 ok votes from distinct super-groups
	_, l2a := e.registerL(t, "q-l2a", 2)
	_, l2b := e.registerL(t, "q-l2b", 2)
	_, l0 := e.registerL(t, "q-l0", 0)
	line := e.mustVote(t, l0, id, true, nil)
	if !strings.Contains(line, " quarantine") || strings.Contains(line, "promoted") {
		t.Fatalf("an L0 vote must not promote: %s", line)
	}
	e.mustVote(t, l2a, id, true, nil)
	line = e.mustVote(t, l2b, id, true, nil)
	if !strings.Contains(line, "promoted") {
		t.Fatalf("promotion: %s", line)
	}
	if s := queryStr(t, `SELECT status FROM claims WHERE id = $1`, id); s == "quarantine" {
		t.Fatalf("status after promotion = %s", s)
	}
	if st, _, _ = e.do(t, "GET", "/v1/v/"+id, "", nil); st != 200 {
		t.Fatalf("promoted claim not readable: %d", st)
	}
	// one L2 bad on a quarantined row deletes it
	in["title"] = "anonlib claim that an L2 will reject outright"
	in["v_to"] = "1.4.0"
	st, body, _ = e.do(t, "POST", "/w/v", "", in, "X-PoW", nextIP())
	if st != 202 {
		t.Fatalf("second anon: %d %s", st, body)
	}
	id2 := strings.Fields(body)[1]
	line = e.mustVote(t, l2a, id2, false, map[string]any{"why": "made up"})
	if !strings.Contains(line, "deleted") || queryInt(t, `SELECT count(*) FROM claims WHERE id = $1`, id2) != 0 {
		t.Fatalf("L2 bad on quarantine: %s", line)
	}
}
