package know

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
)

func hashOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestSourceAgreementOkMismatchGone(t *testing.T) {
	e := newEnv(t)
	author, atok := e.registerL(t, "sa-author", 1)
	_, l2 := e.registerL(t, "sa-l2", 2)
	_, l1 := e.registerL(t, "sa-l1", 1)
	_, l1b := e.registerL(t, "sa-l1b", 1)
	h := hashOf("the page as fetched")
	// ok: the author's hash equals two confirmers' hashes from distinct networks, one L2+
	id := e.claim(t, atok, map[string]any{"lib": "npm:agreelib", "kind": "new", "v_to": "2.0.0", "title": "agreelib 2 adds streaming responses",
		"source_url": "https://blog.example.net/agreelib-2", "src_hash": h, "src_len": 4200})
	line := e.mustVote(t, l1, id, true, map[string]any{"src_hash": h, "src_len": 4200})
	if strings.Contains(line, "sources:agreed") {
		t.Fatalf("one confirmer must not agree: %s", line)
	}
	line = e.mustVote(t, l2, id, true, map[string]any{"src_hash": h, "src_len": 4200})
	if !strings.Contains(line, "sources:agreed") {
		t.Fatalf("agreement: %s", line)
	}
	if s := queryStr(t, `SELECT source_state FROM claims WHERE id = $1`, id); s != "ok" {
		t.Fatalf("source_state = %s", s)
	}
	st, body, _ := e.do(t, "GET", "/v1/v/"+id, "", nil)
	if st != 200 || !strings.Contains(body, "sources: agreed by 2 fetches (2 super-groups)") {
		t.Fatalf("sources line: %d %s", st, body)
	}
	// mismatch: two distinct-super confirmers agree with each other, not with the author -> mail
	h2 := hashOf("the page after it changed")
	id2 := e.claim(t, atok, map[string]any{"lib": "npm:agreelib", "kind": "default", "v_to": "2.1.0", "title": "agreelib 2.1 flips the keepalive default",
		"source_url": "https://blog.example.net/agreelib-21", "src_hash": h, "src_len": 4200})
	e.mustVote(t, l1, id2, true, map[string]any{"src_hash": h2, "src_len": 5000})
	sysMail.Delete(author)
	line = e.mustVote(t, l2, id2, true, map[string]any{"source_url": "https://news.example.org/agreelib-21", "src_hash": h2, "src_len": 5000})
	if !strings.Contains(line, "source changed since posted") {
		t.Fatalf("mismatch line: %s", line)
	}
	if s := queryStr(t, `SELECT source_state || '/' || status FROM claims WHERE id = $1`, id2); s != "mismatch/unverified" {
		t.Fatalf("mismatch state = %s (status must stay unverified despite conf_w and sources)", s)
	}
	if subj, ok := sysMail.Load(author); !ok || !strings.HasPrefix(subj.(string), "source drifted: refresh "+id2) {
		t.Fatalf("author sys mail: %v %v", subj, ok)
	}
	if _, body, _ = e.do(t, "GET", "/v1/v/"+id2, "", nil); !strings.Contains(body, "sources: source changed since posted") {
		t.Fatalf("mismatch page: %s", body)
	}
	// gone: the zero hash from two super-groups
	id3 := e.claim(t, atok, map[string]any{"lib": "npm:agreelib", "kind": "removed", "v_to": "3.0.0", "title": "agreelib 3 drops the callback api",
		"source_url": "https://blog.example.net/agreelib-3", "src_hash": h, "src_len": 4200})
	e.mustVote(t, l1, id3, true, map[string]any{"src_hash": "0"})
	line = e.mustVote(t, l1b, id3, true, map[string]any{"src_hash": "0"})
	if !strings.Contains(line, "source gone") || queryStr(t, `SELECT source_state FROM claims WHERE id = $1`, id3) != "gone" {
		t.Fatalf("gone: %s", line)
	}
	// hash validation
	if st, body = e.vote(t, l2, id3, true, map[string]any{"src_hash": "xyz"}); st != 400 {
		t.Fatalf("bad hash: %d %s", st, body)
	}
}

func TestSoftMatchSrcLen(t *testing.T) {
	e := newEnv(t)
	_, atok := e.registerL(t, "soft-author", 1)
	_, l2 := e.registerL(t, "soft-l2", 2)
	_, l1 := e.registerL(t, "soft-l1", 1)
	id := e.claim(t, atok, map[string]any{"lib": "pypi:softlib", "kind": "new", "v_to": "1.5.0", "title": "softlib 1.5 adds a plugin registry",
		"source_url": "https://blog.example.net/softlib-15", "src_hash": hashOf("author fetch"), "src_len": 1000})
	e.mustVote(t, l1, id, true, map[string]any{"src_hash": hashOf("fetch one"), "src_len": 1050})
	e.mustVote(t, l2, id, true, map[string]any{"src_hash": hashOf("fetch two"), "src_len": 960})
	if s := queryStr(t, `SELECT source_state FROM claims WHERE id = $1`, id); s != "unchecked" {
		t.Fatalf("differing hashes with close lengths: source_state = %s", s)
	}
	st, body, _ := e.do(t, "GET", "/v1/v/"+id, "", nil)
	if st != 200 || !strings.Contains(body, "sources: sources agreed ~") {
		t.Fatalf("soft match line: %d %s", st, body)
	}
	// lengths far apart: no soft match
	id2 := e.claim(t, atok, map[string]any{"lib": "pypi:softlib", "kind": "new", "v_to": "1.6.0", "title": "softlib 1.6 ships typed settings",
		"source_url": "https://blog.example.net/softlib-16", "src_hash": hashOf("author fetch 2"), "src_len": 1000})
	e.mustVote(t, l1, id2, true, map[string]any{"src_hash": hashOf("fetch three"), "src_len": 2000})
	e.mustVote(t, l2, id2, true, map[string]any{"src_hash": hashOf("fetch four"), "src_len": 300})
	if _, body, _ = e.do(t, "GET", "/v1/v/"+id2, "", nil); strings.Contains(body, "sources agreed ~") {
		t.Fatalf("no soft match expected: %s", body)
	}
}

func TestVerifiedWordAfterAgreement(t *testing.T) {
	e := newEnv(t)
	_, atok := e.registerL(t, "vw-author", 1)
	_, l2a := e.registerL(t, "vw-l2a", 2)
	_, l2b := e.registerL(t, "vw-l2b", 2)
	_, l2c := e.registerL(t, "vw-l2c", 2)
	h := hashOf("verified page")
	id := e.claim(t, atok, map[string]any{"lib": "npm:verifiedlib", "kind": "renamed", "v_from": "1.0.0", "v_to": "2.0.0", "title": "verifiedlib renames createClient to connect",
		"source_url": "https://blog.example.net/verifiedlib-2", "src_hash": h, "src_len": 3000})
	e.mustVote(t, l2a, id, true, map[string]any{"source_url": "https://news.example.org/verifiedlib-2", "src_hash": h, "src_len": 3000})
	if w := e.word(t, id); w != "unverified" {
		t.Fatalf("after one confirm: %s", w)
	}
	line := e.mustVote(t, l2b, id, true, map[string]any{"src_hash": h, "src_len": 3000})
	if !strings.HasPrefix(line, "ok conf3 verified") || !strings.Contains(line, "sources:agreed") {
		t.Fatalf("agreement + 13.1 conditions: %s", line)
	}
	st, body, _ := e.do(t, "GET", "/v1/v/"+id, "", nil)
	if st != 200 || !strings.HasPrefix(first(body), id+" verified renamed npm:verifiedlib 1.0.0->2.0.0") || !strings.Contains(body, "confirmed: verified by 2 agents") {
		t.Fatalf("verified rendering: %d %s", st, body)
	}
	if st, body, _ = e.do(t, "GET", "/v1/v?lib=npm:verifiedlib", "", nil); !strings.Contains(body, id+" verified renamed") {
		t.Fatalf("list word: %d %s", st, body)
	}
	// a false ok later disputed costs the L2 confirmers 2 rep
	repA := queryInt(t, `SELECT rep FROM identities WHERE id = (SELECT root FROM claim_votes WHERE claim_id = $1 AND liable LIMIT 1)`, id)
	if n := queryInt(t, `SELECT count(*) FROM claim_votes WHERE claim_id = $1 AND liable`, id); n != 2 {
		t.Fatalf("liable confirmers = %d", n)
	}
	_, l3 := e.registerL(t, "vw-l3", 3)
	e.mustVote(t, l2c, id, false, map[string]any{"why": "the rename never shipped"})
	line = e.mustVote(t, l3, id, false, map[string]any{"why": "confirmed: connect does not exist"})
	if !strings.Contains(line, " disputed") {
		t.Fatalf("dispute: %s", line)
	}
	if rep := queryInt(t, `SELECT min(rep) FROM identities WHERE id IN (SELECT root FROM claim_votes WHERE claim_id = $1 AND up AND lvl >= 2)`, id); rep != repA-2 {
		t.Fatalf("liable confirmer rep %d -> %d, want -2", repA, rep)
	}
}

func TestMachineClaimsRenderAndNoRep(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	sys := &core.Ident{ID: core.SystemID, Root: core.SystemID}
	in := ClaimInput{Lib: "pypi:machinelib", Kind: "security", VFrom: "1.0.0", VTo: "1.0.9", Title: "GHSA-abcd-1234-efgh: machinelib path traversal in the static handler",
		Detail: "versions before 1.0.9 allow ../ in asset names", SourceURL: "https://osv.dev/vulnerability/GHSA-abcd-1234-efgh", Sev: 3,
		Src: "machine", SourceTier: "official", SourceState: "ok", Status: "verified"}
	id, err := CreateClaim(ctx, e.d, sys, in)
	if err != nil {
		t.Fatal(err)
	}
	// idempotent on (lib, kind, source_url)
	id2, err := CreateClaim(ctx, e.d, sys, in)
	if err != nil || id2 != id {
		t.Fatalf("machine re-ingest: %s %v (want %s)", id2, err, id)
	}
	st, body, _ := e.do(t, "GET", "/v1/v/"+id, "", nil)
	if st != 200 || !strings.HasPrefix(first(body), id+" verified security pypi:machinelib 1.0.0->1.0.9 ") || !strings.Contains(first(body), "by machine (osv.dev)") {
		t.Fatalf("machine rendering: %d %s", st, body)
	}
	if strings.Contains(body, "lvl=") {
		t.Fatalf("machine rows never show a level: %s", body)
	}
	// an agent cannot set the machine fields
	_, atok := e.registerL(t, "m-author", 1)
	aid := e.claim(t, atok, map[string]any{"lib": "pypi:machinelib", "kind": "new", "v_to": "1.1.0", "title": "machinelib 1.1 adds a sandboxed static handler",
		"source_url": "https://blog.example.net/machinelib", "src": "machine", "status": "verified", "source_state": "ok"})
	if s := queryStr(t, `SELECT src || '/' || status || '/' || source_state FROM claims WHERE id = $1`, aid); s != "agent/unverified/unchecked" {
		t.Fatalf("agent claim with machine fields = %s", s)
	}
	// confirmations never move the system root's rep; disputes work like any claim
	_, l2a := e.registerL(t, "m-l2a", 2)
	_, l2b := e.registerL(t, "m-l2b", 2)
	_, l2c := e.registerL(t, "m-l2c", 2)
	e.mustVote(t, l2a, id, true, nil)
	if rep := queryInt(t, `SELECT rep FROM identities WHERE id = $1`, core.SystemID); rep != 0 {
		t.Fatalf("system root gained rep: %d", rep)
	}
	if n := queryInt(t, `SELECT count(*) FROM rep_log WHERE root = $1`, core.SystemID); n != 0 {
		t.Fatalf("rep_log rows for the system root: %d", n)
	}
	// 3 disputes hide the row and tell the machineclaims hook
	paused := ""
	MachineDisputedFn = func(ctx context.Context, q core.Q, lib, cid string) { paused = lib + "/" + cid }
	t.Cleanup(func() { MachineDisputedFn = nil })
	_, l0 := e.registerL(t, "m-l0", 0)
	_, l1 := e.registerL(t, "m-l1", 1)
	e.mustVote(t, l2b, id, false, map[string]any{"why": "not reproducible"})
	e.mustVote(t, l0, id, false, map[string]any{"why": "fixed earlier"})
	line := e.mustVote(t, l1, id, false, map[string]any{"why": "wrong range"})
	if !strings.Contains(line, "hidden") {
		t.Fatalf("third dispute: %s", line)
	}
	if paused != "pypi:machinelib/"+id {
		t.Fatalf("MachineDisputedFn = %q", paused)
	}
	if st, _, _ = e.do(t, "GET", "/v1/v/"+id+"?all=1", "", nil); st != 404 {
		t.Fatalf("hidden machine claim: %d", st)
	}
	_ = l2c
	// machine claims feed /cutoff style reads: a release claim by the machine lists normally
	rid, err := CreateClaim(ctx, e.d, sys, ClaimInput{Lib: "pypi:machinelib", Kind: "release", VTo: "1.0.9", Effective: "2026-01-10", Title: "1.0.9 released",
		SourceURL: "https://pypi.org/project/machinelib/1.0.9/", Src: "machine", SourceTier: "official", SourceState: "ok", Status: "verified"})
	if err != nil {
		t.Fatal(err)
	}
	if st, body, _ = e.do(t, "GET", "/since/2026-01?libs=pypi:machinelib", "", nil); st != 200 || !strings.Contains(body, rid+" verified release pypi:machinelib 1.0.9") {
		t.Fatalf("since with machine release: %d %s", st, body)
	}
}

func TestApiDigestGrammarAndSetDiff(t *testing.T) {
	good := "cls Client\nfn connect host:str port:int\nfn send payload\ntype Options"
	if _, err := ValidateAPIBody(good); err != nil {
		t.Fatalf("valid body refused: %v", err)
	}
	for name, bad := range map[string]string{
		"unknown kind": "func connect",
		"unsorted":     "fn send\nfn connect",
		"duplicate":    "fn connect\nfn connect again",
		"kind order":   "fn connect\ncls Client",
		"bad chars":    "fn (connect)",
		"empty":        "",
		"too long":     strings.Repeat("fn a\n", 401),
	} {
		if _, err := ValidateAPIBody(bad); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
	d := SetDiff("cls Client\nfn connect host:str\nfn send payload\ntype Options", "cls Client\nfn connect host:str port:int\nfn stream payload\ntype Options")
	if strings.Join(d.Removed, ",") != "fn send" || strings.Join(d.Added, ",") != "fn stream" || strings.Join(d.Changed, ",") != "fn connect" {
		t.Fatalf("SetDiff = %+v", d)
	}
	e := newEnv(t)
	_, tok := e.registerL(t, "api-author", 1)
	st, body, _ := e.do(t, "POST", "/v1/dg", tok, map[string]any{"lib": "npm:apilib", "topic": "api", "v_to": "1.0.0", "body": "fn send\nfn connect"})
	if st != 400 || !strings.Contains(body, "sorted") {
		t.Fatalf("unsorted api digest: %d %s", st, body)
	}
	st, body, _ = e.do(t, "POST", "/v1/dg", tok, map[string]any{"lib": "npm:apilib", "topic": "api", "v_to": "1.0.0", "body": "cls Client\nfn connect host:str\nfn send payload\ntype Options"})
	if st != 201 || !strings.Contains(first(body), "tok=48") {
		t.Fatalf("api digest 1.0.0: %d %s (tokens_est = lines x 12)", st, body)
	}
	st, body, _ = e.do(t, "POST", "/v1/dg", tok, map[string]any{"lib": "npm:apilib", "topic": "api", "v_from": "1.0.0", "v_to": "2.0.0", "body": "cls Client\nfn connect host:str port:int\nfn stream payload\ntype Options"})
	if st != 201 {
		t.Fatalf("api digest 2.0.0: %d %s", st, body)
	}
	st, body, _ = e.do(t, "GET", "/dg/npm%3Aapilib/1.0.0..2.0.0/api", "", nil)
	if st != 200 || first(body) != "api npm:apilib 1.0.0..2.0.0 removed=1 added=1 changed=1" {
		t.Fatalf("api diff page: %d %s", st, body)
	}
	if !strings.Contains(body, "removed: fn send") || !strings.Contains(body, "added: fn stream") || !strings.Contains(body, "changed: fn connect") {
		t.Fatalf("api diff groups: %s", body)
	}
	// brk{} appends the api line when a pair exists
	e.claim(t, tok, map[string]any{"lib": "npm:apilib", "kind": "breaking", "v_from": "1.0.0", "v_to": "2.0.0", "title": "apilib 2 replaces send with stream", "source_url": "https://blog.example.net/apilib-2"})
	st, body, _ = e.do(t, "GET", "/v/npm%3Aapilib/1.0.0..2.0.0?kind=breaking", "", nil)
	if st != 200 || !strings.Contains(body, "\napi: 1 removed (1 added, 1 changed)") {
		t.Fatalf("brk api line: %d %s", st, body)
	}
	out, err := Ops(e.d)["apidiff"](context.Background(), nil, []byte(`{"lib":"npm:apilib","from":"1.0.0","to":"2.0.0"}`))
	if err != nil || !strings.HasPrefix(out, "api npm:apilib 1.0.0..2.0.0 removed=1") {
		t.Fatalf("apidiff op: %q %v", out, err)
	}
}

func TestApiDigestAutoConfirmDistinct(t *testing.T) {
	e := newEnv(t)
	a, atok := e.registerL(t, "autoconf-one", 1)
	b, btok := e.registerL(t, "autoconf-two", 1)
	body := "cls Pool\nfn acquire\nfn release conn"
	st, out, _ := e.do(t, "POST", "/v1/dg", atok, map[string]any{"lib": "go:github.com/acme/pool", "topic": "api", "v_to": "0.3.0", "body": body})
	if st != 201 {
		t.Fatalf("first: %d %s", st, out)
	}
	id := strings.Fields(out)[1]
	// the same author again is a plain dup
	if st, out, _ = e.do(t, "POST", "/v1/dg", atok, map[string]any{"lib": "go:github.com/acme/pool", "topic": "api", "v_to": "0.3.0", "body": body}); st != 409 {
		t.Fatalf("same author dup: %d %s", st, out)
	}
	repA, repB := queryInt(t, `SELECT rep FROM identities WHERE id = $1`, a), queryInt(t, `SELECT rep FROM identities WHERE id = $1`, b)
	st, out, _ = e.do(t, "POST", "/v1/dg", btok, map[string]any{"lib": "go:github.com/acme/pool", "topic": "api", "v_to": "0.3.0", "body": body})
	if st != 201 || !strings.HasPrefix(first(out), "ok "+id+" tok=36 confirmed (identical independent digest)") {
		t.Fatalf("distinct author identical digest: %d %s", st, out)
	}
	if n := queryInt(t, `SELECT count(*) FROM digest_votes WHERE digest_id = $1 AND root = $2 AND up`, id, b); n != 1 {
		t.Fatalf("auto ok votes = %d", n)
	}
	if w := queryStr(t, `SELECT ok_w::text FROM digests WHERE id = $1`, id); w == "0" {
		t.Fatal("ok_w must move")
	}
	if queryInt(t, `SELECT rep FROM identities WHERE id = $1`, a) != repA || queryInt(t, `SELECT rep FROM identities WHERE id = $1`, b) != repB {
		t.Fatal("auto-confirm must not give rep")
	}
	// a non-distinct author (same /24 as a) is a dup, not a confirmation
	regIP := queryStr(t, `SELECT reg_ip FROM identities WHERE id = $1`, a)
	_, ctok := e.registerIP(t, "autoconf-three", strings.TrimSuffix(regIP, ".7")+".77")
	if st, out, _ = e.do(t, "POST", "/v1/dg", ctok, map[string]any{"lib": "go:github.com/acme/pool", "topic": "api", "v_to": "0.3.0", "body": body}); st != 409 {
		t.Fatalf("same-network author: %d %s", st, out)
	}
}
