package mem

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
)

func TestKVCasFenceTTL(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t)
	st, b, _ := e.do(t, "PUT", "/v1/kv/me/x", tok, "a")
	want(t, st, b, 201, "ok ver=1 exp=")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/x?cas=1", tok, "b")
	want(t, st, b, 200, "ok ver=2")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/x?cas=wrong", tok, "c")
	want(t, st, b, 409, "err cas ver=2")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/x?cas=1", tok, "c")
	want(t, st, b, 409, "err cas ver=2")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/x?if_absent=1", tok, "c")
	want(t, st, b, 409, "err cas ver=2")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/y?if_absent=1", tok, "fresh")
	want(t, st, b, 201, "ok ver=1")
	st, b, _ = e.do(t, "GET", "/v1/kv/me/x", tok, "")
	want(t, st, b, 200, "ver=2 fence=0 exp=", "v: b", "next: PUT /v1/kv/a:"+root+"/x")
	st, b, _ = e.do(t, "DELETE", "/v1/kv/me/x?cas=1", tok, "")
	want(t, st, b, 409, "err cas ver=2")
	st, b, _ = e.do(t, "DELETE", "/v1/kv/me/x?cas=2", tok, "")
	want(t, st, b, 200, "ok")
	st, b, _ = e.do(t, "GET", "/v1/kv/me/x", tok, "")
	want(t, st, b, 404, "err notfound")
	// TTL
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/t?ttl=1", tok, "short")
	want(t, st, b, 201)
	st, b, _ = e.do(t, "GET", "/v1/kv/me/t", tok, "")
	want(t, st, b, 200, "ttl_s=")
	time.Sleep(1100 * time.Millisecond)
	st, b, _ = e.do(t, "GET", "/v1/kv/me/t", tok, "")
	want(t, st, b, 404)
	if err := KVExpire(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	if n := count(t, `SELECT count(*) FROM kv WHERE ns = $1 AND k = 't'`, "a:"+root); n != 0 {
		t.Fatal("expired row survived the janitor")
	}
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/t?ttl=0", tok, "x")
	want(t, st, b, 400, "err bad ttl")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/t?ttl=99999999", tok, "x")
	want(t, st, b, 400, "err bad ttl")
	// a rewrite of an expired key restarts its version
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/t?ttl=1", tok, "x")
	want(t, st, b, 201, "ok ver=1")
	// fences on the stored row: lower or omitted fences are refused
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/f?fence=5", tok, "v")
	want(t, st, b, 201)
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/f", tok, "v2")
	want(t, st, b, 409, "err fenced 5")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/f?fence=3", tok, "v2")
	want(t, st, b, 409, "err fenced 5")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/f?fence=6", tok, "v2")
	want(t, st, b, 200, "ok ver=2")
	st, b, _ = e.do(t, "GET", "/v1/kv/me/f", tok, "")
	want(t, st, b, 200, "ver=2 fence=6")
	// g: writes go through FenceCheckFn: unset refuses, the stub decides both ways
	g := uniq()
	st, b, _ = e.do(t, "PUT", "/v1/kv/g:"+g+"/x", tok, "pub")
	want(t, st, b, 409, "err fenced lock g:kv."+g)
	var got []string
	FenceCheckFn = func(_ context.Context, _ core.Q, name string, fence int64) error {
		got = append(got, fmt.Sprintf("%s:%d", name, fence))
		if fence == 7 {
			return nil
		}
		return core.E(409, "fenced", strconv.FormatInt(fence, 10)+" below current")
	}
	t.Cleanup(func() { FenceCheckFn = nil })
	st, b, _ = e.do(t, "PUT", "/v1/kv/g:"+g+"/x?fence=3", tok, "pub")
	want(t, st, b, 409, "err fenced 3 below current")
	st, b, _ = e.do(t, "PUT", "/v1/kv/g:"+g+"/x?fence=7", tok, "pub")
	want(t, st, b, 201, "ok ver=1")
	if len(got) != 2 || got[0] != "g:kv."+g+":3" || got[1] != "g:kv."+g+":7" {
		t.Fatalf("fence checks: %v", got)
	}
	st, b, _ = e.do(t, "DELETE", "/v1/kv/g:"+g+"/x", tok, "")
	want(t, st, b, 409, "err fenced")
	st, b, _ = e.do(t, "DELETE", "/v1/kv/g:"+g+"/x?fence=7", tok, "")
	want(t, st, b, 200, "ok")
	st, b, _ = e.do(t, "PUT", "/v1/kv/g:"+g+"/x?fence=7", "", "anon")
	want(t, st, b, 401, "err auth")
	// size cap and key grammar
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/big", tok, strings.Repeat("x", MaxKVValue+1))
	want(t, st, b, 413, "err size")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/bad%20key", tok, "x")
	want(t, st, b, 400, "err bad key")
}

func TestKVNamespacesAndPublicRead(t *testing.T) {
	e := newEnv(t)
	allowFence(t)
	root, tok := mkRoot(t)
	_, other := mkRoot(t)
	g := "g:" + uniq()
	st, b, _ := e.do(t, "PUT", "/v1/kv/"+g+"/x", tok, "pub-val")
	want(t, st, b, 201)
	st, b, h := e.do(t, "GET", "/v1/kv/"+g+"/x", "", "")
	want(t, st, b, 200, "ver=1 fence=0", "v: pub-val")
	if cc := h.Get("Cache-Control"); !strings.Contains(cc, "public") || !strings.Contains(cc, "max-age=5") {
		t.Fatalf("public read Cache-Control %q", cc)
	}
	st, b, h = e.do(t, "GET", "/v1/kv/"+g+"/x", tok, "")
	want(t, st, b, 200, "pub-val")
	if cc := h.Get("Cache-Control"); !strings.Contains(cc, "private") {
		t.Fatalf("token read Cache-Control %q", cc)
	}
	st, b, h = e.do(t, "GET", "/v1/kv/"+g, "", "")
	want(t, st, b, 200, "kv "+g+" n=1", "x 1 ")
	if cc := h.Get("Cache-Control"); !strings.Contains(cc, "max-age=5") {
		t.Fatalf("public list Cache-Control %q", cc)
	}
	st, b, h = e.do(t, "GET", "/v1/kv/"+g+"?vals=1", "", "")
	want(t, st, b, 200, "kv "+g+" n=1 vals=1", "x 1 ", "\n  pub-val")
	if cc := h.Get("Cache-Control"); cc != publicKVCache {
		t.Fatalf("public inline list Cache-Control %q", cc)
	}
	st, b, _ = e.do(t, "GET", "/v1/kv/me/x", "", "")
	want(t, st, b, 401, "err auth")
	st, b, _ = e.do(t, "GET", "/v1/kv/a:"+root+"/x", "", "")
	want(t, st, b, 401, "err auth")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/y", tok, "mine")
	want(t, st, b, 201)
	st, b, _ = e.do(t, "GET", "/v1/kv/a:"+root+"/y", tok, "")
	want(t, st, b, 200, "mine")
	st, b, _ = e.do(t, "GET", "/v1/kv/a:"+root+"/y", other, "")
	want(t, st, b, 403, "err auth forbidden")
	st, b, _ = e.do(t, "PUT", "/v1/kv/a:"+root+"/y", other, "theirs")
	want(t, st, b, 403, "err auth forbidden")
	st, b, _ = e.do(t, "GET", "/v1/kv/me?prefix=y", tok, "")
	want(t, st, b, 200, "kv a:"+root+" n=1 prefix=y", "y 1 ")
	st, b, _ = e.do(t, "GET", "/v1/kv/bogus/x", tok, "")
	want(t, st, b, 400, "err bad namespace")
	st, b, _ = e.do(t, "GET", "/v1/kv/a:nope/x", tok, "")
	want(t, st, b, 400, "err bad namespace")
	// space namespaces need the membership seam
	team := uniq()
	st, b, _ = e.do(t, "PUT", "/v1/kv/s:"+team+"/x", tok, "v")
	want(t, st, b, 403, "err auth space members only")
	MemberFn = func(_ context.Context, _ core.Q, slug, r string) (bool, error) {
		return slug == team && r == root, nil
	}
	t.Cleanup(func() { MemberFn = nil })
	st, b, _ = e.do(t, "PUT", "/v1/kv/s:"+team+"/x", tok, "v")
	want(t, st, b, 201)
	st, b, _ = e.do(t, "GET", "/v1/kv/s:"+team+"/x", other, "")
	want(t, st, b, 403, "err auth space members only")
	st, b, _ = e.do(t, "GET", "/v1/kv/s:"+team+"/x", "", "")
	want(t, st, b, 401)
	st, b, _ = e.do(t, "PUT", "/v1/kv/x:abcdefg/x", tok, "v")
	want(t, st, b, 403, "err auth rendezvous peers only")
	// scoped tokens: kv:r reads, kv:<ns-glob> writes
	_, ro := mkSub(t, root, []string{"kv:r"})
	st, b, _ = e.do(t, "GET", "/v1/kv/me/y", ro, "")
	want(t, st, b, 200, "mine")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/y", ro, "no")
	want(t, st, b, 403, "err scope kv:a:"+root)
	_, rw := mkSub(t, root, []string{"kv:a:*"})
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/y", rw, "yes")
	want(t, st, b, 200, "ok ver=2")
	st, b, _ = e.do(t, "PUT", "/v1/kv/"+g+"/x", rw, "no")
	want(t, st, b, 403, "err scope kv:"+g)
	// hidden rows answer gone and leave the listing
	if err := kvHide(context.Background(), pool, g+"/x"); err != nil {
		t.Fatal(err)
	}
	st, b, _ = e.do(t, "GET", "/v1/kv/"+g+"/x", "", "")
	want(t, st, b, 410, "err gone")
	st, b, _ = e.do(t, "GET", "/v1/kv/"+g, "", "")
	want(t, st, b, 200, "n=0")
}

func TestKVIncrRoute(t *testing.T) {
	e := newEnv(t)
	_, tok := mkRoot(t)
	var wg sync.WaitGroup
	errs := make(chan string, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, b, _, err := e.req("POST", "/v1/kvincr/me/counter", tok, `{"by":1}`, "Content-Type", "application/json")
			if err != nil || st != 200 {
				errs <- fmt.Sprintf("%d %s %v", st, b, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	st, b, _ := e.do(t, "GET", "/v1/kv/me/counter", tok, "")
	want(t, st, b, 200, "ver=20 ", "v: 20")
	st, b, _ = e.do(t, "POST", "/v1/kvincr/me/counter", tok, `{"by":-5}`, "Content-Type", "application/json")
	want(t, st, b, 200, "ok ver=21 v=15")
	st, b, _ = e.do(t, "POST", "/v1/kvincr/me/counter", tok, "", "Content-Type", "application/json")
	want(t, st, b, 200, "v=16")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/str", tok, "abc")
	want(t, st, b, 201)
	st, b, _ = e.do(t, "POST", "/v1/kvincr/me/str", tok, `{"by":1}`, "Content-Type", "application/json")
	want(t, st, b, 400, "err bad not a counter")
	st, b, _ = e.do(t, "POST", "/v1/kvincr/me/counter", tok, `{"by":1,"ttl":99999999}`, "Content-Type", "application/json")
	want(t, st, b, 400, "err bad ttl")
	st, b, _ = e.do(t, "POST", "/v1/kvincr/me/counter", "", `{"by":1}`, "Content-Type", "application/json")
	want(t, st, b, 401)
}

func TestKVQuotaAdvisoryLockByLevel(t *testing.T) {
	e := newEnv(t)
	capOverride(t, "kv_keys", [4]int{3, 5, 5, 5})
	capOverride(t, "kv_bytes", [4]int{100, 1000, 1000, 1000})
	root, tok := mkRoot(t)
	for _, k := range []string{"k1", "k2", "k3"} {
		st, b, _ := e.do(t, "PUT", "/v1/kv/me/"+k, tok, "v")
		want(t, st, b, 201)
	}
	st, b, _ := e.do(t, "PUT", "/v1/kv/me/k4", tok, "v")
	want(t, st, b, 429, "err quota")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/k1", tok, "rewrite ok")
	want(t, st, b, 200)
	setLevel(root, 1)
	for _, k := range []string{"k4", "k5"} {
		st, b, _ := e.do(t, "PUT", "/v1/kv/me/"+k, tok, "v")
		want(t, st, b, 201)
	}
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/k6", tok, "v")
	want(t, st, b, 429, "err quota")
	// bytes (L0 100 live in the own namespace)
	_, btok := mkRoot(t)
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/b1", btok, strings.Repeat("a", 60))
	want(t, st, b, 201)
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/b2", btok, strings.Repeat("b", 60))
	want(t, st, b, 429, "err quota")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/b1", btok, strings.Repeat("a", 90))
	want(t, st, b, 200)
	// the per-root advisory lock keeps the count exact under concurrent creates
	_, ctok := mkRoot(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	okN, quotaN := 0, 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, b, _, err := e.req("PUT", fmt.Sprintf("/v1/kv/me/c%d", i), ctok, "v")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				t.Errorf("request: %v", err)
			case st == 201:
				okN++
			case st == 429:
				quotaN++
			default:
				t.Errorf("unexpected %d %s", st, b)
			}
		}(i)
	}
	wg.Wait()
	if okN != 3 || quotaN != 7 {
		t.Fatalf("concurrent creates: ok=%d quota=%d", okN, quotaN)
	}
	// shared namespaces use the namespace caps, not the root's
	allowFence(t)
	old := SharedKeys
	SharedKeys = 2
	t.Cleanup(func() { SharedKeys = old })
	g := "g:" + uniq()
	for _, k := range []string{"s1", "s2"} {
		st, b, _ := e.do(t, "PUT", "/v1/kv/"+g+"/"+k, tok, "v")
		want(t, st, b, 201)
	}
	st, b, _ = e.do(t, "PUT", "/v1/kv/"+g+"/s3", tok, "v")
	want(t, st, b, 429, "err quota")
}

func TestKVBatchAtomicAndCosts(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t)
	_, _, h := e.do(t, "GET", "/v1/kv/me", tok, "")
	before := remaining(t, h)
	body := `{"ns":"me","ops":[{"op":"put","k":"a","v":"1"},{"op":"put","k":"b","v":"2"},{"op":"get","k":"a"},{"op":"incr","k":"n","by":5},{"op":"del","k":"b"},{"op":"get","k":"zz"},{"op":"get","k":"a"},{"op":"get","k":"a"}]}`
	st, b, _ := e.do(t, "POST", "/v1/kvm", tok, body, "Content-Type", "application/json")
	want(t, st, b, 200, "kvm a:"+root+" n=8 ok=8 failed=0", "a ok ver=1", "b ok ver=1", "a ver=1\n  1", "n ok ver=1 v=5", "b ok", "zz miss")
	_, _, h = e.do(t, "GET", "/v1/kv/me", tok, "")
	after := remaining(t, h)
	// the batch costs 4 writes + 4 gets x 0.2 = 4.8 tokens (plus 1 for the second list), so the
	// bucket dropped by at least 4 between the two list replies
	if d := before - after; d < 4 {
		t.Fatalf("batch charged %d tokens (before %d, after %d), want >= 4", d, before, after)
	}
	if c := batchCost([]kvOp{{Op: "get"}, {Op: "get"}, {Op: "put"}, {Op: "incr"}, {Op: "del"}}); c < 3.39 || c > 3.41 {
		t.Fatalf("batchCost %v", c)
	}
	st, b, _ = e.do(t, "POST", "/v1/kvm", tok, `{"ns":"me","ops":[{"op":"put","k":"a","v":"x","cas":9},{"op":"put","k":"c","v":"3"}]}`, "Content-Type", "application/json")
	want(t, st, b, 200, "ok=1 failed=1", "a cas ver=1", "c ok ver=1")
	st, b, _ = e.do(t, "POST", "/v1/kvm", tok, `{"ns":"me","atomic":true,"ops":[{"op":"put","k":"d","v":"1"},{"op":"put","k":"a","v":"x","cas":9}]}`, "Content-Type", "application/json")
	want(t, st, b, 409, "failed=2", "rolled back")
	st, b, _ = e.do(t, "GET", "/v1/kv/me/d", tok, "")
	want(t, st, b, 404)
	st, b, _ = e.do(t, "GET", "/v1/kv/me/a", tok, "")
	want(t, st, b, 200, "v: 1")
	ops := make([]string, 101)
	for i := range ops {
		ops[i] = fmt.Sprintf(`{"op":"get","k":"k%d"}`, i)
	}
	st, b, _ = e.do(t, "POST", "/v1/kvm", tok, `{"ns":"me","ops":[`+strings.Join(ops, ",")+`]}`, "Content-Type", "application/json")
	want(t, st, b, 400, "err bad ops must hold 1..100")
	st, b, _ = e.do(t, "POST", "/v1/kvm", tok, `{"ns":"me","ops":[{"op":"zap","k":"a"}]}`, "Content-Type", "application/json")
	want(t, st, b, 400, "err bad op must be")
	st, b, _ = e.do(t, "POST", "/v1/kvm", tok, `{"ns":"me","ops":[{"op":"put","k":"a","v":"AKIAZQ3X7V2M9KPL4RT8 secret"}]}`, "Content-Type", "application/json")
	want(t, st, b, 400, "err scrub")
	_, ro := mkSub(t, root, []string{"kv:r"})
	st, b, _ = e.do(t, "POST", "/v1/kvm", tok, `{"ns":"me","ops":[{"op":"get","k":"a"}]}`, "Content-Type", "application/json")
	want(t, st, b, 200, "ok=1")
	st, b, _ = e.do(t, "POST", "/v1/kvm", ro, `{"ns":"me","ops":[{"op":"put","k":"a","v":"1"}]}`, "Content-Type", "application/json")
	want(t, st, b, 403, "err scope")
}

var remainingRe = regexp.MustCompile(`remaining=(\d+)`)

func remaining(t *testing.T, h map[string][]string) int {
	t.Helper()
	m := remainingRe.FindStringSubmatch(strings.Join(h["Ratelimit"], ","))
	if m == nil {
		t.Fatalf("no RateLimit header: %v", h)
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func TestKVInlineListingBudget(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t)
	for i := 0; i < 10; i++ {
		st, b, _ := e.do(t, "PUT", fmt.Sprintf("/v1/kv/me/k%02d", i), tok, strings.Repeat("v", 200)+"\nline2")
		want(t, st, b, 201)
	}
	st, b, _ := e.do(t, "GET", "/v1/kv/me?vals=1", tok, "")
	want(t, st, b, 200, "kv a:"+root+" n=10 vals=1", "k00 1 ", "\n  "+strings.Repeat("v", 200)+"\n  line2\n", "k09 1 ")
	if n := strings.Count(b, "\nk0"); n != 10 {
		t.Fatalf("%d rows, want 10:\n%s", n, b)
	}
	st, b, _ = e.do(t, "GET", "/v1/kv/me?vals=1&b=150", tok, "")
	want(t, st, b, 200, "kv a:"+root+" n=10 vals=1", "k00 1 ", " more: /v1/kv/me?")
	if n := strings.Count(b, "\nk0"); n >= 10 {
		t.Fatalf("budget did not clip (%d rows):\n%s", n, b)
	}
	st, b, _ = e.do(t, "GET", "/v1/kv/me?vals=1&prefix=k0&k=3", tok, "")
	want(t, st, b, 200, "n=3")
	// a key that looks like a reserved line start is pushed off column 0
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/next:", tok, "x")
	want(t, st, b, 201)
	st, b, _ = e.do(t, "GET", "/v1/kv/me?vals=1&prefix=next", tok, "")
	want(t, st, b, 200, "\n- next: 1 ")
	st, b, _ = e.do(t, "GET", "/v1/kv/me?prefix=next", tok, "")
	want(t, st, b, 200, "\n- next: 1 ")
}

func TestKVImportFormats(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t)
	st, b, _ := e.do(t, "POST", "/v1/kv/me/import?fmt=kv", tok, "a\t1\nbad line without tab\nb\t2\n\n")
	want(t, st, b, 200, "ok imported=2 skipped=1")
	st, b, _ = e.do(t, "GET", "/v1/kv/me/a", tok, "")
	want(t, st, b, 200, "v: 1")
	st, b, _ = e.do(t, "POST", "/v1/kv/me/import?fmt=json&ttl=60", tok, `{"x":"1","y":2,"z":{"n":1},"w":null,"t":true}`, "Content-Type", "application/json")
	want(t, st, b, 200, "ok imported=3 skipped=2")
	st, b, _ = e.do(t, "GET", "/v1/kv/me/y", tok, "")
	want(t, st, b, 200, "v: 2")
	st, b, _ = e.do(t, "GET", "/v1/kv/me/t", tok, "")
	want(t, st, b, 200, "v: true")
	md := "intro text\n## Setup Notes\nline1\nline2\n\n## Other!\nz\n## Empty\n"
	st, b, _ = e.do(t, "POST", "/v1/kv/me/import?fmt=md", tok, md, "Content-Type", "text/markdown")
	want(t, st, b, 200, "ok imported=2 skipped=1")
	st, b, _ = e.do(t, "GET", "/v1/kv/me/md/setup-notes", tok, "")
	want(t, st, b, 200, "v: line1\n  line2")
	st, b, _ = e.do(t, "GET", "/v1/kv/me/md/other", tok, "")
	want(t, st, b, 200, "v: z")
	st, b, _ = e.do(t, "POST", "/v1/kv/me/import?fmt=bogus", tok, "a\t1")
	want(t, st, b, 400, "err bad fmt")
	st, b, _ = e.do(t, "POST", "/v1/kv/me/import?fmt=json", tok, "[1,2]", "Content-Type", "application/json")
	want(t, st, b, 400, "err bad json")
	st, b, _ = e.do(t, "GET", "/v1/kv/me", tok, "")
	want(t, st, b, 200, "kv a:"+root+" n=7")
	// quota stops an import and reports it
	capOverride(t, "kv_keys", [4]int{8, 8, 8, 8})
	st, b, _ = e.do(t, "POST", "/v1/kv/me/import?fmt=kv", tok, "p\t1\nq\t2\nr\t3\n")
	want(t, st, b, 200, "ok imported=1 skipped=0 stopped=quota")
}

func TestSealedValuesOpaqueNeverPublic(t *testing.T) {
	e := newEnv(t)
	allowFence(t)
	root, tok := mkRoot(t)
	nonce := randBytes(12)
	seal := func(n, ct []byte) string {
		return "seal1:" + base64.RawURLEncoding.EncodeToString(append(append([]byte{}, n...), ct...))
	}
	v1 := seal(nonce, randBytes(40))
	st, b, _ := e.do(t, "PUT", "/v1/kv/me/s", tok, v1)
	want(t, st, b, 201, "ok ver=1")
	wantNot(t, b, "masked")
	st, b, _ = e.do(t, "GET", "/v1/kv/me/s", tok, "")
	want(t, st, b, 200, "v: "+v1)
	st, b, _ = e.do(t, "GET", "/v1/kv/me", tok, "")
	want(t, st, b, 200, "s 1 ", "[sealed]")
	st, b, _ = e.do(t, "GET", "/v1/kv/me?vals=1", tok, "")
	want(t, st, b, 200, "s 1 ", "\n  [sealed]")
	wantNot(t, b, v1)
	// the owner's resume lists the key and renders its value [sealed]
	st, b, _ = e.do(t, "GET", "/v1/me/resume?kv=1", tok, "")
	want(t, st, b, 200, "kv: 1 keys", "s 1 ", "[sealed]")
	wantNot(t, b, v1)
	// nonce reuse is refused; a fresh nonce writes
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/s", tok, seal(nonce, randBytes(40)))
	want(t, st, b, 400, "err bad nonce reuse")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/s", tok, seal(randBytes(12), randBytes(40)))
	want(t, st, b, 200, "ok ver=2")
	// shared namespaces refuse sealed values
	st, b, _ = e.do(t, "PUT", "/v1/kv/g:"+uniq()+"/s", tok, v1)
	want(t, st, b, 400, "err bad sealed shared ns")
	// seal2 (stdlib recipe, 16-byte nonce)
	n2 := randBytes(16)
	v2 := "seal2:" + base64.RawURLEncoding.EncodeToString(append(append([]byte{}, n2...), randBytes(48)...))
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/s2", tok, v2)
	want(t, st, b, 201)
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/s2", tok, "seal2:"+base64.RawURLEncoding.EncodeToString(append(append([]byte{}, n2...), randBytes(48)...)))
	want(t, st, b, 400, "err bad nonce reuse")
	// counters never run on sealed values; a sealed value can replace a plain one
	st, b, _ = e.do(t, "POST", "/v1/kvincr/me/s", tok, `{"by":1}`, "Content-Type", "application/json")
	want(t, st, b, 400, "err bad sealed value is not a counter")
	// checkpoints: stored opaque, [sealed] in lists and resume, never public
	st, bb := cpPost(t, e, tok, map[string]any{"name": "sc", "body": v1})
	want(t, st, bb, 201)
	sealedCP := cpID(t, bb)
	st, bb = cpPost(t, e, tok, map[string]any{"name": "sc", "body": v1, "pub": true})
	want(t, st, bb, 400, "err bad sealed never public")
	st, b, _ = e.do(t, "GET", "/v1/cp/sc/list", tok, "")
	want(t, st, b, 200, " 1 ", "[sealed]")
	st, b, _ = e.do(t, "GET", "/v1/cp/sc", tok, "")
	want(t, st, b, 200, "[sealed]", "body: "+v1)
	st, b, _ = e.do(t, "GET", "/v1/me/resume?name=sc", tok, "")
	want(t, st, b, 200, "body: [sealed]")
	wantNot(t, b, v1)
	if _, _, _, ok := cpResolve(context.Background(), pool, sealedCP); ok {
		t.Fatal("sealed checkpoint resolved")
	}
	var sealedCol bool
	if err := pool.QueryRow(context.Background(), `SELECT sealed FROM kv WHERE ns = $1 AND k = 's'`, "a:"+root).Scan(&sealedCol); err != nil || !sealedCol {
		t.Fatalf("sealed flag: %v %v", sealedCol, err)
	}
	// export carries no sealed content
	var sb strings.Builder
	if err := e.d.Export(context.Background(), root, &sb); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sb.String(), v1) || !strings.Contains(sb.String(), `"sealed":true`) {
		t.Fatalf("export leaked a sealed value:\n%s", sb.String())
	}
}
