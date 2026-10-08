// Package compat replays recorded v1 sessions (the SPEC.md examples as the cx CLI, raw HTTP and
// MCP tools/call issue them) against the v2 server and checks them under the SPEC-v2 section 0
// rules: v1 text lines are prefix-stable (compared up to the last v1 field, in order; appended
// fields and appended lines are ignored), documents carry at most one trailing `next:` line,
// raw-body replies are byte-identical with no tail, v1 JSON only gains fields, MCP results omit
// `next` on success, and a v1 donor (no `caps`) never receives a pinned module.
//
// Fixtures live in fixtures/*.txt (grammar in replay_test.go). COMPAT_STRICT=1 removes the
// prefix logic (whole-line / exact-key comparison): the suite then fails, as documented by
// TestNegativePrefixLogicRemoved.
package compat

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/mcp"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
	"ekaii.fr/commons/internal/web"
)

var testPool *pgxpool.Pool

const adminToken = "adm-compat-token"

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("compat", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping compat tests")
		os.Exit(0)
	}
	core.LevelFn = trust.LevelOf // the gateway's seam: compute and the catalog read the submitter's level
	// A reused database may hold leftovers of an interrupted run: queued replicas would be leased
	// by this run's donors and a persisted freeze would refuse its writes.
	testPool.Exec(ctx, `WITH j AS (UPDATE jobs SET status = 'failed', reason = 'test-cleanup', finished_at = now()
		WHERE status IN ('queued','running') RETURNING id) DELETE FROM replicas WHERE job IN (SELECT id FROM j) AND state <> 'reported'`)
	testPool.Exec(ctx, `DELETE FROM flags WHERE k LIKE 'freeze:%'`)
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// env is one booted gateway: core (+AuthV2/AdminV2), kb, forge (Postgres only), compute, the
// catalog, mcp and web on the package database, plus the fixture variables.
type env struct {
	t      *testing.T
	d      *core.Deps
	srv    *httptest.Server
	cfg    core.Config
	client *http.Client
	strict bool // COMPAT_STRICT: whole-line / exact-key comparison (the negative check)

	vars  map[string]string // $name text variables
	bins  map[string][]byte // binary variables (>var, |var, ! sha256 $name)
	roots []string          // roots joined by this env, purged at cleanup (re-runs on one database)

	donorMu     sync.Mutex
	donorCancel context.CancelFunc
	donorWG     sync.WaitGroup
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("compat-secret-0123456789"), AdminToken: adminToken, PowBits: 6, PowBitsW: 6, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20, AbuseContact: "abuse@example.invalid", LicenseContent: "CC0-1.0"}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAuthV2(mux, d)
	core.RegisterAdminV2(mux, d)
	kb.Register(mux, d)
	forge.Register(mux, d)
	compute.Register(mux, d)
	catalog.Register(mux, d)
	mcp.Register(mux, d)
	web.Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	e := &env{t: t, d: d, srv: srv, cfg: cfg, client: &http.Client{Timeout: 90 * time.Second}, vars: map[string]string{}, bins: map[string][]byte{}}
	t.Cleanup(func() {
		e.stopDonors()
		e.purgeRoots()
		srv.Close()
		d.Close()
	})
	return e
}

// purgeRoots removes everything the fixture's roots wrote through the v1 admin route (tokens,
// KB rows, notes, blobs, jobs, tasks), so a later run on the same database never trips the KB
// duplicate check or leases a leftover replica.
func (e *env) purgeRoots() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, root := range e.roots {
		body, _ := json.Marshal(map[string]string{"id": root})
		if r, err := e.send(ctx, "POST", "/admin/purge", e.cfg.AdminToken, "", body, jsonCT); err != nil || r.status != 200 {
			e.t.Logf("purge %s: %v %+v", root, err, r)
		}
	}
}

// randIP hands every anonymous request its own address in its own /24: the per-IP limiter and
// the registration caps never shape a replay, and trust.Distinct sees distinct networks.
func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], 1+int(b[2])%250)
}

type reply struct {
	status int
	header http.Header
	body   []byte
}

// send performs one request; an empty ip picks a fresh random address.
func (e *env) send(ctx context.Context, method, path, token, ip string, body []byte, hdr map[string]string) (*reply, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, e.srv.URL+path, rd)
	if err != nil {
		return nil, err
	}
	if ip == "" {
		ip = randIP()
	}
	req.Header.Set("CF-Connecting-IP", ip)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return &reply{status: res.StatusCode, header: res.Header, body: b}, nil
}

var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

func kvMap(s string) map[string]string {
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(s, -1) {
		if _, dup := m[x[1]]; !dup {
			m[x[1]] = x[2]
		}
	}
	return m
}

var jsonCT = map[string]string{"Content-Type": "application/json"}

// join registers a root the way a v1 agent does (challenge, PoW, register) and binds $name (id)
// and $tok_name (token).
func (e *env) join(name string) error {
	ctx := context.Background()
	ip := randIP()
	r, err := e.send(ctx, "POST", "/v1/challenge", "", ip, nil, nil)
	if err != nil {
		return err
	}
	if r.status != 200 {
		return fmt.Errorf("join %s: challenge %d %s", name, r.status, r.body)
	}
	m := kvMap(string(r.body))
	bits := e.cfg.PowBits
	if b, err := strconv.Atoi(m["bits"]); err == nil && b > 0 {
		bits = b
	}
	body, _ := json.Marshal(map[string]string{"c": m["c"], "nonce": pow.Solve(m["c"], bits), "name": "compat-" + name})
	r, err = e.send(ctx, "POST", "/v1/register", "", ip, body, jsonCT)
	if err != nil {
		return err
	}
	if r.status != 201 {
		return fmt.Errorf("join %s: register %d %s", name, r.status, r.body)
	}
	m = kvMap(strings.SplitN(string(r.body), "\n", 2)[0])
	if !core.ValidID(m["id"]) || !strings.HasPrefix(m["token"], "cx_") {
		return fmt.Errorf("join %s: bad register reply %q", name, r.body)
	}
	e.vars[name], e.vars["tok_"+name] = m["id"], m["token"]
	e.roots = append(e.roots, m["id"])
	return nil
}

// startDonors runs one v1 echo donor per token (lease, download input, upload it unchanged as the
// output, report ok) until stopDonors. They serve the catalog's KAT jobs and service calls.
func (e *env) startDonors(toks []string) {
	e.stopDonors()
	ctx, cancel := context.WithCancel(context.Background())
	e.donorMu.Lock()
	e.donorCancel = cancel
	e.donorMu.Unlock()
	for _, tok := range toks {
		e.donorWG.Add(1)
		go func(tok string) {
			defer e.donorWG.Done()
			e.donorLoop(ctx, tok)
		}(tok)
	}
}

func (e *env) stopDonors() {
	e.donorMu.Lock()
	cancel := e.donorCancel
	e.donorCancel = nil
	e.donorMu.Unlock()
	if cancel != nil {
		cancel()
		e.donorWG.Wait()
	}
}

func (e *env) donorLoop(ctx context.Context, tok string) {
	ip := randIP()
	for ctx.Err() == nil {
		r, err := e.send(ctx, "POST", "/v1/w/lease?wait=2", tok, ip, []byte(`{"max_ms":30000,"max_mb":256}`), jsonCT)
		if err != nil {
			return
		}
		if r.status != 200 {
			if r.status != 204 {
				time.Sleep(200 * time.Millisecond)
			}
			continue
		}
		var l struct{ Lease, Job, Wasm, In string }
		if json.Unmarshal(r.body, &l) != nil || l.Lease == "" {
			continue
		}
		lease := map[string]string{"X-Lease": l.Lease}
		in, err := e.send(ctx, "GET", "/v1/b/"+l.In, tok, ip, nil, lease)
		if err != nil || in.status != 200 {
			continue
		}
		up, err := e.send(ctx, "POST", "/v1/b", tok, ip, in.body, map[string]string{"Content-Type": "application/octet-stream", "X-Lease": l.Lease})
		if err != nil || up.status != 200 {
			continue
		}
		f := strings.Fields(string(up.body))
		if len(f) == 0 {
			continue
		}
		done, _ := json.Marshal(map[string]any{"lease": l.Lease, "status": "ok", "out": f[0], "code": 0, "ms": 50})
		e.send(ctx, "POST", "/v1/w/done", tok, ip, done, jsonCT)
	}
}

// minWasm is a valid core module exporting an empty _start (no imports, no memory); the tag
// lands in a custom section so every fixture gets a distinct hash.
func minWasm(tag string) []byte {
	b := []byte{0, 'a', 's', 'm', 1, 0, 0, 0,
		1, 4, 1, 0x60, 0, 0, // type 0: () -> ()
		3, 2, 1, 0, // func 0: type 0
		7, 10, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0, // export "_start" = func 0
		10, 4, 1, 2, 0, 0x0b} // code: one body, no locals, end
	return append(b, customSection("t", tag)...)
}

// bigWasm is minWasm padded with a custom section so the module is at least size bytes
// (above the 4 MiB unpinned limit when asked).
func bigWasm(tag string, size int) []byte {
	b := minWasm(tag)
	if pad := size - len(b); pad > 0 {
		b = append(b, customSection("pad", strings.Repeat("x", pad))...)
	}
	return b
}

func customSection(name, payload string) []byte {
	body := append(uleb(len(name)), name...)
	body = append(body, payload...)
	out := append([]byte{0}, uleb(len(body))...)
	return append(out, body...)
}

func uleb(n int) []byte {
	var out []byte
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, c|0x80)
			continue
		}
		return append(out, c)
	}
}
