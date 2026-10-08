package pay

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/testdb"
)

var (
	testPool *pgxpool.Pool
	levels   sync.Map // root -> level (core.LevelFn stub)
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	var cleanup func()
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("pay", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping pay DB tests")
		os.Exit(0)
	}
	core.LevelFn = func(ctx context.Context, q core.Q, root string) int {
		v, _ := levels.Load(root)
		n, _ := v.(int)
		return n
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	s   *svc
	srv *httptest.Server
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 4, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &tenv{d: d, s: svcFor(d), srv: srv}
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

func (e *tenv) do(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	return e.doIP(t, method, path, token, body, randIP())
}

func (e *tenv) doIP(t *testing.T, method, path, token, body, ip string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, _ := http.NewRequest(method, e.srv.URL+path, rd)
	r.Header.Set("CF-Connecting-IP", ip)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimRight(string(b), "\n")
}

// mkRoot inserts a root registered from ip (5 days old) with credits/earned and rep.
func mkRoot(t *testing.T, ip string, credits, earned int64, rep int) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, earned, reg_ip, rep, created, verified_noncompute)
		VALUES ($1, 'r', NULL, $1, $2, $3, $4, $5, $6, now() - interval '5 days', 1)`, id, h, credits, earned, ip, rep); err != nil {
		t.Fatal(err)
	}
	lvl := 0
	switch {
	case rep >= 5:
		lvl = 2
	case rep >= 1:
		lvl = 1
	}
	levels.Store(id, lvl)
	return id, tok
}

func bal(t *testing.T, id string) (credits, earned int64) {
	t.Helper()
	if err := testPool.QueryRow(context.Background(), `SELECT credits, earned FROM identities WHERE id = $1`, id).Scan(&credits, &earned); err != nil {
		t.Fatal(err)
	}
	return
}

func (e *tenv) row(t *testing.T, id string) *agreement {
	t.Helper()
	a, err := load(context.Background(), testPool, id, false)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func conserved(t *testing.T, e *tenv, step string) {
	t.Helper()
	a, err := core.LedgerAudit(context.Background(), testPool, e.d.EscrowSQL())
	if err != nil {
		t.Fatal(err)
	}
	if !a.OK() {
		t.Fatalf("%s: %s", step, a.Line())
	}
}

// mkAgreement opens an agreement from payer to payee and returns its id.
func (e *tenv) mkAgreement(t *testing.T, ptok, payee string, max, perCharge int64, ip string) string {
	t.Helper()
	st, body := e.doIP(t, "POST", "/v1/ag", ptok, fmt.Sprintf(`{"to":"%s","max":%d,"per_charge":%d,"ttl_h":24}`, payee, max, perCharge), ip)
	if st != 201 || !strings.HasPrefix(body, "ok y") {
		t.Fatalf("create agreement: %d %s", st, body)
	}
	return strings.Fields(body)[1]
}

// accept flips the offer open (payee token).
func (e *tenv) accept(t *testing.T, id, ptok, ip string) {
	t.Helper()
	st, body := e.doIP(t, "POST", "/v1/ag/"+id+"/accept", ptok, "", ip)
	if st != 200 {
		t.Fatalf("accept: %d %s", st, body)
	}
}
