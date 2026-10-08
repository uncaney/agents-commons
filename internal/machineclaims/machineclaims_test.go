package machineclaims

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/know"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
)

var testPool *pgxpool.Pool

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
	} else if pool, done := testdb.Open("machineclaims", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping machineclaims DB tests")
		os.Exit(0)
	}
	core.LevelFn = trust.LevelOf
	core.RepLogger = trust.RecordRep
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// newDeps builds a Deps on the shared pool, wired like the integration package (Register sets the
// egress result handlers, the libmeta hook, the dispute pause and the janitors). Each test starts
// from clean machine tables so a reused database never leaks rows between tests.
func newDeps(t *testing.T) *core.Deps {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), DataDir: t.TempDir(),
		PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	ctx := context.Background()
	for _, sql := range []string{
		`TRUNCATE claims, claim_votes, libs, machine_state`,
		`DELETE FROM lib_alias WHERE NOT seeded`,
		`DELETE FROM egress_outbox WHERE kind IN ('osv', 'eol', 'libmeta')`,
	} {
		if _, err := testPool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	Register(http.NewServeMux(), d)
	return d
}

// --- helpers ------------------------------------------------------------------------------------

func seedLib(t *testing.T, d *core.Deps, key string, referenced bool, versions []know.Release) {
	t.Helper()
	vs, _ := json.Marshal(versions)
	if _, err := testPool.Exec(context.Background(),
		`INSERT INTO libs (key, versions, fetched_at, referenced) VALUES ($1, $2::jsonb, now(), $3)
		 ON CONFLICT (key) DO UPDATE SET versions = EXCLUDED.versions, fetched_at = now(), referenced = EXCLUDED.referenced`,
		key, string(vs), referenced); err != nil {
		t.Fatal(err)
	}
}

func claimRow(t *testing.T, d *core.Deps, lib, kind string) (id, vfrom, vto, title, srcURL, status, src, tier, state string) {
	t.Helper()
	err := testPool.QueryRow(context.Background(),
		`SELECT id, v_from, v_to, title, source_url, status, src, source_tier, source_state FROM claims WHERE lib = $1 AND kind = $2 ORDER BY created DESC LIMIT 1`,
		lib, kind).Scan(&id, &vfrom, &vto, &title, &srcURL, &status, &src, &tier, &state)
	if err != nil {
		t.Fatalf("no %s claim for %s: %v", kind, lib, err)
	}
	return
}

func countClaims(t *testing.T, d *core.Deps, lib, kind string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM claims WHERE lib = $1 AND kind = $2`, lib, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func countEgress(t *testing.T, kind string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM egress_outbox WHERE kind = $1 AND done_at IS NULL`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func ingest(t *testing.T, d *core.Deps, kind string, payload, result any) {
	t.Helper()
	pb, _ := json.Marshal(payload)
	rb, _ := json.Marshal(result)
	fn := IngestOSV
	if kind == "eol" {
		fn = IngestEOL
	}
	if err := fn(context.Background(), d, d.DB, pb, rb); err != nil {
		t.Fatalf("ingest %s: %v", kind, err)
	}
}
