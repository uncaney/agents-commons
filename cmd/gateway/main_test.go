package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/a2a"
	"ekaii.fr/commons/internal/auction"
	"ekaii.fr/commons/internal/cache"
	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/gov"
	"ekaii.fr/commons/internal/hooks"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/know"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/mem"
	"ekaii.fr/commons/internal/notary"
	"ekaii.fr/commons/internal/oauth"
	"ekaii.fr/commons/internal/ops"
	"ekaii.fr/commons/internal/pages"
	"ekaii.fr/commons/internal/review"
	"ekaii.fr/commons/internal/sem"
	"ekaii.fr/commons/internal/spaces"
	"ekaii.fr/commons/internal/swarm"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/tripwire"
	"ekaii.fr/commons/internal/web"
)

var (
	testPool *pgxpool.Pool
	testDeps *core.Deps
	testMux  *http.ServeMux
)

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
	} else if pool, done := testdb.Open("gateway", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL unset: skipping gateway DB tests")
		os.Exit(0)
	}

	cfg := core.Config{
		ServerSecret:   []byte("test-secret-0123456789abcdef"),
		PowBits:        6,
		PowBitsW:       6,
		DataDir:        mustTempDir(),
		TrustCF:        true,
		PublicURL:      "https://agents.ekaii.fr",
		InternalListen: ":0",
		RegPerHour:     1 << 20,
	}
	doc.Configure(&cfg)
	d, err := core.NewDeps(ctx, cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		panic(err)
	}
	testDeps = d
	testMux = http.NewServeMux()
	registerAll(testMux, d)
	setSeams(d)
	// run() installs this after building the handler; mirror it so the seam check sees it set.
	oauth.MCPHandler = buildHandler(d, testMux)

	code := m.Run()
	d.Close()
	cleanup()
	os.Exit(code)
}

func mustTempDir() string {
	p, err := os.MkdirTemp("", "gw")
	if err != nil {
		panic(err)
	}
	return p
}

// TestNoDegradedRegistrations runs the exact production registration sequence (buildRegistrations) on
// a FRESH mux with NO recover around each step, so a duplicate route pattern — which http.ServeMux
// panics on, and which registerAll otherwise swallows as a silently DEGRADED package at boot — fails
// the build here. This is the regression guard for the /v1/log, /v1/s/{slug}/upstream, /srchash.py and
// /status.json clashes: `go test ./cmd/gateway/` goes red on any future duplicate route pattern.
func TestNoDegradedRegistrations(t *testing.T) {
	if testDeps == nil {
		t.Skip("no TEST_DATABASE_URL: skipping gateway registration guard")
	}
	mux := http.NewServeMux()
	var o *ops.Ops
	for _, s := range buildRegistrations(mux, testDeps, &o) {
		func(reg registration) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("package %q failed to register (route conflict or panic) — DEGRADED in production: %v", reg.name, r)
				}
			}()
			reg.fn()
		}(s)
	}
}

// TestSeamsAllSet asserts every cross-package seam the integration wires (directly in setSeams or by
// a package's own Register) is non-nil after boot, so no write path silently falls through to a
// fail-closed default in production. Table-driven so a regression names the exact seam.
func TestSeamsAllSet(t *testing.T) {
	seams := []struct {
		name string
		set  bool
	}{
		// --- set directly by setSeams ---
		{"core.RepLogger", core.RepLogger != nil},
		{"core.LevelFn", core.LevelFn != nil},
		{"core.SysMailFn", core.SysMailFn != nil},
		{"core.BodyParserFn", core.BodyParserFn != nil},
		{"core.ChallengeIDFn", core.ChallengeIDFn != nil},
		{"core.RegisterBundleFn", core.RegisterBundleFn != nil},
		{"core.XPoWFn", core.XPoWFn != nil},
		{"kb.SavedHook", kb.SavedHook != nil},
		{"kb.ChangesFn", kb.ChangesFn != nil},
		{"kb.TagAliasFn", kb.TagAliasFn != nil},
		{"know.KBForLib", know.KBForLib != nil},
		{"compute.CacheJobFn", compute.CacheJobFn != nil},
		{"compute.OnDone", compute.OnDone != nil},
		{"mail.MemberFn", mail.MemberFn != nil},
		{"swarm.MemberFn", swarm.MemberFn != nil},
		{"mail.RoomFn", mail.RoomFn != nil},
		{"swarm.RoomFn", swarm.RoomFn != nil},
		{"mem.RoomFn", mem.RoomFn != nil},
		{"mem.MemberFn", mem.MemberFn != nil},
		{"mail.PolicyFn", mail.PolicyFn != nil},
		{"swarm.NotifyExpired", swarm.NotifyExpired != nil},
		{"mem.FenceCheckFn", mem.FenceCheckFn != nil},
		{"cache.CanonFn", cache.CanonFn != nil},
		{"pages.TagCanonFn", pages.TagCanonFn != nil},
		{"pages.KbNextFn", pages.KbNextFn != nil},
		{"web.HubsFn", web.HubsFn != nil},
		{"web.A2ACardFn", web.A2ACardFn != nil},
		{"notary.SkillsFn", notary.SkillsFn != nil},
		{"review.SkillsFn", review.SkillsFn != nil},
		{"sem.RelFn", sem.RelFn != nil},
		{"auction.RelFn", auction.RelFn != nil},
		{"auction.ExcludeFn", auction.ExcludeFn != nil},
		{"a2a.PendingFn", a2a.PendingFn != nil},
		{"a2a.PendingGetFn", a2a.PendingGetFn != nil},
		{"a2a.PushConfigFn", a2a.PushConfigFn != nil},
		{"hooks.FundFn", hooks.FundFn != nil},
		{"tripwire.PublishFn", tripwire.PublishFn != nil},
		{"oauth.MCPHandler", oauth.MCPHandler != nil},
		// --- self-wired by a provider's Register (must also be live after boot) ---
		{"core.AnonBitsFn", core.AnonBitsFn != nil},
		{"core.BotLaneFn", core.BotLaneFn != nil},
		{"core.ExportRemoveFn", core.ExportRemoveFn != nil},
		{"forge.TemplateCheck", forge.TemplateCheck != nil},
		{"forge.TaskExtra", forge.TaskExtra != nil},
		{"forge.ClaimLineFn", forge.ClaimLineFn != nil},
		{"review.RelFn", review.RelFn != nil},
		{"review.ExcludeFn", review.ExcludeFn != nil},
		{"kb.RelatedFn", kb.RelatedFn != nil},
		{"kb.FilledHook", kb.FilledHook != nil},
		{"web.CardSigFn", web.CardSigFn != nil},
		{"web.ProfileFn", web.ProfileFn != nil},
		// --- gov anti-capture seams (18.3 / 18.6): nil re-enables space governance with the
		// concentration brake and entry-facts quorum off (SECURITY-REVIEW-2 #8). ---
		{"gov.SpaceInfoFn", gov.SpaceInfoFn != nil},
		{"gov.SpaceStatsFn", gov.SpaceStatsFn != nil},
		{"gov.EligibleWeightFn", gov.EligibleWeightFn != nil},
		{"gov.KBStatsFn", gov.KBStatsFn != nil},
		{"spaces.ProposalCountsFn", spaces.ProposalCountsFn != nil},
	}
	for _, s := range seams {
		if !s.set {
			t.Errorf("seam %s is nil after boot (write paths will fail closed)", s.name)
		}
	}
}

// TestPlatformSpaceGovImmutable is the SECURITY-REVIEW-2 #3 regression: a vote-driven pin or doc
// proposal scoped to the platform roadmap space must never apply, even though the registered
// pin@space / doc@space appliers exist (#8). The system-root StewardPins route stays open and is
// covered in the spaces package.
func TestPlatformSpaceGovImmutable(t *testing.T) {
	if testDeps == nil {
		t.Skip("no TEST_DATABASE_URL: skipping platform-immutability guard")
	}
	ctx := context.Background()
	cases := []struct{ id, kind, target, patch string }{
		{"pplatfm", "pin", "pins", `{"pins":[]}`},
		{"pplatfd", "doc", "home", `{"text":"x"}`},
	}
	for _, c := range cases {
		if _, err := testPool.Exec(ctx, `INSERT INTO proposals (id, scope, kind, target, patch, author, author_root, closes_at, state)
			VALUES ($1, 'platform', $2, $3, $4::jsonb, 'aaaaaaa', 'aaaaaaa', now(), 'passed')
			ON CONFLICT (id) DO UPDATE SET state = 'passed', result = ''`, c.id, c.kind, c.target, c.patch); err != nil {
			t.Fatalf("%s seed: %v", c.kind, err)
		}
		p := &gov.Proposal{ID: c.id, Scope: "platform", Kind: c.kind, Target: c.target, Patch: json.RawMessage(c.patch), AuthorRoot: "aaaaaaa"}
		if err := core.Tx(ctx, testPool, func(tx pgx.Tx) error { return gov.Apply(ctx, tx, p) }); err != nil {
			t.Fatalf("%s apply: %v", c.kind, err)
		}
		var state, result string
		if err := testPool.QueryRow(ctx, `SELECT state, result FROM proposals WHERE id = $1`, c.id).Scan(&state, &result); err != nil {
			t.Fatal(err)
		}
		if state != "failed" || !strings.Contains(result, "not amendable") {
			t.Fatalf("%s: state=%q result=%q, want failed/not amendable", c.kind, state, result)
		}
	}
}

// TestMiddlewareOrder exercises the production pipeline (buildHandler): pathscrub is outermost, so a
// tier-1 secret in a scanned read path is refused before urltok (or anything inner) can inject a
// url token; and a url ?t= token is never honoured on a POST.
func TestMiddlewareOrder(t *testing.T) {
	var reached bool
	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	h := buildHandler(testDeps, terminal)

	// (a) pathscrub rejects a tier-1 cx_ token in a /q/ read path, before urltok.
	reached = false
	tok := "cx_" + strings.Repeat("a", 43)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/q/"+tok, nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("pathscrub: got %d, want 400 for a secret in the path", rec.Code)
	}
	if reached {
		t.Error("pathscrub let a tier-1 secret reach an inner handler (order wrong)")
	}

	// (b) a url token on a POST is refused by urltok (read-only capability), never reaching core.
	reached = false
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/kb?t="+tok, strings.NewReader("{}")))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("urltok: got %d, want 405 for a url token on a POST", rec.Code)
	}
	if reached {
		t.Error("a url token rode a POST to an inner handler")
	}
}

// TestOnDoneChainCallsAll checks the compute.OnDone combinator runs every handler in order and
// returns the first error while still invoking the handlers after it.
func TestOnDoneChainCallsAll(t *testing.T) {
	var order []int
	boom := errors.New("boom")
	mk := func(n int, err error) doneFn {
		return func(context.Context, core.Q, *compute.Job) error {
			order = append(order, n)
			return err
		}
	}
	chain := chainDone(mk(1, nil), mk(2, boom), mk(3, nil))
	err := chain(context.Background(), nil, nil)
	if !errors.Is(err, boom) {
		t.Fatalf("chain returned %v, want boom", err)
	}
	if len(order) != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3 {
		t.Fatalf("handlers ran in %v, want [1 2 3] (all, in order)", order)
	}
}

// TestFenceComposerByPrefix checks the fenced-write router dispatches by lock-name prefix: "sm:" to
// sem, "grp:" to grp, everything else to swarm.
func TestFenceComposerByPrefix(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"sm:permit.x", "sem"},
		{"grp:shard.y", "grp"},
		{"g:kv.notes", "swarm"},
		{"lock-plain", "swarm"},
	}
	for _, c := range cases {
		var got string
		routeFence(c.name,
			func() error { got = "sem"; return nil },
			func() error { got = "grp"; return nil },
			func() error { got = "swarm"; return nil })
		if got != c.want {
			t.Errorf("routeFence(%q) hit %s, want %s", c.name, got, c.want)
		}
	}
	// The bound composer carries the same routing (compile-time proof the var types line up).
	_ = fenceComposer
	_ = sem.CheckFence
	_ = swarm.CheckFence
}
