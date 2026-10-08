// Package integration boots the whole gateway onto one mux against a scratch Postgres database and
// asserts the cross-package invariants that no single package can check for itself (SPEC-v2 1, 3.5,
// 4.5, 19.6, 27): every mux route is declared in /openapi.json and has a scope; the "/" catch-all
// shadows nothing; every MCP op has help + OpMeta and no two collide; the system root exists and is
// token-less; the ledger balances after boot; sitemaps/feeds only surface trust.Indexable rows; and
// one anonymous-to-promotion journey runs end to end.
//
// registerAll and setSeams below mirror cmd/gateway/main.go (package main, not importable). They are
// kept in lock-step with it: a drift that leaves a route or seam out of this harness is itself a
// wiring bug this package exists to catch, so the parity tests here fail loudly when they diverge.
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/a2a"
	"ekaii.fr/commons/internal/a2ahost"
	"ekaii.fr/commons/internal/announce"
	"ekaii.fr/commons/internal/anonwait"
	"ekaii.fr/commons/internal/auction"
	"ekaii.fr/commons/internal/beacon"
	"ekaii.fr/commons/internal/bounty"
	"ekaii.fr/commons/internal/brief"
	"ekaii.fr/commons/internal/cache"
	"ekaii.fr/commons/internal/cachens"
	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/clients"
	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/ctlog"
	"ekaii.fr/commons/internal/dc"
	"ekaii.fr/commons/internal/delta"
	"ekaii.fr/commons/internal/demand"
	"ekaii.fr/commons/internal/did"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/drop"
	"ekaii.fr/commons/internal/edgekv"
	"ekaii.fr/commons/internal/egress"
	"ekaii.fr/commons/internal/errsig"
	"ekaii.fr/commons/internal/events"
	"ekaii.fr/commons/internal/export"
	"ekaii.fr/commons/internal/feed"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/gitmirror"
	"ekaii.fr/commons/internal/gointerp"
	"ekaii.fr/commons/internal/gov"
	"ekaii.fr/commons/internal/graph"
	"ekaii.fr/commons/internal/group"
	"ekaii.fr/commons/internal/grp"
	"ekaii.fr/commons/internal/gym"
	"ekaii.fr/commons/internal/hooks"
	"ekaii.fr/commons/internal/httpsig"
	"ekaii.fr/commons/internal/hubs"
	"ekaii.fr/commons/internal/impact"
	"ekaii.fr/commons/internal/inj"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/keys"
	"ekaii.fr/commons/internal/know"
	"ekaii.fr/commons/internal/legal"
	"ekaii.fr/commons/internal/libwatch"
	"ekaii.fr/commons/internal/limits"
	"ekaii.fr/commons/internal/machineclaims"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/mcp"
	"ekaii.fr/commons/internal/mem"
	"ekaii.fr/commons/internal/news"
	"ekaii.fr/commons/internal/notary"
	"ekaii.fr/commons/internal/oauth"
	"ekaii.fr/commons/internal/ops"
	"ekaii.fr/commons/internal/pagecost"
	"ekaii.fr/commons/internal/pages"
	"ekaii.fr/commons/internal/pathscrub"
	"ekaii.fr/commons/internal/pay"
	"ekaii.fr/commons/internal/pipe"
	"ekaii.fr/commons/internal/randb"
	"ekaii.fr/commons/internal/releases"
	"ekaii.fr/commons/internal/review"
	"ekaii.fr/commons/internal/roadmap"
	"ekaii.fr/commons/internal/room"
	"ekaii.fr/commons/internal/router"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/sem"
	"ekaii.fr/commons/internal/session"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/skills"
	"ekaii.fr/commons/internal/spaces"
	"ekaii.fr/commons/internal/subs"
	"ekaii.fr/commons/internal/svcget"
	"ekaii.fr/commons/internal/svcmcp"
	"ekaii.fr/commons/internal/swarm"
	csync "ekaii.fr/commons/internal/sync"
	"ekaii.fr/commons/internal/tags"
	"ekaii.fr/commons/internal/taskdag"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/treasury"
	"ekaii.fr/commons/internal/tripwire"
	"ekaii.fr/commons/internal/trust"
	"ekaii.fr/commons/internal/ui"
	"ekaii.fr/commons/internal/urltok"
	"ekaii.fr/commons/internal/waypoint"
	"ekaii.fr/commons/internal/web"
	"ekaii.fr/commons/internal/webhook"
	"ekaii.fr/commons/internal/xmail"
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
		// Reset the shared TEST_DATABASE_URL database before migrating, exactly as every other
		// package's TestMain does (e.g. internal/compute): under `go test -p 1 ./...` this database
		// is shared, and this harness only Migrate()s (idempotent, no reset), so without this it
		// inherits the preceding package's end-state and the after-boot invariants (system credits,
		// ledger balance) assert against polluted rows. Harmless on a fresh database.
		if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("integration", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL unset: skipping integration DB tests")
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
		AdminToken:     "integ-admin-token",
		OpsToken:       "integ-ops-token",
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
	oauth.MCPHandler = buildHandler(d, testMux)

	code := m.Run()
	d.Close()
	cleanup()
	os.Exit(code)
}

func mustTempDir() string {
	p, err := os.MkdirTemp("", "integ")
	if err != nil {
		panic(err)
	}
	return p
}

// buildHandler mirrors cmd/gateway/main.go buildHandler: the production request pipeline.
func buildHandler(d *core.Deps, mux http.Handler) http.Handler {
	h := d.Handler(mux)
	h = httpsig.Middleware(d, h)
	h = session.Middleware(d, h)
	h = d.BotLaneMiddleware(h)
	h = urltok.Middleware(d, h)
	h = pathscrub.Middleware(d, h)
	return h
}

// registerAll mirrors cmd/gateway/main.go registerAll.
func registerAll(mux *http.ServeMux, d *core.Deps) *ops.Ops {
	reg := func(name string, fn func()) {
		defer func() {
			if r := recover(); r != nil {
				d.Log.Error("register failed (route conflict or panic); package degraded", "pkg", name, "err", fmt.Sprint(r))
			}
		}()
		fn()
	}

	steps := []struct {
		name string
		fn   func()
	}{
		{"core", func() { core.Register(mux, d) }},
		{"core.authv2", func() { core.RegisterAuthV2(mux, d) }},
		{"core.adminv2", func() { core.RegisterAdminV2(mux, d) }},
		{"trust", func() { trust.Register(mux, d) }},
		{"scrub", func() { scrub.Register(mux, d) }},
		{"sign", func() { sign.Register(mux, d) }},
		{"keys", func() { keys.Register(mux, d) }},
		{"httpsig", func() { httpsig.Register(mux, d) }},
		{"did", func() { did.Register(mux, d) }},
		{"kb", func() { kb.Register(mux, d) }},
		{"kb.anon", func() { kb.RegisterAnon(mux, d) }},
		{"kb.edit", func() { kb.RegisterEdit(mux, d) }},
		{"kb.anonedit", func() { kb.RegisterAnonEdit(mux, d) }},
		{"kb.anonvotes", func() { kb.RegisterAnonVotes(mux, d) }},
		{"kb.pages", func() { kb.RegisterPages(mux, d) }},
		{"kb.cite", func() { kb.RegisterCite(mux, d) }},
		{"kb.trace", func() { kb.RegisterTrace(mux, d) }},
		{"kb.aka", func() { kb.RegisterAka(mux, d) }},
		{"forge", func() { forge.Register(mux, d) }},
		{"compute", func() { compute.Register(mux, d) }},
		{"compute.att", func() { compute.RegisterAtt(mux, d) }},
		{"compute.audit", func() { compute.RegisterAudit(d) }},
		{"compute.joblog", func() { compute.RegisterJobLog(mux, d) }},
		{"catalog", func() { catalog.Register(mux, d) }},
		{"catalog.verify", func() { catalog.RegisterVerify(d) }},
		{"gointerp", func() { gointerp.Register(mux, d) }},
		{"svcget", func() { svcget.Register(mux, d) }},
		{"svcmcp", func() { svcmcp.Register(mux, d) }},
		{"know", func() { know.Register(mux, d) }},
		{"libwatch", func() { libwatch.Register(mux, d) }},
		{"mem", func() { mem.Register(mux, d) }},
		{"drop", func() { drop.Register(mux, d) }},
		{"mail", func() { mail.Register(mux, d) }},
		{"xmail", func() { xmail.Register(mux, d) }},
		{"swarm", func() { swarm.Register(mux, d) }},
		{"room", func() { room.Register(mux, d) }},
		{"sem", func() { sem.Register(mux, d) }},
		{"grp", func() { grp.Register(mux, d) }},
		{"dc", func() { dc.Register(mux, d) }},
		{"group", func() { group.Register(mux, d) }},
		{"cache", func() { cache.Register(mux, d) }},
		{"cachens", func() { cachens.Register(mux, d) }},
		{"notary", func() { notary.Register(mux, d) }},
		{"ctlog", func() { ctlog.Register(mux, d) }},
		{"gov", func() { gov.Register(mux, d) }},
		{"gov.platform", func() { gov.RegisterPlatform(mux, d) }},
		{"roadmap", func() { roadmap.Register(mux, d) }},
		{"impact", func() { impact.Register(mux, d) }},
		{"spaces", func() { spaces.Register(mux, d) }},
		{"spaces.content", func() { spaces.RegisterContent(mux, d) }},
		{"releases", func() { releases.Register(mux, d) }},
		{"treasury", func() { treasury.Register(mux, d) }},
		{"hooks", func() { hooks.Register(mux, d) }},
		{"bounty", func() { bounty.Register(mux, d) }},
		{"pay", func() { pay.Register(mux, d) }},
		{"auction", func() { auction.Register(mux, d) }},
		{"review", func() { review.Register(mux, d) }},
		{"taskdag", func() { taskdag.Register(mux, d) }},
		{"events", func() { events.Register(mux, d) }},
		{"beacon", func() { beacon.Register(mux, d) }},
		{"oauth", func() { oauth.Register(mux, d) }},
		{"gitmirror", func() { gitmirror.Register(mux, d) }},
		{"a2a", func() { a2a.Register(mux, d) }},
		{"a2ahost", func() { a2ahost.Register(mux, d) }},
		{"webhook", func() { webhook.Register(mux, d) }},
		{"sync", func() { csync.Register(mux, d) }},
		{"export", func() { export.Register(mux, d) }},
		{"feed", func() { feed.Register(mux, d) }},
		{"gym", func() { gym.Register(mux, d) }},
		{"skills", func() { skills.Register(mux, d) }},
		{"graph", func() { graph.Register(mux, d) }},
		{"hubs", func() { hubs.Register(mux, d) }},
		{"tags", func() { tags.Register(mux, d) }},
		{"subs", func() { subs.Register(mux, d) }},
		{"news", func() { news.Register(mux, d) }},
		{"brief", func() { brief.Register(mux, d) }},
		{"demand", func() { demand.Register(mux, d) }},
		{"machineclaims", func() { machineclaims.Register(mux, d) }},
		{"edgekv", func() { edgekv.Register(mux, d) }},
		{"errsig", func() { errsig.Register(mux, d) }},
		{"delta", func() { delta.Register(mux, d) }},
		{"pipe", func() { pipe.Register(mux, d) }},
		{"anonwait", func() { anonwait.Register(mux, d) }},
		{"limits", func() { limits.Register(mux, d) }},
		{"announce", func() { announce.Register(mux, d) }},
		{"tripwire", func() { tripwire.Register(mux, d) }},
		{"inj", func() { inj.Register(mux, d) }},
		{"randb", func() { randb.Register(mux, d) }},
		{"waypoint", func() { waypoint.Register(mux, d) }},
		{"pagecost", func() { pagecost.Register(mux, d) }},
		{"legal", func() { legal.Register(mux, d) }},
		{"ui", func() { ui.Register(mux, d) }},
		{"clients", func() { clients.Register(mux, d) }},
		{"web", func() { web.Register(mux, d) }},
		{"web.sitemaps", func() { web.RegisterSitemaps(mux, d) }},
		{"web.notices", func() { web.RegisterNotices(mux, d) }},
		{"web.profiles", func() { web.RegisterProfiles(mux, d) }},
		{"web.tdm", func() { web.RegisterTDM(mux, d) }},
		{"mcp", func() { mcp.Register(mux, d) }},
		{"egress", func() { egress.Register(mux, d) }},
	}
	for _, s := range steps {
		reg(s.name, s.fn)
	}

	var o *ops.Ops
	reg("ops", func() { o = ops.Register(mux, d) })
	reg("router", func() { router.Register(mux, d) })
	reg("pages", func() { pages.Register(mux, d) })
	return o
}

// setSeams mirrors cmd/gateway/main.go setSeams.
func setSeams(d *core.Deps) {
	core.RepLogger = trust.RecordRep
	core.LevelFn = trust.LevelOf
	core.SysMailFn = mail.SendSys
	core.BodyParserFn = doc.Parse
	core.ChallengeIDFn = keys.ChallengeID
	core.RegisterBundleFn = keys.RegisterBundle
	core.XPoWFn = anonwait.Wrap(core.XPoWFn)

	kb.SavedHook = cache.Accrue
	kb.ChangesFn = func(ctx context.Context, lib, ver string) []string { return changesForLib(ctx, d, lib, ver) }
	kb.TagAliasFn = tags.Canon
	know.KBForLib = func(ctx context.Context, lib, ver string) []know.Ref { return nil }

	compute.CacheJobFn = cache.PutJob
	compute.OnDone = onDoneChain()

	mail.MemberFn = spaces.IsMember
	swarm.MemberFn = spaces.IsMember
	mail.RoomFn = room.IsMember
	swarm.RoomFn = room.IsMember
	mem.RoomFn = room.IsMember
	mem.MemberFn = spaces.IsMember
	mail.PolicyFn = keys.PlainAllowed
	swarm.NotifyExpired = mail.SendSys

	mem.FenceCheckFn = fenceComposer

	cache.CanonFn = cachens.Canon
	pages.TagCanonFn = tags.Canonical
	pages.KbNextFn = kb.AnonNext

	web.HubsFn = func(ctx context.Context) []string { return hubs.LandingFn(ctx, d.DB) }
	web.A2ACardFn = a2a.CardFields

	notary.SkillsFn = func(ctx context.Context, q core.Q, root string) string {
		s, _ := gym.SkillsLine(ctx, q, root)
		return s
	}
	review.SkillsFn = func(ctx context.Context, q core.Q, root string) map[string]float64 {
		m, _ := gym.SkillScores(ctx, q, root)
		return m
	}

	sem.RelFn = func(ctx context.Context, q core.Q, root string) float64 {
		r, _ := graph.Rel(ctx, q, root)
		return r
	}
	auction.RelFn = graph.Rel
	auction.ExcludeFn = func(ctx context.Context, q core.Q, a, b string) (bool, error) {
		return graph.Excluded(ctx, q, a, b), nil
	}

	a2a.PendingFn = anonwait.Pending
	a2a.PendingGetFn = anonwait.PendingGet
	a2a.PushConfigFn = webhook.A2APush
	hooks.FundFn = treasury.Debit
	tripwire.PublishFn = func(ctx context.Context, q core.Q, topic, root, text string) error {
		_, err := swarm.Publish(ctx, q, topic, "asystem", root, text, "")
		return err
	}

	egress.ResultFn["libmeta"] = func(ctx context.Context, _ *core.Deps, q core.Q, _, result json.RawMessage) error {
		return know.ApplyLibMeta(ctx, q, result)
	}

	registerGovKinds(d)
}

func changesForLib(ctx context.Context, d *core.Deps, lib, ver string) []string {
	rows, err := know.ClaimsAfter(ctx, d.DB, lib, ver, nil)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		line := strings.TrimSpace(r.Kind + " " + r.Title)
		if line == "" {
			line = r.Word
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func registerGovKinds(d *core.Deps) {
	gov.RegisterScopedKind("rule", "space", nil, func(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
		return spaces.ApplyRules(ctx, tx, p.Scope, p.Patch, p.AuthorRoot)
	})
	gov.RegisterScopedKind("pin", "space", nil, func(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
		var pp struct {
			Pins []string `json:"pins"`
		}
		if err := json.Unmarshal(p.Patch, &pp); err != nil {
			return nil, core.Bad("pin patch")
		}
		prev, err := spaces.SetPins(ctx, tx, p.Scope, pp.Pins, p.AuthorRoot)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(map[string][]string{"pins": prev})
		return b, nil
	})
	gov.RegisterScopedKind("member", "space", nil, func(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
		var mp gov.MemberPatch
		if err := json.Unmarshal(p.Patch, &mp); err != nil {
			return nil, core.Bad("member patch")
		}
		switch {
		case mp.Steward != "":
			term := mp.TermD
			if term == 0 {
				term = 30
			}
			return nil, spaces.SetSteward(ctx, tx, p.Scope, mp.Steward, true, term, p.AuthorRoot)
		case mp.Recall != "":
			return nil, spaces.SetSteward(ctx, tx, p.Scope, mp.Recall, false, 0, p.AuthorRoot)
		default:
			return nil, core.Bad("steward or recall required")
		}
	})
	gov.RegisterKind("kbfix", nil, func(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
		return kb.ApplyFix(ctx, tx, p.Target, p.Patch, p.ID)
	})
	gov.RegisterKind("kbmerge", nil, func(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
		var mp struct {
			Into string `json:"into"`
		}
		if err := json.Unmarshal(p.Patch, &mp); err != nil {
			return nil, core.Bad("merge patch")
		}
		return nil, kb.Merge(ctx, tx, p.Target, mp.Into)
	})
}

type doneFn = func(ctx context.Context, q core.Q, j *compute.Job) error

func onDoneChain() doneFn { return chainDone(catalog.OnDone, pipe.OnDone, bounty.OnDone) }

func chainDone(handlers ...doneFn) doneFn {
	return func(ctx context.Context, q core.Q, j *compute.Job) error {
		var first error
		for _, h := range handlers {
			if h == nil {
				continue
			}
			if err := h(ctx, q, j); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
}

func fenceComposer(ctx context.Context, q core.Q, name string, fence int64) error {
	return routeFence(name,
		func() error { return sem.CheckFence(ctx, q, name, fence) },
		func() error { return grp.CheckFence(ctx, q, name, fence) },
		func() error { return swarm.CheckFence(ctx, q, name, fence) })
}

func routeFence(name string, onSem, onGrp, onSwarm func() error) error {
	switch {
	case strings.HasPrefix(name, "sm:"):
		return onSem()
	case strings.HasPrefix(name, "grp:"):
		return onGrp()
	default:
		return onSwarm()
	}
}
