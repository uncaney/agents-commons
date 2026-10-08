// Command gateway is the single exposed process of agents.ekaii.fr.
//
// It wires every internal package onto one mux (SPEC-v2 1), installs the request
// middleware stack (pathscrub -> urltok -> botlane -> session -> httpsig -> core.Handler),
// sets the cross-package seams that need an integration adapter (the ones a single package
// cannot set without an import cycle), runs the courier-facing egress server on its own
// listener, the metrics server, the janitor and the shed ladder.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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
	"ekaii.fr/commons/internal/mcpsse"
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
	"ekaii.fr/commons/internal/sync"
	"ekaii.fr/commons/internal/tags"
	"ekaii.fr/commons/internal/taskdag"
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

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-healthcheck":
			os.Exit(healthcheck())
		}
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := core.LoadConfig()
	if err != nil {
		return err
	}
	doc.Configure(&cfg)

	// Flags that only need the config/DSN, before the full boot.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-migrate-check":
			rep, err := ops.MigrateCheck(ctx, core.ApplyPasswordFile(cfg.DatabaseURL))
			if err != nil {
				return err
			}
			fmt.Printf("%+v\n", rep)
			return nil
		}
	}

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return err
	}
	db, err := core.OpenDB(ctx, core.ApplyPasswordFile(cfg.DatabaseURL))
	if err != nil {
		return err
	}
	defer db.Close()
	d, err := core.NewDeps(ctx, cfg, db, log)
	if err != nil {
		return err
	}

	// -check-budget: verify the storage-class caps fit DISK_BUDGET, then exit.
	if len(os.Args) > 1 && os.Args[1] == "-check-budget" {
		if err := core.CheckBudget(d.StorageClasses(), cfg.DiskBudget); err != nil {
			return err
		}
		fmt.Println("budget ok")
		return nil
	}

	mux := http.NewServeMux()
	o := registerAll(mux, d)
	setSeams(d)

	// -import-forge: one-shot backfill of the Forgejo mirror, then exit.
	if len(os.Args) > 1 && os.Args[1] == "-import-forge" {
		return forge.Import(ctx, d)
	}

	// Fail-fast on a misconfigured storage budget before accepting traffic.
	if err := core.CheckBudget(d.StorageClasses(), cfg.DiskBudget); err != nil {
		return err
	}

	// Seed the system catalog tools and gym mods from the baked-in wasm dir.
	seeded := 0
	if n, err := catalog.SeedSystem(ctx, d, cfg.SeedWasmDir); err != nil {
		log.Warn("catalog seed", "err", err)
	} else {
		seeded += n
	}
	if n, err := gym.SeedSystem(ctx, d, cfg.SeedWasmDir); err != nil {
		log.Warn("gym seed", "err", err)
	} else {
		seeded += n
	}
	log.Info(fmt.Sprintf("seed modules: %d", seeded))

	go d.Janitor.Run(ctx, 30*time.Second)
	if o != nil {
		go o.Run(ctx)
	}
	// Courier-facing egress server on its own listener; never on the public mux.
	go func() {
		if err := egress.Serve(ctx, d, cfg.InternalListen); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("egress serve", "err", err)
		}
	}()
	if cfg.MetricsListen != "" && o != nil {
		go func() {
			if err := o.ServeMetrics(ctx, cfg.MetricsListen); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics serve", "err", err)
			}
		}()
	}

	handler := buildHandler(d, mux)
	if o != nil {
		handler = o.Middleware(handler)
	}
	// The url-token MCP route (oauth POST /mcp/t/{token}) replays the request as /mcp through the
	// full pipeline, so it authenticates and signs like any other call.
	oauth.MCPHandler = handler
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second, // long-polls up to 85 s
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "pow_bits", cfg.PowBits, "internal", cfg.InternalListen)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// buildHandler assembles the request pipeline (SPEC-v2 27): the outermost middleware is the first
// to see a request, so the slice is wrapped inner-first. Order, outer -> inner:
//
//	pathscrub -> urltok -> botlane -> session -> httpsig(response) -> core.Handler -> mux
func buildHandler(d *core.Deps, mux http.Handler) http.Handler {
	h := d.Handler(mux)          // core.Handler terminates on the mux
	h = httpsig.Middleware(d, h) // response signing, closest to core
	h = session.Middleware(d, h)
	h = d.BotLaneMiddleware(h)
	h = urltok.Middleware(d, h)
	h = pathscrub.Middleware(d, h) // outermost: rejects a hostile path before anything injects
	return h
}

// registration is one package's mount step: a stable name (for the degraded-package log and the
// cmd/gateway regression test) and the Register call that mounts it.
type registration struct {
	name string
	fn   func()
}

// buildRegistrations returns every package's mount step in dependency order (SPEC-v2 1): the single
// ordered source of truth that both run()'s registerAll and the cmd/gateway regression test build
// from. Order matters: pages' "/" catch-all and router mount last so specific routes win; ops mounts
// after the feature packages so it only claims /status, /status/history and /healthz when still free.
// Security-critical packages (keys, the E2EE transparency log) wire before any package that might
// clash on a shared path, so the key log keeps its routes if a later package collides. The ops
// instance (needed for Run / ServeMetrics / Middleware) is stored through op.
func buildRegistrations(mux *http.ServeMux, d *core.Deps, op **ops.Ops) []registration {
	steps := []registration{
		// --- core identity, trust, crypto ---
		{"core", func() { core.Register(mux, d) }},
		{"core.authv2", func() { core.RegisterAuthV2(mux, d) }},
		{"core.adminv2", func() { core.RegisterAdminV2(mux, d) }},
		{"trust", func() { trust.Register(mux, d) }},
		{"scrub", func() { scrub.Register(mux, d) }},
		{"sign", func() { sign.Register(mux, d) }},
		{"keys", func() { keys.Register(mux, d) }},
		{"httpsig", func() { httpsig.Register(mux, d) }},
		{"did", func() { did.Register(mux, d) }},
		// --- knowledge base (+ anon, edit, pages, rev3 surfaces) ---
		{"kb", func() { kb.Register(mux, d) }},
		{"kb.anon", func() { kb.RegisterAnon(mux, d) }},
		{"kb.edit", func() { kb.RegisterEdit(mux, d) }},
		{"kb.anonedit", func() { kb.RegisterAnonEdit(mux, d) }},
		{"kb.anonvotes", func() { kb.RegisterAnonVotes(mux, d) }},
		{"kb.pages", func() { kb.RegisterPages(mux, d) }},
		{"kb.cite", func() { kb.RegisterCite(mux, d) }},
		{"kb.trace", func() { kb.RegisterTrace(mux, d) }},
		{"kb.aka", func() { kb.RegisterAka(mux, d) }},
		// --- board, compute, catalog ---
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
		// --- knowledge, continuity, messaging, swarm ---
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
		// --- notary, governance, spaces, economy ---
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
		// --- discovery, events, integrations ---
		{"events", func() { events.Register(mux, d) }},
		{"beacon", func() { beacon.Register(mux, d) }},
		{"oauth", func() { oauth.Register(mux, d) }},
		{"gitmirror", func() { gitmirror.Register(mux, d) }},
		{"a2a", func() { a2a.Register(mux, d) }},
		{"a2ahost", func() { a2ahost.Register(mux, d) }},
		{"webhook", func() { webhook.Register(mux, d) }},
		{"sync", func() { sync.Register(mux, d) }},
		{"export", func() { export.Register(mux, d) }},
		{"feed", func() { feed.Register(mux, d) }},
		// --- rev3 feature surfaces ---
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
		// --- site, egress, router + pages catch-all last ---
		{"web", func() { web.Register(mux, d) }},
		{"web.sitemaps", func() { web.RegisterSitemaps(mux, d) }},
		{"web.notices", func() { web.RegisterNotices(mux, d) }},
		{"web.profiles", func() { web.RegisterProfiles(mux, d) }},
		{"web.tdm", func() { web.RegisterTDM(mux, d) }},
		{"mcp", func() { mcp.Register(mux, d) }},
		{"mcpsse", func() { mcpsse.Register(mux, d) }},
		{"egress", func() { egress.Register(mux, d) }},
	}
	return append(steps,
		registration{"ops", func() { *op = ops.Register(mux, d) }},
		registration{"router", func() { router.Register(mux, d) }}, // after every package, before the pages catch-all
		registration{"pages", func() { pages.Register(mux, d) }},   // catch-all ("/") last
	)
}

// registerAll mounts every package in buildRegistrations order, isolating a route conflict: http.ServeMux
// panics on a duplicate pattern, and a single misbehaving package (two owners that both claim one path
// during the concurrent waves) must not take the whole gateway down at boot. A panic is logged at ERROR
// with the package name so the clash is loud, never silent, and the rest still wire. It returns the ops
// instance for Run / ServeMetrics / Middleware. The cmd/gateway test runs the same sequence without the
// recover so a duplicate route fails the build instead of silently degrading a package.
func registerAll(mux *http.ServeMux, d *core.Deps) *ops.Ops {
	reg := func(name string, fn func()) {
		defer func() {
			if r := recover(); r != nil {
				d.Log.Error("register failed (route conflict or panic); package degraded", "pkg", name, "err", fmt.Sprint(r))
			}
		}()
		fn()
	}
	var o *ops.Ops
	for _, s := range buildRegistrations(mux, d, &o) {
		reg(s.name, s.fn)
	}
	return o
}

// setSeams installs the cross-package function vars that a single package cannot set without an
// import cycle. Most REV3 seams self-wire inside each package's Register; the ones here are the
// adapters P60a owns (SPEC-v2 1 core_seams): trust/mail/swarm/mem glue, the gov kind registry, the
// fence composer, the compute OnDone chain and the anon-wait PoW wrapper.
func setSeams(d *core.Deps) {
	// Reputation + standing (trust implements the core seams).
	core.RepLogger = trust.RecordRep
	core.LevelFn = trust.LevelOf
	core.SysMailFn = mail.SendSys
	core.BodyParserFn = doc.Parse
	core.ChallengeIDFn = keys.ChallengeID
	core.RegisterBundleFn = keys.RegisterBundle
	// Anon-wait wraps the installed PoW checker so a pending anonymous write parks instead of 400.
	core.XPoWFn = anonwait.Wrap(core.XPoWFn)

	// KB <-> cache/know.
	kb.SavedHook = cache.Accrue
	kb.ChangesFn = func(ctx context.Context, lib, ver string) []string { return changesForLib(ctx, d, lib, ver) }
	kb.TagAliasFn = tags.Canon
	know.KBForLib = func(ctx context.Context, lib, ver string) []know.Ref { return nil }

	// Compute <-> cache/catalog; OnDone is a chain built after every package self-set it.
	compute.CacheJobFn = cache.PutJob
	compute.OnDone = onDoneChain()

	// Membership + rooms + plaintext policy (spaces/room/keys provide, the recipients import neither).
	mail.MemberFn = spaces.IsMember
	swarm.MemberFn = spaces.IsMember
	mail.RoomFn = room.IsMember
	swarm.RoomFn = room.IsMember
	mem.RoomFn = room.IsMember
	mem.MemberFn = spaces.IsMember
	mail.PolicyFn = keys.PlainAllowed
	swarm.NotifyExpired = mail.SendSys

	// Fence checks composed across swarm / sem / grp by lock-name prefix.
	mem.FenceCheckFn = fenceComposer

	// Catalog / cache canonicalisation, pages next-actions.
	cache.CanonFn = cachens.Canon
	pages.TagCanonFn = tags.Canonical
	pages.KbNextFn = kb.AnonNext

	// Site landing hubs, A2A card. The OAuth MCP forwarder is wired in run() to the fully
	// authenticated handler, since it must dispatch /mcp through core.Handler.
	web.HubsFn = func(ctx context.Context) []string { return hubs.LandingFn(ctx, d.DB) }
	web.A2ACardFn = a2a.CardFields

	// Notary / review skill lines (gym provides; drop the error for the string-only seams).
	notary.SkillsFn = func(ctx context.Context, q core.Q, root string) string {
		s, _ := gym.SkillsLine(ctx, q, root)
		return s
	}
	review.SkillsFn = func(ctx context.Context, q core.Q, root string) map[string]float64 {
		m, _ := gym.SkillScores(ctx, q, root)
		return m
	}

	// Relatedness seams that graph sets for review/bounty but not for sem/auction.
	sem.RelFn = func(ctx context.Context, q core.Q, root string) float64 {
		r, _ := graph.Rel(ctx, q, root)
		return r
	}
	auction.RelFn = graph.Rel
	auction.ExcludeFn = func(ctx context.Context, q core.Q, a, b string) (bool, error) {
		return graph.Excluded(ctx, q, a, b), nil
	}

	// A2A pending (anon-wait), push config (webhook), funding (treasury), tripwire publish (swarm).
	a2a.PendingFn = anonwait.Pending
	a2a.PendingGetFn = anonwait.PendingGet
	a2a.PushConfigFn = webhook.A2APush
	hooks.FundFn = treasury.Debit
	tripwire.PublishFn = func(ctx context.Context, q core.Q, topic, root, text string) error {
		_, err := swarm.Publish(ctx, q, topic, "asystem", root, text, "")
		return err
	}

	// Libmeta egress result (courier) handled by know.
	egress.ResultFn["libmeta"] = func(ctx context.Context, _ *core.Deps, q core.Q, _, result json.RawMessage) error {
		return know.ApplyLibMeta(ctx, q, result)
	}

	// Governance seams (18.3 / 18.6 anti-capture): the gov engine reads space facts, capture stats,
	// space-scoped eligible weight and kb entry facts through these vars (nil = disabled). spaces and
	// kb cannot import gov, so the gateway adapts their exported funcs onto the gov types.
	gov.SpaceInfoFn = func(ctx context.Context, q core.Q, slug, root string) (gov.SpaceInfo, error) {
		gi, err := spaces.InfoForGov(ctx, q, slug, root)
		if err != nil {
			return gov.SpaceInfo{}, err
		}
		return gov.SpaceInfo{
			Exists: gi.Exists, Member: gi.Member, Banned: gi.Banned,
			Frozen: gi.Frozen, Hidden: gi.Hidden, MemberSince: gi.MemberSince,
			MinMemberH: gi.MinMemberH, VoteWindowH: gi.VoteWindowH, VoteThreshold: gi.VoteThreshold,
			Creator: gi.Creator, Created: gi.Created,
		}, nil
	}
	gov.SpaceStatsFn = func(ctx context.Context, q core.Q, slug string) (gov.Stats, error) {
		st, _, ok, err := spaces.LatestStats(ctx, q, slug)
		if err != nil {
			return gov.Stats{}, err
		}
		if !ok {
			if st, err = spaces.ComputeStats(ctx, q, slug); err != nil {
				return gov.Stats{}, err
			}
		}
		return gov.Stats{
			Members: st.Members, EligibleW: st.EligibleW, Groups: st.Groups,
			TopGroupShare: st.TopGroupShare, Top5Share: st.Top5Share,
			Passed: st.Passed, Failed: st.Failed,
		}, nil
	}
	gov.EligibleWeightFn = func(ctx context.Context, q core.Q, scope string) (float64, error) {
		if scope == "" {
			return gov.DefaultEligibleWeight(ctx, q)
		}
		st, err := spaces.ComputeStats(ctx, q, scope)
		if err != nil {
			return 0, err
		}
		return st.EligibleW, nil
	}
	gov.KBStatsFn = func(ctx context.Context, q core.Q, id string) (gov.KBStats, error) {
		e, err := kb.GetV2(ctx, q, id, kb.GetOpts{IncHidden: true, IncQuarantine: true})
		if err != nil {
			if errors.Is(err, core.ErrNotFound) {
				return gov.KBStats{}, nil // Exists == false
			}
			return gov.KBStats{}, err
		}
		return gov.KBStats{
			Exists:     true,
			Visible:    e.Visible() && !e.Quarantine,
			OkW:        float64(e.OkW),
			AuthorRoot: e.AuthorRoot,
		}, nil
	}
	spaces.ProposalCountsFn = gov.ScopeCounts

	// Governance kinds that need a gov.Proposal shape the provider cannot import (spaces, kb, catalog).
	registerGovKinds(d)

	// Fail fast if any required gov seam is left nil: a partial wiring must never silently re-enable
	// space governance with the concentration brake (SpaceStatsFn) or the entry-facts quorum off.
	assertGovSeams()
}

// assertGovSeams panics when a gov seam the engine depends on is unset, so the process refuses to
// serve rather than run space governance with anti-capture enforcement disabled (18.3 / 18.6).
func assertGovSeams() {
	var missing []string
	if gov.SpaceInfoFn == nil {
		missing = append(missing, "gov.SpaceInfoFn")
	}
	if gov.SpaceStatsFn == nil {
		missing = append(missing, "gov.SpaceStatsFn")
	}
	if gov.EligibleWeightFn == nil {
		missing = append(missing, "gov.EligibleWeightFn")
	}
	if gov.KBStatsFn == nil {
		missing = append(missing, "gov.KBStatsFn")
	}
	if spaces.ProposalCountsFn == nil {
		missing = append(missing, "spaces.ProposalCountsFn")
	}
	if len(missing) > 0 {
		panic("gov seams unwired: " + strings.Join(missing, ", "))
	}
}

// changesForLib formats the know claims feed for a library version into display lines; empty when
// know has nothing (the kb.ChangesFn seam is advisory and fails neutral).
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

// registerGovKinds supplies the proposal appliers whose owning package cannot import gov without a
// cycle (SPEC-v2 18.1): spaces (rule, pin, member) and kb (kbfix, kbmerge). gov ships the shape
// validators in its own init; catalog (svc-*), platform (doc) and the rev3 packages self-register
// theirs, so P60a only fills these appliers.
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
		// The platform roadmap space is non-amendable by vote (27.5): refuse the GOVERNANCE pin
		// path here while leaving the system-root StewardPins -> SetPins route untouched, mirroring
		// the slug=="platform" guards in spaces.ApplyRules/SetSteward.
		if p.Scope == "platform" {
			return nil, core.E(403, "auth", "platform space is not amendable")
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
	gov.RegisterScopedKind("doc", "space", nil, func(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
		var dp struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(p.Patch, &dp); err != nil {
			return nil, core.Bad("doc patch")
		}
		prev, _, err := spaces.ApplyDoc(ctx, tx, p.Scope, p.Target, dp.Text, p.ID)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(map[string]string{"text": prev})
		return b, nil
	})
	gov.RegisterScopedKind("template", "space", nil, func(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
		var dp struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(p.Patch, &dp); err != nil {
			return nil, core.Bad("template patch")
		}
		// gov's template target is "task"|"kb"; the backing doc is tpl-task / tpl-kb (18.3).
		prev, _, err := spaces.ApplyDoc(ctx, tx, p.Scope, "tpl-"+p.Target, dp.Text, p.ID)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(map[string]string{"text": prev})
		return b, nil
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

// onDoneChain is the compute.OnDone installed after every package has self-set it (catalog and pipe
// both overwrite the var in their Register, so the chain must be set last). Order (SPEC-v2 1):
// catalog fees, pipe steps, bounty review.
func onDoneChain() doneFn { return chainDone(catalog.OnDone, pipe.OnDone, bounty.OnDone) }

// chainDone fans a finished job through every handler in order. Each runs even if a prior one errs;
// the first error is returned so the job row is retried.
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

// fenceComposer routes a fenced-write check to the owner of the lock name by prefix (SPEC-v2 1):
// "sm:" -> sem permits, "grp:" -> grp shards, everything else -> swarm locks.
func fenceComposer(ctx context.Context, q core.Q, name string, fence int64) error {
	return routeFence(name,
		func() error { return sem.CheckFence(ctx, q, name, fence) },
		func() error { return grp.CheckFence(ctx, q, name, fence) },
		func() error { return swarm.CheckFence(ctx, q, name, fence) })
}

// routeFence selects the fenced-write owner by lock-name prefix; split out so the routing is unit
// testable without a live sem/grp/swarm backend.
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

// healthcheck probes the local /healthz for the distroless compose healthcheck.
func healthcheck() int {
	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
