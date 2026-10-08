// Code generated for P60b-mcp-registry: every package whose Ops(d) and OpMeta the MCP
// registry merges (SPEC-v2 19.6/3.5). Regenerate rather than edit by hand.
package mcp

import (
	"ekaii.fr/commons/internal/core"

	"ekaii.fr/commons/internal/a2a"
	"ekaii.fr/commons/internal/a2ahost"
	"ekaii.fr/commons/internal/announce"
	"ekaii.fr/commons/internal/auction"
	"ekaii.fr/commons/internal/beacon"
	"ekaii.fr/commons/internal/bounty"
	"ekaii.fr/commons/internal/brief"
	"ekaii.fr/commons/internal/cache"
	"ekaii.fr/commons/internal/cachens"
	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/ctlog"
	"ekaii.fr/commons/internal/dc"
	"ekaii.fr/commons/internal/delta"
	"ekaii.fr/commons/internal/demand"
	"ekaii.fr/commons/internal/errsig"
	"ekaii.fr/commons/internal/events"
	"ekaii.fr/commons/internal/export"
	"ekaii.fr/commons/internal/feed"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/gointerp"
	"ekaii.fr/commons/internal/gov"
	"ekaii.fr/commons/internal/group"
	"ekaii.fr/commons/internal/grp"
	"ekaii.fr/commons/internal/gym"
	"ekaii.fr/commons/internal/hooks"
	"ekaii.fr/commons/internal/hubs"
	"ekaii.fr/commons/internal/impact"
	"ekaii.fr/commons/internal/inj"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/keys"
	"ekaii.fr/commons/internal/know"
	"ekaii.fr/commons/internal/legal"
	"ekaii.fr/commons/internal/libwatch"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/mem"
	"ekaii.fr/commons/internal/news"
	"ekaii.fr/commons/internal/notary"
	"ekaii.fr/commons/internal/oauth"
	"ekaii.fr/commons/internal/pagecost"
	"ekaii.fr/commons/internal/pages"
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
	"ekaii.fr/commons/internal/spaces"
	"ekaii.fr/commons/internal/subs"
	"ekaii.fr/commons/internal/svcget"
	"ekaii.fr/commons/internal/swarm"
	"ekaii.fr/commons/internal/sync"
	"ekaii.fr/commons/internal/tags"
	"ekaii.fr/commons/internal/taskdag"
	"ekaii.fr/commons/internal/treasury"
	"ekaii.fr/commons/internal/tripwire"
	"ekaii.fr/commons/internal/trust"
	"ekaii.fr/commons/internal/waypoint"
	"ekaii.fr/commons/internal/webhook"
	"ekaii.fr/commons/internal/xmail"
)

// opSource is one package contributing ops and their metadata to the merged registry.
type opSource struct {
	name  string
	ops   func(*core.Deps) map[string]Op
	metas []map[string]core.OpMeta
}

// opSources is every package the registry merges; Ops() panics on a duplicate op name.
var opSources = []opSource{
	{"a2a", a2a.Ops, []map[string]core.OpMeta{a2a.OpMeta}},
	{"a2ahost", a2ahost.Ops, []map[string]core.OpMeta{a2ahost.OpMeta}},
	{"announce", announce.Ops, []map[string]core.OpMeta{announce.OpMeta}},
	{"auction", auction.Ops, []map[string]core.OpMeta{auction.OpMeta}},
	{"beacon", beacon.Ops, []map[string]core.OpMeta{beacon.OpMeta}},
	{"bounty", bounty.Ops, []map[string]core.OpMeta{bounty.OpMeta}},
	{"brief", brief.Ops, []map[string]core.OpMeta{brief.OpMeta}},
	{"cache", cache.Ops, []map[string]core.OpMeta{cache.OpMeta}},
	{"cachens", cachens.Ops, []map[string]core.OpMeta{cachens.OpMeta}},
	{"catalog", catalog.Ops, []map[string]core.OpMeta{catalog.OpMeta}},
	{"compute", compute.Ops, []map[string]core.OpMeta{compute.OpMeta, compute.OpMetaAtt, compute.OpMetaJobLog}},
	{"ctlog", ctlog.Ops, []map[string]core.OpMeta{ctlog.OpMeta}},
	{"dc", dc.Ops, []map[string]core.OpMeta{dc.OpMeta}},
	{"delta", delta.Ops, []map[string]core.OpMeta{delta.OpMeta}},
	{"demand", demand.Ops, []map[string]core.OpMeta{demand.OpMeta}},
	{"errsig", errsig.Ops, []map[string]core.OpMeta{errsig.OpMeta}},
	{"events", events.Ops, []map[string]core.OpMeta{events.OpMeta}},
	{"export", export.Ops, []map[string]core.OpMeta{export.OpMeta}},
	{"feed", feed.Ops, []map[string]core.OpMeta{feed.OpMeta}},
	{"forge", forge.Ops, []map[string]core.OpMeta{forge.OpMeta}},
	{"gointerp", gointerp.Ops, []map[string]core.OpMeta{gointerp.OpMeta}},
	{"gov", gov.Ops, []map[string]core.OpMeta{gov.OpMeta, gov.PlatformOpMeta}},
	{"group", group.Ops, []map[string]core.OpMeta{group.OpMeta}},
	{"grp", grp.Ops, []map[string]core.OpMeta{grp.OpMeta}},
	{"gym", gym.Ops, []map[string]core.OpMeta{gym.OpMeta}},
	{"hooks", hooks.Ops, []map[string]core.OpMeta{hooks.OpMeta}},
	{"hubs", hubs.Ops, []map[string]core.OpMeta{hubs.OpMeta}},
	{"impact", impact.Ops, []map[string]core.OpMeta{impact.OpMeta}},
	{"inj", inj.Ops, []map[string]core.OpMeta{inj.OpMeta}},
	{"kb", kb.Ops, []map[string]core.OpMeta{kb.OpMeta, kb.AkaOpMeta, kb.EditOpMeta, kb.AnonOpMeta, kb.AnonVotesOpMeta, kb.AnonEditOpMeta, kb.DryOpMeta, kb.TraceOpMeta}},
	{"keys", keys.Ops, []map[string]core.OpMeta{keys.OpMeta}},
	{"know", know.Ops, []map[string]core.OpMeta{know.OpMeta}},
	{"legal", legal.Ops, []map[string]core.OpMeta{legal.OpMeta}},
	{"libwatch", libwatch.Ops, []map[string]core.OpMeta{libwatch.OpMeta}},
	{"mail", mail.Ops, []map[string]core.OpMeta{mail.OpMeta}},
	{"mem", mem.Ops, []map[string]core.OpMeta{mem.OpMeta}},
	{"news", news.Ops, []map[string]core.OpMeta{news.OpMeta}},
	{"notary", notary.Ops, []map[string]core.OpMeta{notary.OpMeta}},
	{"oauth", oauth.Ops, []map[string]core.OpMeta{oauth.OpMeta}},
	{"pagecost", pagecost.Ops, []map[string]core.OpMeta{pagecost.OpMeta}},
	{"pages", pages.Ops, []map[string]core.OpMeta{pages.OpMeta}},
	{"pay", pay.Ops, []map[string]core.OpMeta{pay.OpMeta}},
	{"pipe", pipe.Ops, []map[string]core.OpMeta{pipe.OpMeta}},
	{"randb", randb.Ops, []map[string]core.OpMeta{randb.OpMeta}},
	{"releases", releases.Ops, []map[string]core.OpMeta{releases.OpMeta}},
	{"review", review.Ops, []map[string]core.OpMeta{review.OpMeta}},
	{"roadmap", roadmap.Ops, []map[string]core.OpMeta{roadmap.OpMeta}},
	{"room", room.Ops, []map[string]core.OpMeta{room.OpMeta}},
	{"router", router.Ops, []map[string]core.OpMeta{router.OpMeta}},
	{"scrub", scrub.Ops, nil}, // scrub.OpMeta uses a local struct type, not core.OpMeta; ops take default meta
	{"sem", sem.Ops, []map[string]core.OpMeta{sem.OpMeta}},
	{"session", session.Ops, []map[string]core.OpMeta{session.OpMeta}},
	{"sign", sign.Ops, []map[string]core.OpMeta{}},
	{"spaces", spaces.Ops, []map[string]core.OpMeta{spaces.OpMeta, spaces.ContentOpMeta, spaces.LLMSOpMeta}},
	{"subs", subs.Ops, []map[string]core.OpMeta{subs.OpMeta}},
	{"svcget", svcget.Ops, []map[string]core.OpMeta{svcget.OpMeta}},
	{"swarm", swarm.Ops, []map[string]core.OpMeta{swarm.OpMeta}},
	{"sync", sync.Ops, []map[string]core.OpMeta{sync.OpMeta}},
	{"tags", tags.Ops, []map[string]core.OpMeta{tags.OpMeta}},
	{"taskdag", taskdag.Ops, []map[string]core.OpMeta{taskdag.OpMeta}},
	{"treasury", treasury.Ops, []map[string]core.OpMeta{treasury.OpMeta}},
	{"tripwire", tripwire.Ops, []map[string]core.OpMeta{tripwire.OpMeta}},
	{"trust", trust.Ops, []map[string]core.OpMeta{trust.OpMeta}},
	{"waypoint", waypoint.Ops, []map[string]core.OpMeta{waypoint.OpMeta}},
	{"webhook", webhook.Ops, []map[string]core.OpMeta{webhook.OpMeta}},
	{"xmail", xmail.Ops, []map[string]core.OpMeta{xmail.OpMeta}},
}
