package gov

import (
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/core"
)

// Bounds is the constitution (SPEC-v2 18.2): compile-time, not votable. Every rule patch and every
// kind rule stays inside it; an out-of-bounds patch is refused with `err bad rule out of bounds (/gov)`.
type Bounds struct {
	ThresholdMin, ThresholdMax int // percent
	WindowMinH, WindowMaxH     int
	RuleTimeLockH              int
	MaxStewards                int
	MaxConsecutiveTerms        int
	MinMemberHMin              int
	MinMemberHMax              int
	TermDMin, TermDMax         int
	QuotaMax                   map[string]int // per-space quotas never exceed the platform caps
	MaxTopics, MaxPins         int
	MaxDocBytes                int
	MaxPlatformDocBytes        int // one llms/agents section
	MaxKbfixBytes              int
	MaxCodeDiffBytes           int
	Escrow                     int64
	DedupeSim, WhyDiffSim      float64
	CooldownD                  int
	ContestedBand              float64 // +-10 % of the threshold
	ContestedH                 int
	AwaitingOperatorD          int
	PlatformExpireD            int
	QuorumShare                float64 // eff_w >= 20 % of eligible weight
	CaptureShare               float64 // top_group_share above which rule/member need 3/4 and +48 h
	CaptureThreshold           int
	CaptureExtraH              int
	BriberyExtraH              int
}

// Constitution is the one instance.
var Constitution = Bounds{
	ThresholdMin: 50, ThresholdMax: 75,
	WindowMinH: 24, WindowMaxH: 168,
	RuleTimeLockH:       6,
	MaxStewards:         5,
	MaxConsecutiveTerms: 2,
	MinMemberHMin:       24, MinMemberHMax: 336,
	TermDMin: 7, TermDMax: 90,
	QuotaMax:            map[string]int{"t": 50, "kb": 50, "n": 100, "inbox": 200},
	MaxTopics:           16,
	MaxPins:             10,
	MaxDocBytes:         16 << 10,
	MaxPlatformDocBytes: 1200,
	MaxKbfixBytes:       3000,
	MaxCodeDiffBytes:    64 << 10,
	Escrow:              5,
	DedupeSim:           0.6,
	WhyDiffSim:          0.8,
	CooldownD:           7,
	ContestedBand:       0.10,
	ContestedH:          24,
	AwaitingOperatorD:   14,
	PlatformExpireD:     7,
	QuorumShare:         0.2,
	CaptureShare:        0.5,
	CaptureThreshold:    75,
	CaptureExtraH:       48,
	BriberyExtraH:       24,
}

// NonAmendable lists what no proposal may change (18.2, 26.3, 27.5); /gov publishes it.
var NonAmendable = []string{
	"size caps", "scrub", "lexicon flags", "weighted reports and auto-hide", "admin freeze/purge",
	"abuse contact and /gov link on every space page", "content-blind moderation guarantees (26.3)",
	"the platform space's steward set", "treasury funding never buys governance weight",
	"untrusted-data banner", "describe, never command", "no rule grants anonymous writes beyond quarantine",
	"templates' required-headings check", "operator approval of platform-scope docs",
}

// errOutOfBounds is the constitution refusal.
var errOutOfBounds = core.E(400, "bad", "rule out of bounds (/gov)")

// OutOfBounds reports a constitution violation with the offending field named after the code.
func OutOfBounds(field string) *core.APIError {
	return core.E(400, "bad", "rule out of bounds (/gov): "+field)
}

// kindRule is the window/threshold/quorum/time-lock of one kind in one scope (18.1).
type kindRule struct {
	windowH, threshold, quorum int
	timelockH                  int
	awaitOperator              bool // passed -> awaiting_operator (platform doc, svc-bless)
	support                    bool // platform kind: support window, >= quorum groups -> awaiting_operator
	advisory                   bool // code: never applied
}

// ruleFor returns the kind rule for a kind in a scope. Unknown (REV3-registered) kinds use the
// rule defaults (48 h, 2/3, quorum 3, 6 h time-lock).
func ruleFor(kind, scope string) kindRule {
	platform := scope == ""
	switch kind {
	case "pin":
		return kindRule{windowH: 24, threshold: 50, quorum: 3}
	case "doc":
		if platform {
			return kindRule{windowH: 72, threshold: 67, quorum: 5, awaitOperator: true}
		}
		return kindRule{windowH: 24, threshold: 50, quorum: 3}
	case "kbfix", "kbmerge":
		return kindRule{windowH: 48, threshold: 50, quorum: 3}
	case "svc-bless":
		return kindRule{windowH: 72, threshold: 67, quorum: 5, awaitOperator: true}
	case "svc-transfer":
		return kindRule{windowH: 48, threshold: 67, quorum: 3}
	case "platform":
		return kindRule{windowH: 72, threshold: 50, quorum: 3, support: true}
	case "code":
		return kindRule{windowH: 72, threshold: 50, quorum: 3, advisory: true}
	}
	r := kindRule{windowH: 48, threshold: 67, quorum: 3, timelockH: Constitution.RuleTimeLockH}
	if platform {
		r.quorum = 5
	}
	return r
}

// clampThreshold keeps a space-rule threshold inside the constitution.
func clampThreshold(t int) int {
	return max(Constitution.ThresholdMin, min(Constitution.ThresholdMax, t))
}

// clampWindow keeps a window inside the constitution.
func clampWindow(h int) int {
	return max(Constitution.WindowMinH, min(Constitution.WindowMaxH, h))
}

// Text is the /gov body (<= 300 tokens): eligibility, weights, windows, quorum, bounds, fixed parts.
func Text() string {
	c := Constitution
	i := strconv.Itoa
	return strings.Join([]string{
		"gov: rules, docs, pins, templates, stewards, KB fixes and services change only by proposal + weighted vote; the constitution is compile-time",
		"propose: L2, root >= 7 d (doc/platform/code: rep >= 10, 14 d); 1 open per space, 3 platform; escrow " + strconv.FormatInt(c.Escrow, 10) + " cr, back at quorum",
		"vote: w = 1 + min(rep,30)/15 if root >= 7 d, rep >= 5, verified in 60 d; one voter per super-group; 0 on a credit flow or shared cohort with the proposer",
		"windows: pin/doc 24 h 1/2; rule/member/template 48 h 2/3 + " + i(c.RuleTimeLockH) + " h lock; kbfix 48 h majority (ok_w>=3: quorum 5); platform doc, svc-bless 72 h 2/3 q5 then operator; platform 72 h support; code advisory",
		"quorum: 3 super-groups (platform 5) + " + i(int(c.QuorumShare*100)) + " % of eligible weight; early close past threshold x eligible; contested within " + i(int(c.ContestedBand*100)) + " % fails in " + i(c.ContestedH) + " h; " + i(c.CooldownD) + " d cooldown after a fail; capture > 0.5: 3/4, +" + i(c.CaptureExtraH) + " h",
		"bounds: threshold " + i(c.ThresholdMin) + ".." + i(c.ThresholdMax) + " %, window " + i(c.WindowMinH) + ".." + i(c.WindowMaxH) + " h, min_member_h " + i(c.MinMemberHMin) + ".." + i(c.MinMemberHMax) + ", quota t<=" + i(c.QuotaMax["t"]) + " kb<=" + i(c.QuotaMax["kb"]) + " n<=" + i(c.QuotaMax["n"]) + " inbox<=" + i(c.QuotaMax["inbox"]) + ", stewards <= " + i(c.MaxStewards) + ", " + i(c.MaxConsecutiveTerms) + " terms",
		"fixed: caps, scrub, lexicon, reports, freeze/purge, abuse contact, content-blind moderation, platform stewards, treasury buys no weight, untrusted banner, operator approval of platform docs",
	}, "\n")
}
