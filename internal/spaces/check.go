package spaces

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/trust"
)

// Check enforces a space's rules for one write by root (18.3): the space must be live, root not
// banned, the write policy (t/kb/n: rules.write; inbox: rules.inbox; join: none) satisfied, then
// the per-member daily quota under counter sp:<slug>:<root> and the space-wide cap under
// sp:<slug> (SpaceCaps). Counters are charged even when the write is refused, like core.UseQuota.
func Check(ctx context.Context, q core.Q, slug, root, action string) error {
	sp, err := Get(ctx, q, slug)
	if err != nil {
		return err
	}
	if err := sp.Gone(); err != nil {
		if sp.Hidden && !sp.Archived {
			return core.E(403, "auth", "space hidden (read-only)")
		}
		return err
	}
	if sp.Frozen {
		return core.E(503, "frozen", "space "+slug)
	}
	if until, ok, err := banned(ctx, q, slug, root); err != nil {
		return err
	} else if ok {
		return core.E(403, "auth", "banned in space until "+core.Date(until))
	}
	role, err := Role(ctx, q, slug, root)
	if err != nil {
		return err
	}
	rules := sp.Rules
	switch action {
	case "join":
	case "inbox":
		switch rules.Inbox {
		case "closed":
			return core.E(403, "auth", "inbox closed")
		case "members":
			if role == "" {
				return core.E(403, "auth", "members only")
			}
		}
	case "t", "kb", "n":
		switch rules.Write {
		case "stewards":
			if role != "steward" {
				return core.E(403, "auth", "stewards only")
			}
		case "members":
			if role == "" {
				return core.E(403, "auth", "members only")
			}
		case "established":
			if role == "" {
				st, err := trust.Load(ctx, q, root)
				if err != nil {
					return err
				}
				if !(st.Seed || (st.Rep >= 5 && st.Age >= core.EstablishedAge)) {
					return core.E(403, "auth", "established only (rep >= 5, age >= 72 h) or members")
				}
			}
		}
	default:
		return core.Bad("unknown space action " + action)
	}
	if limit := rules.QuotaFor(action); limit > 0 {
		n, err := bump(ctx, q, "sp:"+slug+":"+root, action)
		if err != nil {
			return err
		}
		if n > limit {
			return core.E(429, "quota", fmt.Sprintf("space %s %d/day", action, limit))
		}
	}
	if cap := SpaceCaps[action]; cap > 0 {
		n, err := bump(ctx, q, "sp:"+slug, action)
		if err != nil {
			return err
		}
		if n > cap {
			return core.E(429, "quota", "space-wide "+action+" cap")
		}
	}
	return nil
}

// Used returns today's per-member counter of an action in a space (for `me`-style lines).
func Used(ctx context.Context, q core.Q, slug, root, action string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT coalesce((SELECT n FROM counters WHERE scope = $1 AND kind = $2 AND day = current_date), 0)`,
		"sp:"+slug+":"+root, action).Scan(&n)
	return n, err
}

// headings lists the `## ` headings of a template doc, lowercased and trimmed, in order.
func headings(tpl string) []string {
	var out []string
	for _, l := range strings.Split(tpl, "\n") {
		if h, ok := strings.CutPrefix(strings.TrimSpace(l), "## "); ok {
			if h = strings.ToLower(strings.TrimSpace(h)); h != "" && len(out) < 16 {
				out = append(out, h)
			}
		}
	}
	return out
}

// CheckTemplate verifies that a post body carries every `## ` heading of the space's tpl-task
// (kind task) or tpl-kb (kind kb) doc when the space's rules enforce that template (18.3). The
// required-headings check itself is never disabled by a rule: only the rule's switch is votable.
func CheckTemplate(ctx context.Context, q core.Q, space, kind, body string) *core.APIError {
	if space == "" || !slugRe.MatchString(space) {
		return nil
	}
	rules, err := RulesOf(ctx, q, space)
	if err != nil {
		return nil
	}
	name := "tpl-task"
	switch kind {
	case "task":
		if !rules.Templates.Task {
			return nil
		}
	case "kb":
		if !rules.Templates.KB {
			return nil
		}
		name = "tpl-kb"
	default:
		return nil
	}
	tpl, err := docText(ctx, q, space, name)
	if err != nil || tpl == "" {
		return nil
	}
	low := strings.ToLower(body)
	for _, h := range headings(tpl) {
		if !strings.Contains(low, "## "+h) {
			return core.E(400, "bad", "template: missing heading '## "+h+"' (see /v1/s/"+space+"/d/"+name+")")
		}
	}
	return nil
}

// TemplateCheck is the forge.TemplateCheck seam shape (task bodies).
func TemplateCheck(ctx context.Context, q core.Q, space, body string) *core.APIError {
	return CheckTemplate(ctx, q, space, "task", body)
}

// RuleChangeAllowed refuses rule changes in spaces whose eligible members span fewer than 3
// super-groups (18.3: `err quota need 3 groups`), from the latest stats or a live computation.
func RuleChangeAllowed(ctx context.Context, q core.Q, slug string) error {
	st, _, ok, err := LatestStats(ctx, q, slug)
	if err != nil {
		return err
	}
	if !ok {
		if st, err = ComputeStats(ctx, q, slug); err != nil {
			return err
		}
	}
	if st.Groups < MinGroups {
		return core.E(429, "quota", fmt.Sprintf("need %d groups", MinGroups))
	}
	return nil
}

// ApplyRules is the gov applier shape for proposal kind `rule` (P60a adapts gov.Proposal onto
// (scope, patch, id)): merges the patch onto the current rules inside tx, bumps rules_rev, logs
// the change and refreshes the cache. Returns the previous rules for one-call revert. The
// platform space's rules are non-amendable (27.5).
func ApplyRules(ctx context.Context, tx core.Q, slug string, patch json.RawMessage, by string) (json.RawMessage, error) {
	if slug == "platform" {
		return nil, core.E(403, "auth", "platform rules are not amendable")
	}
	sp, err := scanSpace(tx.QueryRow(ctx, `SELECT `+spaceCols+` FROM spaces WHERE slug = $1 FOR UPDATE`, slug))
	if err != nil {
		return nil, err
	}
	if err := sp.Gone(); err != nil {
		return nil, err
	}
	if err := RuleChangeAllowed(ctx, tx, slug); err != nil {
		return nil, err
	}
	next, err := Merge(*sp.Rules, patch)
	if err != nil {
		return nil, err
	}
	prev := sp.Rules.JSON()
	if _, err := tx.Exec(ctx, `UPDATE spaces SET rules = $2, rules_rev = rules_rev + 1, last_write = now() WHERE slug = $1`, slug, next.JSON()); err != nil {
		return nil, err
	}
	if by == "" {
		by = "gov"
	}
	why := strings.Join(Diff(sp.Rules, next), "; ")
	if err := modLog(ctx, tx, slug, by, "s:"+slug, "rule", why); err != nil {
		return nil, err
	}
	if err := core.Event(ctx, tx, "space", "s:"+slug, "", "space "+slug+" rules rev "+fmt.Sprint(sp.RulesRev+1)); err != nil {
		return nil, err
	}
	cachePut(slug, next)
	return prev, nil
}

// SetSteward is the member-proposal applier shape: grants (or recalls) a steward term of termD
// days, within MaxStewards. by is the proposal id for the log.
func SetSteward(ctx context.Context, tx core.Q, slug, root string, steward bool, termD int, by string) error {
	sp, err := scanSpace(tx.QueryRow(ctx, `SELECT `+spaceCols+` FROM spaces WHERE slug = $1 FOR UPDATE`, slug))
	if err != nil {
		return err
	}
	if err := sp.Gone(); err != nil {
		return err
	}
	if slug == "platform" {
		return core.E(403, "auth", "platform stewards are not amendable")
	}
	role, err := Role(ctx, tx, slug, root)
	if err != nil {
		return err
	}
	if role == "" {
		return core.E(404, "notfound", "not a member")
	}
	if !steward {
		if _, err := tx.Exec(ctx, `UPDATE space_members SET role = 'member', until = NULL WHERE space = $1 AND root = $2`, slug, root); err != nil {
			return err
		}
		return modLog(ctx, tx, slug, by, root, "recall", "")
	}
	if termD < 1 || termD > 365 {
		return core.Bad("term_d must be 1..365")
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM space_members WHERE space = $1 AND role = 'steward' AND root <> $2`, slug, root).Scan(&n); err != nil {
		return err
	}
	if n >= MaxStewards {
		return core.E(429, "quota", fmt.Sprintf("max %d stewards", MaxStewards))
	}
	// Consecutive-term limit (18.3 MaxTerms): count the root's 'steward' grants since its last
	// 'recall' in this space; a root that already served MaxTerms back to back must sit out a term
	// (break the streak with a recall) before being re-elected.
	var terms int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mod_log
		WHERE space = $1 AND target = $2 AND action = 'steward'
		  AND at > (SELECT coalesce(max(at), 'epoch') FROM mod_log WHERE space = $1 AND target = $2 AND action = 'recall')`,
		slug, root).Scan(&terms); err != nil {
		return err
	}
	if terms >= MaxTerms {
		return core.E(429, "quota", fmt.Sprintf("max %d consecutive terms", MaxTerms))
	}
	until := time.Now().Add(time.Duration(termD) * 24 * time.Hour)
	if _, err := tx.Exec(ctx, `UPDATE space_members SET role = 'steward', until = $3 WHERE space = $1 AND root = $2`, slug, root, until); err != nil {
		return err
	}
	return modLog(ctx, tx, slug, by, root, "steward", fmt.Sprintf("term %dd", termD))
}
