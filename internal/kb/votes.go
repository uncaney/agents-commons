package kb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// Votes (SPEC-v2 6.3, 4.1, 4.2, 4.4, 4.7): one vote per root per entry, weighted by trust.Weight
// (seed roots weigh 0 and are recorded with seed=true), summed per super-group (only the
// max-weight voter of a network counts), driving promotion out of quarantine, hiding, restore,
// reputation and the saved-tokens ledger.

// VoteInput is the body of POST /v1/kb/{id}/ok|bad and of the ok/bad ops.
type VoteInput struct {
	Up      bool    `json:"-"`
	V       string  `json:"v"`     // ok: what worked (<= 120)
	Why     string  `json:"why"`   // bad: what failed (<= 200)
	Saved   int     `json:"saved"` // ok: tokens the entry saved (0..50000)
	Applies Applies `json:"applies"`
}

// VoteResult is what a vote changed.
type VoteResult struct {
	Up                                         bool
	OkW, BadW                                  float32
	Promoted, Hidden, Restored, Deleted, Split bool
}

// Line is the reply head: `ok ok<w>` for confirmations (v1), `ok` for reports, plus markers.
func (r VoteResult) Line() string {
	s := "ok"
	if r.Up {
		s += " ok" + fw(r.OkW)
	}
	for _, m := range []struct {
		on   bool
		mark string
	}{{r.Promoted, "promoted"}, {r.Restored, "restored"}, {r.Hidden, "hidden"}, {r.Split, "split"}, {r.Deleted, "deleted"}} {
		if m.on {
			s += " " + m.mark
		}
	}
	return s
}

// Next are the actions after a vote.
func (r VoteResult) Next(id string) []doc.Action {
	if r.Deleted {
		return doc.Next(doc.GET("/quarantine", ""))
	}
	return doc.Next(doc.GET("/v1/kb/"+id, ""), doc.GET("/k/"+id+".md", ""))
}

func (r VoteResult) json() map[string]any {
	m := map[string]any{"ok": true, "ok_w": r.OkW, "bad_w": r.BadW}
	for k, v := range map[string]bool{"promoted": r.Promoted, "hidden": r.Hidden, "restored": r.Restored, "deleted": r.Deleted, "split": r.Split} {
		if v {
			m[k] = true
		}
	}
	return m
}

// vote is one kb_votes row with its voter's standing (level computed from the joined identity).
type vote struct {
	root    string
	up      bool
	w       float64
	note    string
	seed    bool
	super   string
	netKey  string
	applies Applies
	saved   int
	liable  bool
	created time.Time
	lvl     int
}

// loadVotes reads every vote of an entry with the voter's level (trust.Standing.Level on the
// identity columns; upheld reports ignored) and its network key (trust.NetKeySQL: ASN-aware).
func loadVotes(ctx context.Context, q core.Q, kbID string) ([]vote, error) {
	rows, err := q.Query(ctx, `SELECT v.root, v.up, v.w, v.note, v.seed, v.ip_super, `+trust.NetKeySQL("v")+`, coalesce(v.applies::text, ''), v.saved, v.liable, v.created,
		coalesce(r.rep, 0), r.created, coalesce(r.seed, false), coalesce(r.verified_noncompute, 0), r.revoked_at IS NOT NULL,
		EXISTS (SELECT 1 FROM vouches vo JOIN identities vr ON vr.id = vo.voucher WHERE vo.vouchee = v.root AND vr.revoked_at IS NULL)
		FROM kb_votes v LEFT JOIN identities r ON r.id = v.root WHERE v.kb_id = $1 ORDER BY v.created, v.root`, kbID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []vote
	for rows.Next() {
		var v vote
		var w float32
		var applies string
		var rep, vnc int
		var created *time.Time
		var rSeed, revoked, vouched bool
		if err := rows.Scan(&v.root, &v.up, &w, &v.note, &v.seed, &v.super, &v.netKey, &applies, &v.saved, &v.liable, &v.created,
			&rep, &created, &rSeed, &vnc, &revoked, &vouched); err != nil {
			return nil, err
		}
		v.w = float64(w)
		v.applies = decodeApplies([]byte(applies))
		if v.netKey == "" {
			v.netKey = "root:" + v.root // legacy rows without a network key count on their own
		}
		if created != nil {
			st := trust.Standing{Root: v.root, Rep: rep, Created: *created, Age: time.Since(*created), Seed: rSeed, Vouched: vouched, VerifiedNonCompute: vnc}
			st.Banned = rep <= bannedRep || revoked
			v.lvl = st.Level()
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// collapse sums the max weight per network key over the votes keep selects (4.1); in ASN mode at
// most 3 keys of one hosting ASN count (27.8).
func collapse(vs []vote, keep func(vote) bool) float64 {
	best := map[string]float64{}
	for _, v := range vs {
		if !keep(v) {
			continue
		}
		if w, ok := best[v.netKey]; !ok || v.w > w {
			best[v.netKey] = v.w
		}
	}
	perASN := map[string][]float64{}
	sum := 0.0
	for k, w := range best {
		if strings.HasPrefix(k, "asn:") {
			part, _, _ := strings.Cut(k, "|")
			perASN[part] = append(perASN[part], w)
			continue
		}
		sum += w
	}
	for _, ws := range perASN {
		sort.Sort(sort.Reverse(sort.Float64Slice(ws)))
		for i, w := range ws {
			if i == 3 {
				break
			}
			sum += w
		}
	}
	return sum
}

// l2Confirms counts the distinct super-groups of L2 confirmations other than the author's (4.5).
func l2Confirms(vs []vote, authorSuper string) int {
	seen := map[string]bool{}
	for _, v := range vs {
		if v.up && !v.seed && v.w > 0 && v.lvl >= 2 && v.super != "" && v.super != authorSuper {
			seen[v.super] = true
		}
	}
	return len(seen)
}

// inRange reports whether a bad vote counts toward hiding: no applies, or a range the entry does
// not declare differently (otherwise the vote split a range, 6.3).
func inRange(v vote, e *Entry) bool {
	if v.up || len(v.applies) == 0 {
		return true
	}
	_, split := splitRange(e.Applies, v.applies)
	return !split
}

// chooseDistinct picks up to need L2 ok voters that are pairwise distinct (trust.Distinct: root,
// super-group or ASN key, cohort) and in another super-group than the author's; ok when found.
func chooseDistinct(ctx context.Context, q core.Q, vs []vote, authorRoot, authorSuper string, need int) ([]string, bool, error) {
	var cands []vote
	for _, v := range vs {
		if v.up && !v.seed && v.w > 0 && v.lvl >= 2 && v.root != authorRoot && (authorSuper == "" || v.super != authorSuper) {
			cands = append(cands, v)
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].w > cands[j].w })
	var chosen []string
	for _, c := range cands {
		ok, err := trust.Distinct(ctx, q, append(append([]string(nil), chosen...), c.root)...)
		if err != nil {
			return nil, false, err
		}
		if ok {
			chosen = append(chosen, c.root)
		}
		if len(chosen) >= need {
			return chosen, true, nil
		}
	}
	return chosen, false, nil
}

// lockEntry loads an entry of any state FOR UPDATE (expired rows are not found).
func lockEntry(ctx context.Context, q core.Q, id string) (*Entry, error) {
	if !core.ValidIDPrefix(id, 'k') {
		return nil, core.ErrNotFound
	}
	return scanEntry(q.QueryRow(ctx, entrySelect(cols(ctx, q))+` WHERE k.id = $1 AND k.expires_at > now() FOR UPDATE OF k`, id))
}

// mergedBonus is the weight an entry inherits from rows merged into it (6.3: 0.5 x B.ok_w).
func mergedBonus(ctx context.Context, q core.Q, id string) (float64, error) {
	var b float64
	err := q.QueryRow(ctx, `SELECT coalesce(sum(ok_w), 0)::float8 * 0.5 FROM kb WHERE superseded_by = $1`, id).Scan(&b)
	return b, err
}

// Vote records an ok/bad vote (one per root per entry, no self-vote) and applies weights/rep.
// Returns the entry's new ok_w (v1 signature).
func Vote(ctx context.Context, d *core.Deps, id *core.Ident, kid string, up bool, note string) (float32, error) {
	in := VoteInput{Up: up}
	if up {
		in.V = note
	} else {
		in.Why = note
	}
	res, err := VoteV2(ctx, d, id, kid, in)
	return res.OkW, err
}

// VoteV2 is the v2 vote (6.3): weight trust.DampedWeight (0 for seed roots, stored seed=true),
// network keys stored, collapsed sums recomputed in the tx, promotion (4.4), hiding (L1+
// weights in the same applies range; a narrower range splits instead), restore (4.7), reputation
// (4.2) and saved accrual (16.4). L2 roots may confirm a hidden entry (restore votes); everyone
// else sees hidden rows as not found.
func VoteV2(ctx context.Context, d *core.Deps, id *core.Ident, kid string, in VoteInput) (VoteResult, error) {
	res := VoteResult{Up: in.Up}
	if !core.ValidIDPrefix(kid, 'k') {
		return res, core.ErrNotFound
	}
	note, max := in.Why, maxWhy
	if in.Up {
		note, max = in.V, maxVoteNote
	}
	if len(note) > max {
		return res, core.Bad(fmt.Sprintf("note > %d bytes", max))
	}
	note = cleanMulti(note)
	if in.Saved < 0 || in.Saved > maxSaved {
		return res, core.Bad("saved must be 0..50000")
	}
	if err := in.Applies.Validate(); err != nil {
		return res, err
	}
	st, err := trust.Load(ctx, d.DB, id.Root)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return res, core.ErrBadToken
		}
		return res, err
	}
	lvl := st.Level()
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		e, err := lockEntry(ctx, tx, kid)
		if err != nil {
			return err
		}
		if e.SupersededBy != "" || e.Hidden && !(in.Up && lvl >= 2) {
			return core.ErrNotFound
		}
		if e.AuthorRoot != "" && e.AuthorRoot == id.Root {
			return core.E(403, "auth", "no self vote")
		}
		w := trust.DampedWeight(ctx, tx, st, e.AuthorRoot)
		grp, super := st.Group, st.Super
		if super == "" {
			_, grp, super = core.ClientFrom(ctx)
		}
		var split Applies
		if !in.Up && len(in.Applies) > 0 {
			split, _ = splitRange(e.Applies, in.Applies)
		}
		var applies any
		if len(in.Applies) > 0 {
			applies = string(in.Applies.JSON())
		}
		if _, err := tx.Exec(ctx, `INSERT INTO kb_votes (kb_id, root, up, w, note, ip_group, ip_super, applies, saved, seed) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)`,
			kid, id.Root, in.Up, float32(w), note, grp, super, applies, in.Saved, st.Seed); err != nil {
			if core.IsUniqueViolation(err) {
				return core.E(409, "dup", "already voted")
			}
			return err
		}
		if len(split) > 0 {
			e.Applies = withFails(e.Applies, split)
			if _, err := tx.Exec(ctx, `UPDATE kb SET applies = $2::jsonb WHERE id = $1`, kid, string(e.Applies.JSON())); err != nil {
				return err
			}
			res.Split = true
		}
		vs, err := loadVotes(ctx, tx, kid)
		if err != nil {
			return err
		}
		bonus, err := mergedBonus(ctx, tx, kid)
		if err != nil {
			return err
		}
		authorSuper := authorSuperOf(e)
		okW := collapse(vs, func(v vote) bool { return v.up && !v.seed }) + bonus
		badW := collapse(vs, func(v vote) bool { return !v.up && !v.seed && inRange(v, e) })
		hideW := collapse(vs, func(v vote) bool { return !v.up && !v.seed && v.lvl >= 1 && inRange(v, e) })
		res.OkW, res.BadW = float32(okW), float32(badW)
		if e.Quarantine {
			switch {
			case in.Up && lvl >= 2 && w > 0:
				chosen, ok, err := chooseDistinct(ctx, tx, vs, e.AuthorRoot, authorSuper, 2)
				if err != nil {
					return err
				}
				if ok {
					if _, err := tx.Exec(ctx, `UPDATE kb SET quarantine = false, confirmed_at = now(), ok_w = $2, bad_w = $3 WHERE id = $1`, kid, okW, badW); err != nil {
						return err
					}
					if _, err := tx.Exec(ctx, `UPDATE kb_votes SET liable = true WHERE kb_id = $1 AND root = ANY($2)`, kid, chosen); err != nil {
						return err
					}
					res.Promoted = true
					if err := core.Event(ctx, tx, "kb", kid, "", e.Title); err != nil {
						return err
					}
					if e2, err := GetV2(ctx, tx, kid, GetOpts{}); err == nil && indexableSoon(e2) {
						indexNow(ctx, tx, kid, e2.Libs, e2.Tags)
					}
					return mirror(ctx, tx, kid)
				}
			case !in.Up && lvl >= 2 && w > 0:
				res.Deleted = true
				return Remove(ctx, tx, kid, "hidden", "")
			}
			_, err := tx.Exec(ctx, `UPDATE kb SET ok_w = $2, bad_w = $3 WHERE id = $1`, kid, okW, badW)
			return err // pending rows: voters earn nothing, nothing is mirrored
		}
		if in.Up {
			sql := `UPDATE kb SET ok_w = $2, bad_w = $3, confirmed_at = now() WHERE id = $1`
			if e.Kind != "status" {
				sql = `UPDATE kb SET ok_w = $2, bad_w = $3, confirmed_at = now(), expires_at = greatest(expires_at, now() + interval '180 days') WHERE id = $1`
			}
			if _, err := tx.Exec(ctx, sql, kid, okW, badW); err != nil {
				return err
			}
			if e.Hidden {
				if _, ok, err := chooseDistinct(ctx, tx, vs, e.AuthorRoot, authorSuper, 3); err != nil {
					return err
				} else if ok {
					if _, err := tx.Exec(ctx, `UPDATE kb SET hidden = false, restored_at = now(), immune_until = now() + $2::interval WHERE id = $1`, kid, immuneFor.String()); err != nil {
						return err
					}
					res.Restored = true
					e.Hidden = false
				}
			}
			if lvl >= 2 && w > 0 && !st.Seed && !e.Seed && e.AuthorRoot != "" {
				if distinct, err := trust.Distinct(ctx, tx, id.Root, e.AuthorRoot); err != nil {
					return err
				} else if distinct {
					if _, err := core.AddRep(ctx, tx, e.AuthorRoot, 1, "rep:kbin", 2); err != nil {
						return err
					}
					if ent, err := trust.ConfirmerEntropy(ctx, tx, id.Root); err != nil {
						return err
					} else if ent {
						if err := trust.Verified(ctx, tx, e.AuthorRoot, true); err != nil {
							return err
						}
					}
				}
			}
			if in.Saved > 0 && e.AuthorRoot != "" && SavedHook != nil && w > 0 {
				est := (len(e.Fix) + len(e.Cause) + len(e.Symptom)) / 4
				if n := min(in.Saved, 2*est); n > 0 {
					if err := SavedHook(ctx, tx, e.AuthorRoot, "kb", n); err != nil {
						return err
					}
				}
			}
			if lvl >= 2 && w > 0 && !e.Hidden {
				if e2, err := GetV2(ctx, tx, kid, GetOpts{}); err == nil && e2.L2Confirms == 1 && indexableSoon(e2) {
					indexNow(ctx, tx, kid, e2.Libs, e2.Tags) // first L2 confirmation (9.6)
				}
			}
			return mirror(ctx, tx, kid)
		}
		hidden := !e.Hidden && hideW >= okW+2
		if _, err := tx.Exec(ctx, `UPDATE kb SET ok_w = $2, bad_w = $3, hidden = hidden OR $4, hidden_at = CASE WHEN $4 THEN now() ELSE hidden_at END WHERE id = $1`,
			kid, okW, badW, hidden); err != nil {
			return err
		}
		if hidden {
			res.Hidden = true
			if e.AuthorRoot != "" && !e.Seed {
				if _, err := core.AddRep(ctx, tx, e.AuthorRoot, -1, "", 0); err != nil {
					return err
				}
			}
			// Promoters of a quarantined row that later gets hidden by votes lose 2 rep (4.4).
			rows, err := tx.Query(ctx, `UPDATE kb_votes SET liable = false WHERE kb_id = $1 AND liable RETURNING root`, kid)
			if err != nil {
				return err
			}
			var liable []string
			for rows.Next() {
				var r string
				if err := rows.Scan(&r); err != nil {
					rows.Close()
					return err
				}
				liable = append(liable, r)
			}
			rows.Close()
			for _, r := range liable {
				if _, err := core.AddRep(ctx, tx, r, -2, "rep:liable", 0); err != nil {
					return err
				}
			}
			indexNow(ctx, tx, kid, nil, e.Tags)
			core.ExportRemove(ctx, "kb", kid)
		}
		return mirror(ctx, tx, kid)
	})
	return res, err
}

// recount recomputes the collapsed sums of an entry from its votes (after a purge removed some).
func recount(ctx context.Context, q core.Q, id string) error {
	e, err := loadEntry(ctx, q, id, GetOpts{IncHidden: true, IncQuarantine: true})
	if err != nil {
		return err
	}
	vs, err := loadVotes(ctx, q, id)
	if err != nil {
		return err
	}
	bonus, err := mergedBonus(ctx, q, id)
	if err != nil {
		return err
	}
	okW := collapse(vs, func(v vote) bool { return v.up && !v.seed }) + bonus
	badW := collapse(vs, func(v vote) bool { return !v.up && !v.seed && inRange(v, e) })
	if _, err := q.Exec(ctx, `UPDATE kb SET ok_w = $2, bad_w = $3 WHERE id = $1`, id, okW, badW); err != nil {
		return err
	}
	return mirror(ctx, q, id)
}

// Hide marks an entry hidden (moderation by votes), penalises the author (rep -1) and updates the mirror.
func Hide(ctx context.Context, q core.Q, id string) error { return HideBy(ctx, q, id, "votes") }

// HideNoPenalty hides an entry without touching the author's reputation: for report-triggered
// hides, where the reporters (not a vote) decided and Sybil reports must not be able to ban authors.
func HideNoPenalty(ctx context.Context, q core.Q, id string) error {
	return HideBy(ctx, q, id, "report")
}

// HideBy hides an entry for a reason: `votes` (author rep -1, purged after 30 d without restore),
// `report` (no penalty, respects a restore's 30 d immunity, purged after 30 d), `notice` (no
// penalty, ignores immunity, never auto-purged: waits for the operator, 4.8). Unknown or
// malformed ids and already-hidden rows are a no-op.
func HideBy(ctx context.Context, q core.Q, id, reason string) error {
	if !core.ValidIDPrefix(id, 'k') {
		return nil
	}
	immune, stamp, penalty := false, true, false
	switch reason {
	case "votes":
		penalty = true
	case "report":
		immune = true
	case "notice":
		stamp = false
	default:
		return core.Bad("hide reason")
	}
	var root string
	var seed bool
	var tags []string
	err := q.QueryRow(ctx, `UPDATE kb SET hidden = true, hidden_at = CASE WHEN $2 THEN now() ELSE hidden_at END WHERE id = $1 AND NOT hidden
		AND NOT ($3 AND immune_until IS NOT NULL AND immune_until > now()) RETURNING author_root, seed, tags`, id, stamp, immune).Scan(&root, &seed, &tags)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if penalty && root != "" && !seed {
		if _, err := core.AddRep(ctx, q, root, -1, "", 0); err != nil {
			return err
		}
	}
	indexNow(ctx, q, id, nil, tags)
	core.ExportRemove(ctx, "kb", id)
	return enqueue(ctx, q, id, "")
}

// Restore un-hides an entry (appeal upheld, 4.7): restored_at = now, immune to report-hides for
// 30 d; mirror and IndexNow learn about it. Report target Restore.
func Restore(ctx context.Context, q core.Q, id string) error {
	if !core.ValidIDPrefix(id, 'k') {
		return core.ErrNotFound
	}
	tag, err := q.Exec(ctx, `UPDATE kb SET hidden = false, restored_at = now(), immune_until = now() + $2::interval WHERE id = $1 AND hidden`, id, immuneFor.String())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if e, err := GetV2(ctx, q, id, GetOpts{}); err == nil && indexableSoon(e) {
		indexNow(ctx, q, id, e.Libs, e.Tags)
	}
	return mirror(ctx, q, id)
}

// fixPatch is a kbfix patch (18.6): partial fields, <= 3000 B.
type fixPatch struct {
	Cause    *string   `json:"cause"`
	Fix      *string   `json:"fix"`
	Versions *string   `json:"versions"`
	Tags     *[]string `json:"tags"`
	Applies  *Applies  `json:"applies"`
}

const maxPatch = 3000

// ApplyFix applies a kbfix proposal to an entry inside the caller's tx (6.3, 18.6): the patched
// fields re-run scrub/lexicon/hazards, `rev` increments, `edited_by` = by (a proposal or identity
// id), `edited_after_confirm` is set, ok_w moves to ok_w_prev and resets to 0 (prior ok votes are
// removed so the entry leaves the index until two fresh L2 confirmations; bad votes and their
// failing ranges stay); confirmed_at is NOT refreshed. Returns the previous field snapshot for a
// one-call revert.
func ApplyFix(ctx context.Context, tx core.Q, id string, patch json.RawMessage, by string) (json.RawMessage, error) {
	if len(patch) > maxPatch {
		return nil, core.E(413, "size", "patch > 3000 bytes")
	}
	var p fixPatch
	dec := json.NewDecoder(strings.NewReader(string(patch)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, core.Bad("patch: " + err.Error())
	}
	e, err := lockEntry(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	prev, _ := json.Marshal(map[string]any{"cause": e.Cause, "fix": e.Fix, "versions": e.Versions, "tags": e.Tags, "applies": e.Applies, "ok_w": e.OkW, "rev": e.Rev})
	in := Input{Kind: e.Kind, Title: e.Title, Symptom: e.Symptom, Cause: e.Cause, Fix: e.Fix, Versions: e.Versions, Tags: append([]string{}, e.Tags...),
		Applies: e.Applies, License: e.License, WhySafe: e.WhySafe, Att: e.Att, Space: e.Space}
	var changed []string
	set := func(name string, dst *string, src *string) {
		if src != nil && *src != *dst {
			changed = append(changed, "-"+name+": "+indent(*dst)+"\n+"+name+": "+indent(*src))
			*dst = *src
		}
	}
	set("cause", &in.Cause, p.Cause)
	set("fix", &in.Fix, p.Fix)
	set("versions", &in.Versions, p.Versions)
	if p.Tags != nil {
		changed = append(changed, "-tags: "+strings.Join(in.Tags, ",")+"\n+tags: "+strings.Join(*p.Tags, ","))
		in.Tags = *p.Tags
	}
	if p.Applies != nil {
		changed = append(changed, "-applies: "+in.Applies.String()+"\n+applies: "+p.Applies.String())
		in.Applies = *p.Applies
	}
	if len(changed) == 0 {
		return prev, core.Bad("patch changes nothing")
	}
	pf, err := Prepare(ctx, tx, &in, 2) // voted patches skip the first-seen-domain rule
	if err != nil {
		return nil, err
	}
	var rev int
	if err := tx.QueryRow(ctx, `UPDATE kb SET cause = $2, fix = $3, versions = $4, tags = $5, applies = $6::jsonb, hazard = $7, flags = $8,
		rev = rev + 1, edited_by = $9, edited_after_confirm = true, ok_w_prev = ok_w, ok_w = 0 WHERE id = $1 RETURNING rev`,
		id, in.Cause, in.Fix, in.Versions, in.Tags, string(in.Applies.JSON()), pf.Hazard, pf.Flags, doc.SafeLine(by)).Scan(&rev); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM kb_votes WHERE kb_id = $1 AND up`, id); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM kb_versions WHERE kb_id = $1`, id); err != nil {
		return nil, err
	}
	for _, lv := range pf.Libs {
		if _, err := tx.Exec(ctx, `INSERT INTO kb_versions (kb_id, lib, ver) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, id, lv.Lib, lv.Ver); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO kb_revisions (kb_id, n, diff, by) VALUES ($1, $2, $3, $4) ON CONFLICT (kb_id, n) DO UPDATE SET diff = EXCLUDED.diff, by = EXCLUDED.by, at = now()`,
		id, rev, strings.Join(changed, "\n"), doc.SafeLine(by)); err != nil {
		return nil, err
	}
	indexNow(ctx, tx, id, pf.Libs, in.Tags)
	return prev, mirror(ctx, tx, id)
}

// Merge folds entry from into entry into (kbmerge, 6.3): from.superseded_by = into (its permalink
// answers `moved`, pages 301), into.ok_w += 0.5 x from.ok_w, tombstone `merged` with the successor.
func Merge(ctx context.Context, tx core.Q, from, into string) error {
	if from == into || !core.ValidIDPrefix(from, 'k') || !core.ValidIDPrefix(into, 'k') {
		return core.Bad("merge needs two different entry ids")
	}
	a, err := lockEntry(ctx, tx, into)
	if err != nil {
		return err
	}
	if a.Hidden || a.Quarantine || a.SupersededBy != "" {
		return core.Bad("merge target must be visible")
	}
	b, err := lockEntry(ctx, tx, from)
	if err != nil {
		return err
	}
	if b.SupersededBy != "" {
		return core.E(409, "dup", "already merged into "+b.SupersededBy)
	}
	if _, err := tx.Exec(ctx, `UPDATE kb SET superseded_by = $2 WHERE id = $1`, from, into); err != nil {
		return err
	}
	if err := tombstone(ctx, tx, from, b.Title, "merged", into); err != nil {
		return err
	}
	if err := enqueue(ctx, tx, from, ""); err != nil {
		return err
	}
	indexNow(ctx, tx, from, nil, b.Tags)
	core.ExportRemove(ctx, "kb", from)
	return recount(ctx, tx, into)
}
