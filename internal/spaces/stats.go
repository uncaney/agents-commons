package spaces

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/trust"
)

// Capture-index thresholds (18.3): a top super-group above ConcentratedAt earns the `concentrated`
// badge (rule/member proposals then need 3/4 and +48 h in gov); fewer than MinGroups eligible
// super-groups refuse rule changes.
const (
	ConcentratedAt = 0.5
	MinGroups      = 3
	statsSample    = 5000
)

// Stats is one space_stats row (18.3).
type Stats struct {
	Members         int
	EligibleW       float64
	Groups          int
	TopGroupShare   float64 // share of eligible weight held by the largest /24 (/48) super-group
	TopGroup64Share float64 // same at the /32 (/64) group key
	Top5Share       float64
	Passed, Failed  int
}

// ComputeStats measures the capture index of a space now (not stored): eligible weight is
// trust.GovWeight per member (age >= 7 d, rep >= 5, verified contribution within 60 d, member
// for rules.vote.min_member_h), grouped by the super-group and group of each root's reg_ip.
func ComputeStats(ctx context.Context, q core.Q, slug string) (Stats, error) {
	var st Stats
	rules, err := RulesOf(ctx, q, slug)
	if err != nil {
		return st, err
	}
	rows, err := q.Query(ctx, `SELECT i.id, i.rep, i.created, i.reg_ip, i.seed, i.revoked_at IS NOT NULL, i.last_verified_at, m.since
		FROM space_members m JOIN identities i ON i.id = m.root WHERE m.space = $1 LIMIT $2`, slug, statsSample)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	bySuper, byGroup := map[string]float64{}, map[string]float64{}
	for rows.Next() {
		var s trust.Standing
		var ip string
		var revoked bool
		var lastVerified *time.Time
		var since time.Time
		if err := rows.Scan(&s.Root, &s.Rep, &s.Created, &ip, &s.Seed, &revoked, &lastVerified, &since); err != nil {
			return st, err
		}
		st.Members++
		s.Age = time.Since(s.Created)
		s.Banned = revoked || s.Rep <= -10
		if lastVerified != nil {
			s.LastVerified = *lastVerified
		}
		w := trust.GovWeight(s, since, rules.Vote.MinMemberH)
		if w <= 0 {
			continue
		}
		st.EligibleW += w
		if ip != "" {
			bySuper[core.IPSuper(ip)] += w
			byGroup[core.IPGroup(ip)] += w
		}
	}
	if err := rows.Err(); err != nil {
		return st, err
	}
	st.Groups = len(bySuper)
	if st.EligibleW > 0 {
		supers := make([]float64, 0, len(bySuper))
		for _, w := range bySuper {
			supers = append(supers, w)
		}
		sort.Sort(sort.Reverse(sort.Float64Slice(supers)))
		if len(supers) > 0 {
			st.TopGroupShare = supers[0] / st.EligibleW
		}
		var top5 float64
		for i, w := range supers {
			if i >= 5 {
				break
			}
			top5 += w
		}
		st.Top5Share = top5 / st.EligibleW
		for _, w := range byGroup {
			if share := w / st.EligibleW; share > st.TopGroup64Share {
				st.TopGroup64Share = share
			}
		}
	}
	if ProposalCountsFn != nil {
		if st.Passed, st.Failed, err = ProposalCountsFn(ctx, q, slug); err != nil {
			return st, err
		}
	}
	return st, nil
}

// StoreStats upserts today's row.
func StoreStats(ctx context.Context, q core.Q, slug string, st Stats) error {
	_, err := q.Exec(ctx, `INSERT INTO space_stats (space, day, members, eligible_w, groups, top_group_share, top_group64_share, top5_share, passed, failed)
		VALUES ($1, current_date, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (space, day) DO UPDATE SET members = EXCLUDED.members, eligible_w = EXCLUDED.eligible_w, groups = EXCLUDED.groups,
		  top_group_share = EXCLUDED.top_group_share, top_group64_share = EXCLUDED.top_group64_share, top5_share = EXCLUDED.top5_share,
		  passed = EXCLUDED.passed, failed = EXCLUDED.failed`,
		slug, st.Members, st.EligibleW, st.Groups, st.TopGroupShare, st.TopGroup64Share, st.Top5Share, st.Passed, st.Failed)
	return err
}

// RunStats computes and stores today's row for live spaces that lack one (janitor; <= 200 per run,
// so the nightly pass spreads over a few ticks on a large instance).
func RunStats(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `SELECT s.slug FROM spaces s WHERE NOT s.archived
		AND NOT EXISTS (SELECT 1 FROM space_stats t WHERE t.space = s.slug AND t.day = current_date) ORDER BY s.created LIMIT 200`)
	if err != nil {
		return err
	}
	var slugs []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return err
		}
		slugs = append(slugs, s)
	}
	rows.Close()
	for _, slug := range slugs {
		st, err := ComputeStats(ctx, q, slug)
		if err != nil {
			return err
		}
		if err := StoreStats(ctx, q, slug, st); err != nil {
			return err
		}
	}
	return nil
}

// LatestStats returns the newest stored row of a space (ok false when none).
func LatestStats(ctx context.Context, q core.Q, slug string) (Stats, time.Time, bool, error) {
	var st Stats
	var day time.Time
	err := q.QueryRow(ctx, `SELECT day, members, eligible_w, groups, top_group_share, top_group64_share, top5_share, passed, failed
		FROM space_stats WHERE space = $1 ORDER BY day DESC LIMIT 1`, slug).
		Scan(&day, &st.Members, &st.EligibleW, &st.Groups, &st.TopGroupShare, &st.TopGroup64Share, &st.Top5Share, &st.Passed, &st.Failed)
	if errors.Is(err, errNoRows) {
		return st, day, false, nil
	}
	return st, day, err == nil, err
}

// CaptureLine renders the sg `capture:` field: `0.18 groups 11` (top super-group share of eligible
// weight, distinct eligible super-groups) or `n/a` before the first nightly run.
func CaptureLine(st Stats, ok bool) string {
	if !ok {
		return "n/a"
	}
	s := fmt.Sprintf("%s groups %d", strconv.FormatFloat(st.TopGroupShare, 'f', 2, 64), st.Groups)
	if st.TopGroupShare > ConcentratedAt {
		s += " concentrated"
	}
	return s
}

// Concentrated reports a capture index above ConcentratedAt in the latest stats (gov: 3/4 + 48 h).
func Concentrated(ctx context.Context, q core.Q, slug string) (bool, error) {
	st, _, ok, err := LatestStats(ctx, q, slug)
	return ok && st.TopGroupShare > ConcentratedAt, err
}

// RunArchive archives spaces idle for IdleDays with fewer than ArchiveMinMembers members (18.3);
// seed spaces of the system root never archive. Returns the slugs archived.
func RunArchive(ctx context.Context, q core.Q) ([]string, error) {
	rows, err := q.Query(ctx, `UPDATE spaces s SET archived = true, archived_at = now()
		WHERE NOT s.archived AND s.members < $1 AND s.creator_root <> $3
		  AND GREATEST(s.last_write,
		        coalesce((SELECT max(created) FROM kb WHERE kb.space = s.slug), '-infinity'::timestamptz),
		        coalesce((SELECT max(created) FROM tasks WHERE tasks.space = s.slug), '-infinity'::timestamptz),
		        coalesce((SELECT max(updated) FROM space_docs WHERE space_docs.space = s.slug), '-infinity'::timestamptz))
		      < now() - ($2 || ' days')::interval
		RETURNING s.slug`, ArchiveMinMembers, strconv.Itoa(IdleDays), core.SystemID)
	if err != nil {
		return nil, err
	}
	var slugs []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return nil, err
		}
		slugs = append(slugs, s)
	}
	rows.Close()
	for _, slug := range slugs {
		cachePut(slug, nil)
		if err := modLog(ctx, q, slug, core.SystemID, "s:"+slug, "archive", fmt.Sprintf("idle %d d, members < %d", IdleDays, ArchiveMinMembers)); err != nil {
			return slugs, err
		}
		if err := core.Event(ctx, q, "space", "s:"+slug, "", "space "+slug+" archived"); err != nil {
			return slugs, err
		}
	}
	return slugs, nil
}

// distinctSupers counts the distinct super-groups of a space's members (from their reg_ip).
func distinctSupers(ctx context.Context, q core.Q, slug string) (int, error) {
	rows, err := q.Query(ctx, `SELECT i.reg_ip FROM space_members m JOIN identities i ON i.id = m.root
		WHERE m.space = $1 AND i.reg_ip <> '' AND i.revoked_at IS NULL LIMIT $2`, slug, statsSample)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return 0, err
		}
		seen[core.IPSuper(ip)] = true
	}
	return len(seen), rows.Err()
}

// Indexable is the 4.5 predicate for a space: creator L2 AND >= 3 members from distinct
// super-groups AND docs clean (no lexicon flags, no hazard families) AND age >= 1 h, and not
// hidden/frozen/archived. Pages, the spaces sitemap and llms.txt consult only this.
func Indexable(ctx context.Context, q core.Q, sp *Space) (bool, error) {
	if sp.Hidden || sp.Frozen || sp.Archived {
		return false, nil
	}
	st, err := trust.Load(ctx, q, sp.CreatorRoot)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	supers, err := distinctSupers(ctx, q, sp.Slug)
	if err != nil {
		return false, err
	}
	var flags, hazard []string
	if err := q.QueryRow(ctx, `SELECT coalesce((SELECT array_agg(DISTINCT f) FROM space_docs d, unnest(d.flags) f WHERE d.space = $1), '{}'),
		coalesce((SELECT array_agg(DISTINCT h) FROM space_docs d, unnest(d.hazard) h WHERE d.space = $1), '{}')`, sp.Slug).Scan(&flags, &hazard); err != nil {
		return false, err
	}
	return trust.Indexable("space", trust.IndexInput{Author: st, Age: time.Since(sp.Created), SpaceMembers: supers,
		Flags: flags, Hazard: hazard}), nil
}
