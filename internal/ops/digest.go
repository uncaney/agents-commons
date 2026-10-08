package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

const digestBodyMax = 8192

// WeekStart returns the Monday 00:00 UTC of t's ISO week.
func WeekStart(t time.Time) time.Time {
	t = t.UTC()
	d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	wd := int(d.Weekday()+6) % 7 // Monday = 0
	return d.AddDate(0, 0, -wd)
}

// digestStats are the numbers behind one weekly digest (stored as jsonb next to the text).
type digestStats struct {
	Week       string         `json:"week"`
	Reqs       int64          `json:"reqs"`
	E5xx       int64          `json:"e5xx"`
	ShedS      int64          `json:"shed_s"`
	ShedEvents int64          `json:"shed_events"`
	Reports    int64          `json:"reports"`
	HiddenKB   int64          `json:"hidden_kb"`
	NewRoots   int64          `json:"new_roots"`
	Notices    int64          `json:"notices"`
	AuditFails int64          `json:"audit_fails"`
	Storage    map[string]any `json:"storage"`
}

// WriteDigest stores the digest of the ISO week starting at week (any time inside it) and appends
// core.Event("ops", "digest:<week>"); created is false when the row already existed (two instances
// race on the janitor; the row wins once). 21.4.
func (o *Ops) WriteDigest(ctx context.Context, week time.Time) (created bool, err error) {
	start := WeekStart(week)
	end := start.AddDate(0, 0, 7)
	q := o.q()
	st := digestStats{Week: start.Format("2006-01-02"), Storage: map[string]any{}}
	if err := q.QueryRow(ctx, `SELECT coalesce(sum(reqs), 0), coalesce(sum(e5xx), 0), coalesce(sum(shed_s), 0)
		FROM status_daily WHERE day >= $1 AND day < $2`, start, end).Scan(&st.Reqs, &st.E5xx, &st.ShedS); err != nil {
		return false, err
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE ref LIKE 'shed:%' AND title LIKE 'shed on %'),
		count(*) FILTER (WHERE ref NOT LIKE 'shed:%' AND ref NOT LIKE 'digest:%')
		FROM events WHERE kind = 'ops' AND at >= $1 AND at < $2`, start, end).Scan(&st.ShedEvents, &st.Notices); err != nil {
		return false, err
	}
	if err := q.QueryRow(ctx, `SELECT (SELECT count(*) FROM reports WHERE created >= $1 AND created < $2),
		(SELECT count(*) FROM kb WHERE hidden),
		(SELECT count(*) FROM identities WHERE parent IS NULL AND created >= $1 AND created < $2),
		(SELECT count(*) FROM audit_fail WHERE at >= $1 AND at < $2)`, start, end).
		Scan(&st.Reports, &st.HiddenKB, &st.NewRoots, &st.AuditFails); err != nil {
		return false, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "digest week=%s..%s\n", st.Week, end.AddDate(0, 0, -1).Format("2006-01-02"))
	pct := 0.0
	if st.Reqs > 0 {
		pct = 100 * float64(st.E5xx) / float64(st.Reqs)
	}
	fmt.Fprintf(&b, "traffic: reqs=%d 5xx=%d (%.2f%%) shed_s=%d\n", st.Reqs, st.E5xx, pct, st.ShedS)
	fmt.Fprintf(&b, "shed: events=%d\n", st.ShedEvents)
	fmt.Fprintf(&b, "moderation: reports=%d hidden_kb=%d\n", st.Reports, st.HiddenKB)
	fmt.Fprintf(&b, "identities: new_roots=%d\n", st.NewRoots)
	for _, c := range o.d.StorageClasses() {
		name := doc.SafeLine(c.Name)
		frozen := ""
		if c.Frozen {
			frozen = " frozen"
		}
		fmt.Fprintf(&b, "storage: %s %s/%s%s\n", name, human(c.Used), human(c.Cap), frozen)
		st.Storage[name] = map[string]any{"used": c.Used, "cap": c.Cap, "frozen": c.Frozen}
	}
	fmt.Fprintf(&b, "notices: ops_events=%d\n", st.Notices)
	fmt.Fprintf(&b, "audit: failures=%d\n", st.AuditFails)
	body := b.String()
	if len(body) > digestBodyMax {
		body = body[:digestBodyMax]
	}
	stats, _ := json.Marshal(st)
	err = core.Tx(ctx, o.d.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO ops_digest (week, body, stats) VALUES ($1, $2, $3) ON CONFLICT (week) DO NOTHING`, start, body, stats)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		created = true
		return core.Event(ctx, tx, "ops", "digest:"+st.Week, "", fmt.Sprintf("weekly digest %s: reqs=%d 5xx=%d shed_s=%d reports=%d", st.Week, st.Reqs, st.E5xx, st.ShedS, st.Reports))
	})
	return created, err
}

// Digest returns a stored digest body ("" when none).
func Digest(ctx context.Context, q core.Q, week time.Time) (string, error) {
	var body string
	err := q.QueryRow(ctx, `SELECT body FROM ops_digest WHERE week = $1`, WeekStart(week)).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return body, err
}

// digestTask writes last week's digest once it is missing (janitor task "ops_digest", under the
// task's advisory lock).
func (o *Ops) digestTask(ctx context.Context) (err error) {
	defer o.timed("ops_digest", time.Now(), &err)
	last := WeekStart(time.Now()).AddDate(0, 0, -7)
	var exists bool
	if err := o.q().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ops_digest WHERE week = $1)`, last).Scan(&exists); err != nil || exists {
		return err
	}
	_, err = o.WriteDigest(ctx, last)
	return err
}

// human formats bytes as KiB/MiB/GiB ("-" for an unlimited cap).
func human(n int64) string {
	switch {
	case n <= 0:
		return "-"
	case n >= 1<<30:
		return fmt.Sprintf("%.1fGiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}
