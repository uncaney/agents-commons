package ops

import (
	"context"
	"time"
)

// Retention windows (21.2); vars so tests can shorten them. Events and audit are also trimmed by
// their owners; the deletes here are idempotent and bounded.
var (
	EventsKeep      = 7 * 24 * time.Hour
	AuditKeep       = 30 * 24 * time.Hour
	OriginKeep      = 365 * 24 * time.Hour // ORIGIN_RETENTION_DAYS overrides at Register
	StatusDailyKeep = 400 * 24 * time.Hour
	DigestKeep      = 2 * 365 * 24 * time.Hour
	RetentionBatch  = 5000
	retentionRounds = 10
)

// retentionTables are the tables whose row estimates the gauges report ("ledger counts").
var retentionTables = []string{"events", "audit", "content_origin", "ledger", "status_daily", "ops_digest", "admin_log"}

type retentionRule struct {
	table, col, key string
	keep            *time.Duration
}

// rules: key is the column the batched delete selects by (ctid when the table has no key).
var rules = []retentionRule{
	{"events", "at", "seq", &EventsKeep},
	{"audit", "ts", "ctid", &AuditKeep},
	{"content_origin", "at", "ctid", &OriginKeep},
	{"status_daily", "day", "day", &StatusDailyKeep},
	{"ops_digest", "week", "week", &DigestKeep},
}

// retention deletes rows past their window in batches of RetentionBatch (at most retentionRounds
// per table per run) so no statement outlives the ops pool's timeout. Janitor task "ops_retention".
func (o *Ops) retention(ctx context.Context) (err error) {
	defer o.timed("ops_retention", time.Now(), &err)
	q := o.q()
	for _, r := range rules {
		cut := time.Now().Add(-*r.keep)
		sql := `DELETE FROM ` + r.table + ` WHERE ` + r.key + ` IN (SELECT ` + r.key + ` FROM ` + r.table + ` WHERE ` + r.col + ` < $1 LIMIT $2)`
		if r.key == "ctid" {
			sql = `DELETE FROM ` + r.table + ` WHERE ctid = ANY (ARRAY(SELECT ctid FROM ` + r.table + ` WHERE ` + r.col + ` < $1 LIMIT $2))`
		}
		for i := 0; i < retentionRounds; i++ {
			tag, e := q.Exec(ctx, sql, cut, RetentionBatch)
			if e != nil {
				if err == nil {
					err = e
				}
				break
			}
			o.m.Add("cx_retention_deleted_total", float64(tag.RowsAffected()), r.table)
			if tag.RowsAffected() < int64(RetentionBatch) {
				break
			}
		}
	}
	return err
}
