package group

import (
	"context"

	"ekaii.fr/commons/internal/core"
)

// Janitor enforces the lifecycle (5.5, D6): rows are hard-deleted at ttl_d, an idle group expires at
// 90 d (full deletability, cascade), tombs are kept 12 months for former-member reports, and franking
// evidence is kept 90 d. Postgres only — nothing is ever deleted from a Forgejo mirror here.
func Janitor(ctx context.Context, q core.Q) error {
	if _, err := q.Exec(ctx, `DELETE FROM grp_rows WHERE exp < now()`); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE grp SET bytes = coalesce((SELECT sum(size) FROM grp_rows WHERE gid = grp.id), 0)`); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `DELETE FROM grp WHERE idle < now() - make_interval(days => 90)`); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `DELETE FROM grp_members_tomb WHERE at < now() - make_interval(days => 365)`); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `DELETE FROM grp_evidence WHERE exp < now()`); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `DELETE FROM grp_snapshots s WHERE NOT EXISTS (SELECT 1 FROM grp g WHERE g.id = s.gid)`)
	return err
}
