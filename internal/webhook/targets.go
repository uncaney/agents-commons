package webhook

import (
	"context"

	"ekaii.fr/commons/internal/core"
)

// report targets (4.7): 'h' outbound hooks and 'i' inbound sinks are owner-private config, so a
// report only needs to resolve the ref (Exists). An inbound sink can additionally be disabled and
// re-enabled; an outbound hook carries no hidden state (moderation is by root ban / purge), so its
// Hide/Restore are no-ops.

func (h *handlers) tgtHookExists(ctx context.Context, q core.Q, ref string) error {
	return existsRow(ctx, q, `SELECT EXISTS (SELECT 1 FROM hooks WHERE id = $1)`, ref)
}

func (h *handlers) tgtInExists(ctx context.Context, q core.Q, ref string) error {
	return existsRow(ctx, q, `SELECT EXISTS (SELECT 1 FROM in_hooks WHERE id = $1)`, ref)
}

func (h *handlers) tgtInHide(ctx context.Context, q core.Q, ref string) error {
	return setInDisabled(ctx, q, ref, true)
}

func (h *handlers) tgtInRestore(ctx context.Context, q core.Q, ref string) error {
	return setInDisabled(ctx, q, ref, false)
}

func existsRow(ctx context.Context, q core.Q, sql, ref string) error {
	var ok bool
	if err := q.QueryRow(ctx, sql, ref).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func setInDisabled(ctx context.Context, q core.Q, ref string, v bool) error {
	tag, err := q.Exec(ctx, `UPDATE in_hooks SET disabled = $2 WHERE id = $1`, ref, v)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return nil
}

func noop(context.Context, core.Q, string) error { return nil }
