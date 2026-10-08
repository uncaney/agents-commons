package compute

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// cacheRow is a finished, attested job the result cache may reuse (14.1).
type cacheRow struct {
	id, out, root, scope string
	usedMs, code         int
}

const cacheCols = `SELECT id, out, used_ms, code, root, cache_scope FROM jobs
	WHERE wasm = $1 AND input = $2 AND fs = $3 AND mb = $4 AND status = 'done' AND reason = '' AND cached_from = ''
	  AND finished_at > now() - make_interval(days => $5) AND att_d AND cache_scope <> 'revoked'`

// cacheFind returns the best matching row for root: a servable one (global, or root's own) first,
// else the newest root-scoped result of another root (a miss that asks for a priority audit).
func cacheFind(ctx context.Context, q core.Q, wasm, input, fs string, mb int, root string) (*cacheRow, error) {
	r := &cacheRow{}
	err := q.QueryRow(ctx, cacheCols+` ORDER BY (cache_scope = 'global' OR root = $6) DESC, finished_at DESC LIMIT 1`,
		wasm, input, fs, mb, retentionD, root).Scan(&r.id, &r.out, &r.usedMs, &r.code, &r.root, &r.scope)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

func (r *cacheRow) servable(root string) bool { return r.scope == "global" || r.root == root }

// cacheLookupGlobal is CacheLookup: a globally scoped hit only (anonymous service reads, 27.6).
func cacheLookupGlobal(ctx context.Context, q core.Q, wasm, input, fs string, mb int) (*JobView, bool, error) {
	if !hashRe.MatchString(wasm) || !hashRe.MatchString(input) || (fs != "" && !hashRe.MatchString(fs)) {
		return nil, false, core.Bad("bad hash")
	}
	r := &cacheRow{}
	err := q.QueryRow(ctx, cacheCols+` AND cache_scope = 'global' ORDER BY finished_at DESC LIMIT 1`,
		wasm, input, fs, mb, retentionD).Scan(&r.id, &r.out, &r.usedMs, &r.code, &r.root, &r.scope)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if revoked, err := isRevoked(ctx, q, wasm, input); err != nil || revoked {
		return nil, false, err
	}
	if _, ok, err := blobSize(ctx, q, r.out); err != nil || !ok {
		return nil, false, err
	}
	return &JobView{ID: r.id, Status: "done", Out: r.out, Ms: r.usedMs, Code: r.code, Cached: true}, true, nil
}

// isRevoked asks the audit package (RevokedFn, 14.5); not revoked when unset.
func isRevoked(ctx context.Context, q core.Q, wasm, input string) (bool, error) {
	if RevokedFn == nil {
		return false, nil
	}
	return RevokedFn(ctx, q, wasm, input)
}

// cacheKey is the key handed to CacheJobFn (16.4): hex(sha256(wasm || input || fs)).
func cacheKey(wasm, input, fs string) string {
	h := sha256.Sum256([]byte(wasm + input + fs))
	return hex.EncodeToString(h[:])
}

// cacheServe serves sp from the result cache inside the submit transaction (14.1). A hit inserts
// a job row already done with cached_from, reserves nothing, refreshes last_ref and bumps the
// root's saved counters; a root-scoped result of another root is a miss that enqueues a
// priority audit (14.5) so a match can make it global.
func (s *svc) cacheServe(ctx context.Context, tx pgx.Tx, id *core.Ident, sp Spec, wasm, in *blobRow) (*JobView, bool, error) {
	r, err := cacheFind(ctx, tx, sp.Wasm, sp.In, sp.FS, sp.Mb, id.Root)
	if err != nil || r == nil {
		return nil, false, err
	}
	if !r.servable(id.Root) {
		if r.scope == "root" {
			if err := priorityAudit(ctx, tx, r.id, "cross-root-hit"); err != nil {
				return nil, false, err
			}
		}
		return nil, false, nil
	}
	if revoked, err := isRevoked(ctx, tx, sp.Wasm, sp.In); err != nil || revoked {
		return nil, false, err
	}
	if _, ok, err := blobSize(ctx, tx, r.out); err != nil || !ok {
		return nil, false, err
	}
	if _, err := os.Stat(s.blobPath(r.out)); err != nil {
		return nil, false, nil
	}
	savedCredits := min(costOf(sp.Ms), max(int64((r.usedMs+999)/1000), 1)*2)
	jid := core.NewID('j')
	if _, err := tx.Exec(ctx, `INSERT INTO jobs (id, submitter, root, wasm, input, fs, ms, mb, reserved, status, out, used_ms, code, finished_at,
			cached_from, wasm_size, svc, kind, lane, sub_lvl, pipe, bounty, sub, saved_ms, saved_credits, charged)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, 'done', $9, 0, $10, now(), $11, $12, $13, $14, $15, 0, $16, $17, $18, $19, $20, 0)`,
		jid, id.ID, id.Root, sp.Wasm, sp.In, sp.FS, sp.Ms, sp.Mb, r.out, r.code, r.id, wasm.size, sp.Svc, sp.Kind, sp.Lane, sp.Pipe, sp.Bounty, sp.Sub,
		r.usedMs, savedCredits); err != nil {
		return nil, false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE blobs SET last_ref = now(), used_at = coalesce(used_at, now()) WHERE hash IN ($1, $2, $3, $4)`, sp.Wasm, sp.In, sp.FS, r.out); err != nil {
		return nil, false, err
	}
	if _, err := bumpDaily(ctx, tx, id.Root, "saved:ms", r.usedMs); err != nil {
		return nil, false, err
	}
	if _, err := bumpDaily(ctx, tx, id.Root, "saved:credits", int(savedCredits)); err != nil {
		return nil, false, err
	}
	return &JobView{ID: jid, Status: "done", Out: r.out, Ms: 0, Code: r.code, Cached: true, Lane: sp.Lane}, true, nil
}

// priorityAudit enqueues a priority audit through PriorityAuditFn, or directly into audit_queue
// when the audit package is not wired yet.
func priorityAudit(ctx context.Context, q core.Q, jobID, reason string) error {
	if PriorityAuditFn != nil {
		return PriorityAuditFn(ctx, q, jobID, reason)
	}
	_, err := q.Exec(ctx, `INSERT INTO audit_queue (job, reason) VALUES ($1, $2) ON CONFLICT (job) DO NOTHING`, jobID, reason)
	return err
}

// meLines adds the root's compute savings to GET /v1/me (14.1): cached hits of the retention window.
func (s *svc) meLines(ctx context.Context, id *core.Ident) []string {
	var n, ms, credits int64
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*), coalesce(sum(saved_ms), 0), coalesce(sum(saved_credits), 0) FROM jobs WHERE root = $1 AND cached_from <> ''`, id.Root).
		Scan(&n, &ms, &credits); err != nil || n == 0 {
		return nil
	}
	return []string{"compute saved=" + itoa(credits) + " saved_ms=" + itoa(ms) + " cached=" + itoa(n)}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
