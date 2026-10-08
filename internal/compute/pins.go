package compute

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

var verRe = regexp.MustCompile(`^[A-Za-z0-9._-]{0,32}$`)

// pinned reports whether hash is in pins (14.4): modules above 4 MiB run only when pinned.
func pinned(ctx context.Context, q core.Q, hash string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pins WHERE hash = $1)`, hash).Scan(&ok)
	return ok, err
}

type pinIn struct {
	Hash string `json:"hash"`
	Name string `json:"name"`
	Ver  string `json:"ver"`
	Note string `json:"note"`
}

// pin records a pin for a stored blob and marks it pinned_by admin (unless a seed already did).
func (s *svc) pin(ctx context.Context, in pinIn) (int64, error) {
	switch {
	case !hashRe.MatchString(in.Hash):
		return 0, core.Bad("bad hash")
	case !core.ValidName(in.Name):
		return 0, core.Bad("name must match [a-zA-Z0-9._-]{1,32}")
	case !verRe.MatchString(in.Ver):
		return 0, core.Bad("ver must match [A-Za-z0-9._-]{0,32}")
	}
	note := doc.SafeLine(in.Note)
	if len(note) > 120 {
		note = note[:120]
	}
	var size int64
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		b, err := loadBlob(ctx, tx, in.Hash)
		if err != nil {
			return err
		}
		if b == nil {
			return core.ErrNotFound
		}
		size = b.size
		if _, err := tx.Exec(ctx, `INSERT INTO pins (hash, name, ver, size, note) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (hash) DO UPDATE SET name = EXCLUDED.name, ver = EXCLUDED.ver, note = EXCLUDED.note`, in.Hash, in.Name, in.Ver, size, note); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE blobs SET pinned_by = CASE WHEN pinned_by = '' THEN 'admin' ELSE pinned_by END, used_at = coalesce(used_at, now()), last_ref = now() WHERE hash = $1`, in.Hash)
		return err
	})
	return size, err
}

// unpin drops a pin; queued jobs that needed it (modules above 4 MiB) are cancelled with refund.
func (s *svc) unpin(ctx context.Context, hash string) ([]string, error) {
	if !hashRe.MatchString(hash) {
		return nil, core.Bad("bad hash")
	}
	var ids []string
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM pins WHERE hash = $1`, hash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return core.ErrNotFound
		}
		if _, err := tx.Exec(ctx, `UPDATE blobs SET pinned_by = '' WHERE hash = $1 AND pinned_by = 'admin'`, hash); err != nil {
			return err
		}
		ids, err = cancelJobs(ctx, tx, `wasm = $2 AND wasm_size > $3`, "unpinned", true, hash, maxWasm)
		return err
	})
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		s.d.Notify.Wake("job:" + id)
	}
	return ids, nil
}

type pinRow struct {
	hash, name, ver, note, by string
	size                      int64
}

func (s *svc) listPins(ctx context.Context) ([]pinRow, error) {
	rows, err := s.d.DB.Query(ctx, `SELECT p.hash, p.name, p.ver, p.size, p.note, coalesce(b.pinned_by, '') FROM pins p LEFT JOIN blobs b ON b.hash = p.hash ORDER BY p.name, p.ver, p.hash`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pinRow
	for rows.Next() {
		var p pinRow
		if err := rows.Scan(&p.hash, &p.name, &p.ver, &p.size, &p.note, &p.by); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (p pinRow) line() string {
	l := fmt.Sprintf("%s %s@%s %d", p.hash, p.name, p.ver, p.size)
	if p.note == "seed" || p.by == "seed" {
		l += " by=seed"
	}
	return l
}

func (s *svc) hPins(w http.ResponseWriter, r *http.Request) {
	if _, err := s.d.AuthOpt(r); err != nil {
		core.Fail(w, r, err)
		return
	}
	pins, err := s.listPins(r.Context())
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	lines := make([]string, 0, len(pins))
	js := make([]map[string]any, 0, len(pins))
	for _, p := range pins {
		lines = append(lines, p.line())
		j := map[string]any{"hash": p.hash, "name": p.name, "ver": p.ver, "size": p.size}
		if p.note == "seed" || p.by == "seed" {
			j["by"] = "seed"
		}
		js = append(js, j)
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	core.OK(w, r, strings.Join(lines, "\n"), js)
}

func (s *svc) hPin(w http.ResponseWriter, r *http.Request) {
	var in pinIn
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.AdminArg(r, in.Hash)
	size, err := s.pin(r.Context(), in)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, fmt.Sprintf("ok pin %s %s@%s %d", in.Hash, in.Name, in.Ver, size), map[string]any{"ok": true, "hash": in.Hash, "name": in.Name, "ver": in.Ver, "size": size})
}

func (s *svc) hUnpin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hash string `json:"hash"`
	}
	if err := core.Decode(w, r, 1<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.AdminArg(r, in.Hash)
	ids, err := s.unpin(r.Context(), in.Hash)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, fmt.Sprintf("ok unpin %s cancelled=%d", in.Hash, len(ids)), map[string]any{"ok": true, "hash": in.Hash, "cancelled": ids})
}
