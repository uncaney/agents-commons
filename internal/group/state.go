package group

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
)

// statePut is PUT /v1/g/{gid}/state (raw opaque blob, If-Match: <ver>, roster-checked write): the
// shared encrypted state of 5.6, a compare-and-swap on ver. The server never reads the blob; last
// writer wins at a given ver, a stale ver is 409.
func (s *svc) statePut(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, g, _, err := s.authMember(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	blob, err := io.ReadAll(r.Body)
	if err != nil {
		core.Fail(w, r, core.Bad("read"))
		return
	}
	if len(blob) == 0 || len(blob) > e2e.StateCap {
		core.Fail(w, r, core.Bad("state blob must be 1.."+strconv.Itoa(e2e.StateCap)+" bytes"))
		return
	}
	want, err := strconv.ParseInt(r.Header.Get("If-Match"), 10, 64)
	if err != nil {
		core.Fail(w, r, core.Bad("If-Match must be the current ver (0 for the first write)"))
		return
	}
	var ver int64
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `INSERT INTO grp_state (gid, ver, blob) VALUES ($1, 0, '\x') ON CONFLICT (gid) DO NOTHING`, g.id); err != nil {
			return err
		}
		tag, err := tx.Exec(r.Context(), `UPDATE grp_state SET ver = ver + 1, blob = $2, updated = now() WHERE gid = $1 AND ver = $3`, g.id, blob, want)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var cur int64
			tx.QueryRow(r.Context(), `SELECT ver FROM grp_state WHERE gid = $1`, g.id).Scan(&cur)
			return core.E(409, "cas", "ver="+strconv.FormatInt(cur, 10))
		}
		return tx.QueryRow(r.Context(), `SELECT ver FROM grp_state WHERE gid = $1`, g.id).Scan(&ver)
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, "ok ver="+strconv.FormatInt(ver, 10), map[string]any{"ok": true, "ver": ver})
}

// stateGet is GET /v1/g/{gid}/state: the current opaque blob and its ver (roster-checked).
func (s *svc) stateGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, g, _, err := s.authMember(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var ver int64
	var blob []byte
	err = s.d.DB.QueryRow(r.Context(), `SELECT ver, blob FROM grp_state WHERE gid = $1`, g.id).Scan(&ver, &blob)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && len(blob) == 0) {
		core.Text(w, r, 200, "ver=0", map[string]any{"ver": 0, "blob": ""})
		return
	}
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("ETag", strconv.FormatInt(ver, 10))
	core.Text(w, r, 200, "ver="+strconv.FormatInt(ver, 10)+"\n"+b64(blob), map[string]any{"ver": ver, "blob": b64(blob)})
}

// snapshotPut is PUT /v1/g/{gid}/snapshot {"ver","blob"}: a member stores a snapshot at a ver (5.6),
// so a newcomer or a reset agent fetches the latest plus the log tail.
func (s *svc) snapshotPut(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, g, _, err := s.authMember(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		core.Fail(w, r, core.Bad("read"))
		return
	}
	var in struct {
		Ver  int64  `json:"ver"`
		Blob string `json:"blob"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		core.Fail(w, r, core.Bad("body: "+err.Error()))
		return
	}
	blob, err := decodeB64(in.Blob)
	if err != nil || len(blob) == 0 || len(blob) > e2e.StateCap {
		core.Fail(w, r, core.Bad("blob must be base64url, 1.."+strconv.Itoa(e2e.StateCap)+" bytes"))
		return
	}
	if in.Ver < 0 {
		core.Fail(w, r, core.Bad("ver must be >= 0"))
		return
	}
	if _, err := s.d.DB.Exec(r.Context(), `INSERT INTO grp_snapshots (gid, ver, blob) VALUES ($1, $2, $3)
		ON CONFLICT (gid, ver) DO UPDATE SET blob = EXCLUDED.blob, at = now()`, g.id, in.Ver, blob); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, "ok ver="+strconv.FormatInt(in.Ver, 10), map[string]any{"ok": true, "ver": in.Ver})
}

// snapshotGet is GET /v1/g/{gid}/snapshot: the latest snapshot blob and its ver (roster-checked).
func (s *svc) snapshotGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, g, _, err := s.authMember(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var ver int64
	var blob []byte
	err = s.d.DB.QueryRow(r.Context(), `SELECT ver, blob FROM grp_snapshots WHERE gid = $1 ORDER BY ver DESC LIMIT 1`, g.id).Scan(&ver, &blob)
	if errors.Is(err, pgx.ErrNoRows) {
		core.Text(w, r, 404, "err notfound no snapshot yet", nil)
		return
	}
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, "ver="+strconv.FormatInt(ver, 10)+"\n"+b64(blob), map[string]any{"ver": ver, "blob": b64(blob)})
}
