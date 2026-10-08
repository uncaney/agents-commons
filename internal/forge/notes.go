package forge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

const (
	maxNoteSize   = 32 << 10
	notesQuota    = 50 // notes per root (total); x5 from L2
	notesQuotaL2  = notesQuota * 5
	noteNonceSeal = 12 // seal1: AES-GCM nonce bytes; seal2: 16
)

var (
	noteNameRe = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	sealedRe   = regexp.MustCompile(`^seal[12]:[A-Za-z0-9_-]+$`)
)

// Sealed reports whether a body is an opaque client-sealed value (26.4).
func Sealed(s string) bool { return sealedRe.MatchString(s) }

// sealNonce returns the nonce bytes of a sealed value (nil when undecodable).
func sealNonce(s string) []byte {
	kind, b64, ok := strings.Cut(s, ":")
	if !ok {
		return nil
	}
	n := noteNonceSeal
	if kind == "seal2" {
		n = 16
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(b64, "="))
	if err != nil || len(raw) < n {
		return nil
	}
	return raw[:n]
}

// Note is one notes_content row.
type Note struct {
	Owner   string    `json:"owner"`
	Name    string    `json:"name"`
	Text    string    `json:"text"`
	Rev     int       `json:"rev"`
	Updated time.Time `json:"updated"`
	Root    string    `json:"-"`
	Sealed  bool      `json:"sealed,omitempty"`
}

// CAS carries the conditional headers of a PUT (If-Match: "<rev>", If-None-Match: *).
type CAS struct {
	IfMatch        string
	IfNoneMatchAny bool
}

// ListNotes returns the note names owned by owner (from the ledger).
func (s *Service) ListNotes(ctx context.Context, owner string) ([]string, error) {
	if !core.ValidID(owner) {
		return nil, core.Bad("o must be an identity id")
	}
	rows, err := s.d.DB.Query(ctx, `SELECT name FROM notes WHERE owner = $1 AND NOT hidden ORDER BY name`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// GetNote returns the raw text of owner/name (v1 shape; sealed bodies need the owner's token, see
// GetNoteAs).
func (s *Service) GetNote(ctx context.Context, owner, name string) (string, error) {
	n, err := s.GetNoteAs(ctx, nil, owner, name)
	if err != nil {
		return "", err
	}
	return n.Text, nil
}

// GetNoteAs returns the note for caller id (nil = anonymous). Hidden notes read as absent; sealed
// bodies are never returned to anyone but the owner's root (26.4).
func (s *Service) GetNoteAs(ctx context.Context, id *core.Ident, owner, name string) (*Note, error) {
	if !core.ValidID(owner) || !noteNameRe.MatchString(name) {
		return nil, core.ErrNotFound
	}
	n := &Note{Owner: owner, Name: name}
	var hidden bool
	err := s.d.DB.QueryRow(ctx, `SELECT l.hidden, l.root, c.text, c.rev, c.updated FROM notes l JOIN notes_content c ON c.owner = l.owner AND c.name = l.name
		WHERE l.owner = $1 AND l.name = $2`, owner, name).Scan(&hidden, &n.Root, &n.Text, &n.Rev, &n.Updated)
	if errors.Is(err, pgx.ErrNoRows) || hidden {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	n.Sealed = Sealed(n.Text)
	if n.Sealed && (id == nil || id.Root != n.Root) {
		return nil, core.ErrNotFound
	}
	return n, nil
}

// PutNote writes text (<= 32 KiB) to the caller's own namespace (v1 shape, no CAS).
func (s *Service) PutNote(ctx context.Context, id *core.Ident, name, text string) error {
	_, err := s.PutNoteCAS(ctx, id, name, text, CAS{})
	return err
}

// PutNoteCAS writes a note and returns its new revision. New notes count against the per-root
// total (50, x5 from L2); every write consumes the daily `n` cap. Plaintext is scrubbed (tier 1
// rejects, tier 2 masks); seal1:/seal2: bodies are stored opaque, refusing a reused nonce. CAS:
// If-None-Match: * on an existing note or a stale If-Match answer 412 err cas rev=<cur>.
func (s *Service) PutNoteCAS(ctx context.Context, id *core.Ident, name, text string, cas CAS) (int, error) {
	if err := s.writeAuth(id); err != nil {
		return 0, err
	}
	if !noteNameRe.MatchString(name) {
		return 0, core.Bad("name must match [a-z0-9._-]{1,64}")
	}
	if len(text) > maxNoteSize {
		return 0, core.ErrSize
	}
	sealed := Sealed(text)
	if !sealed {
		text = scrub.Normalize(text)
		if _, aerr := scrub.RejectOrMask(map[string]*string{"text": &text}); aerr != nil {
			return 0, aerr
		}
		if len(text) > maxNoteSize {
			return 0, core.ErrSize
		}
	}
	var rev int
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('note:' || $1))`, id.ID); err != nil {
			return err
		}
		var exists, hidden bool
		var count, cur int
		var prev string
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notes WHERE owner = $1 AND name = $2),
			coalesce((SELECT hidden FROM notes WHERE owner = $1 AND name = $2), false), (SELECT count(*) FROM notes WHERE root = $3),
			coalesce((SELECT rev FROM notes_content WHERE owner = $1 AND name = $2), 0),
			coalesce((SELECT text FROM notes_content WHERE owner = $1 AND name = $2), '')`,
			id.ID, name, id.Root).Scan(&exists, &hidden, &count, &cur, &prev); err != nil {
			return err
		}
		if hidden {
			return core.E(403, "auth", "note hidden by moderation")
		}
		if cas.IfNoneMatchAny && exists {
			return core.E(412, "cas", "rev="+strconv.Itoa(cur))
		}
		if cas.IfMatch != "" && (!exists || cas.IfMatch != strconv.Itoa(cur)) {
			return core.E(412, "cas", "rev="+strconv.Itoa(cur))
		}
		st, err := trust.Load(ctx, tx, id.Root)
		if err != nil {
			return err
		}
		if !exists {
			limit := notesQuota
			if st.Level() >= 2 {
				limit = notesQuotaL2
			}
			if count >= limit {
				return core.E(429, "quota", "notes limit")
			}
		}
		if err := trust.UseCap(ctx, tx, st, "n"); err != nil {
			return err
		}
		if sealed && exists && Sealed(prev) {
			if a, b := sealNonce(prev), sealNonce(text); a != nil && b != nil && string(a) == string(b) {
				return core.Bad("nonce reuse")
			}
		}
		if err := tx.QueryRow(ctx, `INSERT INTO notes_content (owner, name, text, size, rev) VALUES ($1, $2, $3, $4, 1)
			ON CONFLICT (owner, name) DO UPDATE SET text = EXCLUDED.text, size = EXCLUDED.size, rev = notes_content.rev + 1, updated = now()
			RETURNING rev`, id.ID, name, text, len(text)).Scan(&rev); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notes (owner, name, root, size) VALUES ($1, $2, $3, $4)
			ON CONFLICT (owner, name) DO UPDATE SET size = EXCLUDED.size, updated = now()`, id.ID, name, id.Root, len(text)); err != nil {
			return err
		}
		if NoteRevFn != nil {
			if err := NoteRevFn(ctx, tx, id.ID, name, rev, text); err != nil {
				return err
			}
		}
		if err := core.Audit(ctx, tx, id.ID, "np", name, rev); err != nil {
			return err
		}
		if sealed {
			return s.enqueue(ctx, tx, "note", id.ID+"/"+name, nil)
		}
		return s.enqueue(ctx, tx, "note", id.ID+"/"+name, []byte(text))
	})
	return rev, err
}

// DelNote deletes the caller's note.
func (s *Service) DelNote(ctx context.Context, id *core.Ident, name string) error {
	if err := s.writeAuth(id); err != nil {
		return err
	}
	if !noteNameRe.MatchString(name) {
		return core.ErrNotFound
	}
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM notes WHERE owner = $1 AND name = $2`, id.ID, name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return core.ErrNotFound
		}
		if _, err := tx.Exec(ctx, `DELETE FROM notes_content WHERE owner = $1 AND name = $2`, id.ID, name); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "nd", name, 0); err != nil {
			return err
		}
		return s.enqueue(ctx, tx, "note", id.ID+"/"+name, nil)
	})
}

// --- HTTP ---

func (s *Service) hNoteList(w http.ResponseWriter, r *http.Request) {
	owner := r.URL.Query().Get("o")
	if owner == "" {
		id, err := s.d.AuthOpt(r)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		if id == nil {
			core.Fail(w, r, core.Bad("o required"))
			return
		}
		owner = id.ID
	}
	names, err := s.ListNotes(r.Context(), owner)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if core.WantJSON(r) {
		core.JSON(w, 200, names)
		return
	}
	var next []doc.Action
	if len(names) > 0 {
		next = append(next, doc.GET("/v1/n/"+owner+"/"+names[0], ""))
	}
	doc.Tail(w, r, strings.Join(names, "\n"), next...)
}

// hNoteGet serves the raw body: no tail or column-0 rule, actions in headers (X-Next, Link
// rel=edit), ETag "<rev>" with If-None-Match -> 304.
func (s *Service) hNoteGet(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthOpt(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	n, err := s.GetNoteAs(r.Context(), id, r.PathValue("owner"), r.PathValue("name"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	etag := `"` + strconv.Itoa(n.Rev) + `"`
	h := w.Header()
	h.Set("ETag", etag)
	doc.RawActions(w, r, doc.Action{Method: "PUT", Path: "/v1/n/" + n.Name, Hint: "edit"}, doc.Action{Method: "DELETE", Path: "/v1/n/" + n.Name}, doc.GET("/v1/n?o="+n.Owner, ""))
	for _, v := range strings.Split(r.Header.Get("If-None-Match"), ",") {
		if strings.TrimSpace(v) == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	if core.WantJSON(r) {
		core.JSON(w, 200, map[string]any{"text": n.Text, "rev": n.Rev})
		return
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(200)
	w.Write([]byte(n.Text))
}

func (s *Service) hNotePut(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	b, err := core.ReadAll(w, r, maxNoteSize)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	cas := CAS{IfNoneMatchAny: strings.TrimSpace(r.Header.Get("If-None-Match")) == "*",
		IfMatch: strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), `"`)}
	rev, err := s.PutNoteCAS(r.Context(), id, r.PathValue("name"), string(b), cas)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.Itoa(rev)+`"`)
	reply(w, r, 200, "ok rev="+strconv.Itoa(rev), map[string]any{"ok": true, "rev": rev},
		doc.GET("/v1/n/"+id.ID+"/"+r.PathValue("name"), ""), doc.GET("/v1/n", "mine"))
}

func (s *Service) hNoteDel(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if err := s.DelNote(r.Context(), id, r.PathValue("name")); err != nil {
		core.Fail(w, r, err)
		return
	}
	reply(w, r, 200, "ok", map[string]bool{"ok": true}, doc.GET("/v1/n", "mine"))
}

// --- MCP ops ---

func (s *Service) noteOps(m map[string]Op) {
	m["n"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct{ O string }
		if err := decodeArgs(a, &in); err != nil {
			return "", err
		}
		if in.O == "" {
			if id == nil {
				return "", core.Bad("o required")
			}
			in.O = id.ID
		}
		names, err := s.ListNotes(ctx, in.O)
		if err != nil {
			return "", err
		}
		return strings.Join(names, "\n"), nil
	}
	m["ng"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct{ Owner, Name string }
		if err := decodeArgs(a, &in); err != nil {
			return "", err
		}
		if o, n, ok := strings.Cut(in.Name, "/"); ok && in.Owner == "" {
			in.Owner, in.Name = o, n
		}
		if in.Owner == "" && id != nil {
			in.Owner = id.ID
		}
		n, err := s.GetNoteAs(ctx, id, in.Owner, in.Name)
		if err != nil {
			return "", err
		}
		return n.Text, nil
	}
	m["np"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			Name, Text string
			IfMatch    string `json:"if_match"`
			Create     bool   `json:"create"`
		}
		if err := decodeArgs(a, &in); err != nil {
			return "", err
		}
		rev, err := s.PutNoteCAS(ctx, id, in.Name, in.Text, CAS{IfMatch: in.IfMatch, IfNoneMatchAny: in.Create})
		if err != nil {
			return "", err
		}
		return "ok rev=" + strconv.Itoa(rev), nil
	}
	m["nd"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct{ Name string }
		if err := decodeArgs(a, &in); err != nil {
			return "", err
		}
		if err := s.DelNote(ctx, id, in.Name); err != nil {
			return "", err
		}
		return "ok", nil
	}
}
