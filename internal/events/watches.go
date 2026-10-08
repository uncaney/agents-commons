package events

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
)

// Watch is a saved filter of one root (19.1): GET /v1/ev?w=<id> applies it.
type Watch struct {
	ID, Root string
	Kinds    []string
	Tags     []string
	Q        string
	Created  time.Time
}

// WatchIn is the POST /v1/watch / op watch body.
type WatchIn struct {
	Kinds []string `json:"kinds"`
	Tags  []string `json:"tags"`
	Q     string   `json:"q"`
}

// norm validates and normalises the filters: kinds and tags lowercased against their grammars,
// q one normalised line of <= 120 runes with at least one word, scrubbed (tier-1 secrets refused,
// tier-2 masked); at least one filter is required.
func (in WatchIn) norm() (*Watch, error) {
	kinds, err := normList(in.Kinds, MaxKinds, kindRe, "kind")
	if err != nil {
		return nil, err
	}
	tags, err := normList(in.Tags, MaxTags, tagRe, "tag")
	if err != nil {
		return nil, err
	}
	q := strings.TrimSpace(scrub.Normalize(in.Q))
	if !doc.OneLine(q) {
		return nil, core.Bad("q must be one line")
	}
	if utf8.RuneCountInString(q) > MaxQ {
		return nil, core.Bad(fmt.Sprintf("q must be <= %d chars", MaxQ))
	}
	if q != "" {
		if _, ae := scrub.RejectOrMask(map[string]*string{"q": &q}); ae != nil {
			return nil, ae
		}
		if len(words(q)) == 0 {
			return nil, core.Bad("q needs a word")
		}
	}
	if len(kinds)+len(tags) == 0 && q == "" {
		return nil, core.Bad("watch needs kinds, tags or q")
	}
	return &Watch{Kinds: kinds, Tags: tags, Q: q}, nil
}

// Create stores a watch for the token's root inside the caller's tx: the root row is locked so
// concurrent creates respect the live cap (20), a daily creation counter applies, audit row.
func Create(ctx context.Context, q core.Q, id *core.Ident, in WatchIn) (*Watch, error) {
	wt, err := in.norm()
	if err != nil {
		return nil, err
	}
	var n int
	if err := q.QueryRow(ctx, `SELECT (SELECT count(*) FROM watches WHERE root = r.id) FROM identities r WHERE r.id = $1 FOR UPDATE`, id.Root).Scan(&n); err != nil {
		return nil, err
	}
	if n >= MaxWatches {
		return nil, core.E(429, "quota", fmt.Sprintf("%d watches live", MaxWatches))
	}
	if err := core.UseQuota(ctx, q, id, "watch", WatchesPerDay); err != nil {
		return nil, err
	}
	wt.ID, wt.Root = core.NewID('w'), id.Root
	if err := q.QueryRow(ctx, `INSERT INTO watches (id, root, kinds, tags, q) VALUES ($1, $2, $3, $4, $5) RETURNING created`,
		wt.ID, wt.Root, wt.Kinds, wt.Tags, wt.Q).Scan(&wt.Created); err != nil {
		return nil, err
	}
	return wt, core.Audit(ctx, q, id.ID, "watch", wt.ID, 0)
}

const watchCols = `id, root, kinds, tags, q, created`

func scanWatch(row pgx.Row) (*Watch, error) {
	var w Watch
	if err := row.Scan(&w.ID, &w.Root, &w.Kinds, &w.Tags, &w.Q, &w.Created); err != nil {
		return nil, err
	}
	return &w, nil
}

// Get returns one of root's watches; unknown, malformed and foreign ids are the same not found.
func Get(ctx context.Context, q core.Q, root, id string) (*Watch, error) {
	if !core.ValidIDPrefix(id, 'w') {
		return nil, core.ErrNotFound
	}
	w, err := scanWatch(q.QueryRow(ctx, `SELECT `+watchCols+` FROM watches WHERE id = $1 AND root = $2`, id, root))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	return w, err
}

// List returns root's watches, oldest first.
func List(ctx context.Context, q core.Q, root string) ([]Watch, error) {
	rows, err := q.Query(ctx, `SELECT `+watchCols+` FROM watches WHERE root = $1 ORDER BY created, id`, root)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Watch
	for rows.Next() {
		w, err := scanWatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *w)
	}
	return out, rows.Err()
}

// Delete removes one of the token root's watches (not found for foreign or unknown ids).
func Delete(ctx context.Context, q core.Q, id *core.Ident, wid string) error {
	if !core.ValidIDPrefix(wid, 'w') {
		return core.ErrNotFound
	}
	tag, err := q.Exec(ctx, `DELETE FROM watches WHERE id = $1 AND root = $2`, wid, id.Root)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return core.Audit(ctx, q, id.ID, "unwatch", wid, 0)
}

func dash(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	return strings.Join(xs, ",")
}

// head is the one-line summary: "<prefix> w… kinds=kb,t tags=python [created=<date>]".
func (w *Watch) head(prefix string, created bool) string {
	s := prefix + " " + w.ID
	if len(w.Kinds) > 0 {
		s += " kinds=" + strings.Join(w.Kinds, ",")
	}
	if len(w.Tags) > 0 {
		s += " tags=" + strings.Join(w.Tags, ",")
	}
	if created {
		s += " created=" + core.Date(w.Created)
	}
	return s
}

// text is the op reply: head line plus the q field (user text, never at column 0).
func (w *Watch) text(prefix string, created bool) string {
	s := w.head(prefix, created)
	if w.Q != "" {
		s += "\nq: " + doc.SafeLine(w.Q)
	}
	return s
}

func (w *Watch) doc(prefix string, created bool) *doc.Doc {
	d := &doc.Doc{Head: w.head(prefix, created), MaxAge: -1,
		Next: []doc.Action{doc.GET("/v1/ev?w="+w.ID, ""), {Method: "DELETE", Path: "/v1/watch/" + w.ID}}}
	if w.Q != "" {
		d.Fields = []doc.F{{Name: "q", Val: w.Q}}
	}
	return d
}

func (h *handlers) watchCreate(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in WatchIn
	if err := core.Decode(w, r, watchBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	var wt *Watch
	err = core.Tx(r.Context(), h.d.DB, func(tx pgx.Tx) error {
		wt, err = Create(r.Context(), tx, id, in)
		return err
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Reply(w, r, http.StatusCreated, wt.doc("ok", false))
}

func (h *handlers) watchList(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	ws, err := List(r.Context(), h.d.DB, id.Root)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: fmt.Sprintf("watches n=%d/%d", len(ws), MaxWatches), Cols: []string{"id", "created", "kinds", "tags", "q"},
		MaxAge: -1, Next: []doc.Action{doc.POST("/v1/watch", ""), doc.GET("/v1/ev", "")}}
	for _, x := range ws {
		q := x.Q
		if q == "" {
			q = "-"
		}
		d.Rows = append(d.Rows, []string{x.ID, core.Date(x.Created), dash(x.Kinds), dash(x.Tags), q})
	}
	doc.Reply(w, r, 200, d)
}

func (h *handlers) watchGet(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	wt, err := Get(r.Context(), h.d.DB, id.Root, r.PathValue("id"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Reply(w, r, 200, wt.doc("watch", true))
}

func (h *handlers) watchDelete(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	err = core.Tx(r.Context(), h.d.DB, func(tx pgx.Tx) error { return Delete(r.Context(), tx, id, r.PathValue("id")) })
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, "ok", doc.GET("/v1/watch", ""), doc.POST("/v1/watch", ""))
}
