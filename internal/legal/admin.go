package legal

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// queueItem is one open review-queue row joined to its evidence.
type queueItem struct {
	ID       int64     `json:"id"`
	Ref      string    `json:"ref"`
	FromRoot string    `json:"from_root"`
	Reason   string    `json:"reason"`
	Weight   float64   `json:"weight"`
	Kind     string    `json:"kind"`
	Kinds    string    `json:"kinds"`
	Score    int       `json:"score"`
	Upheld   bool      `json:"upheld"`
	Why      string    `json:"why"`
	Created  time.Time `json:"created"`
}

// queue serves GET /admin/x/queue (ops token): the open review queue with its evidence verdicts, no
// plaintext (26.3). ?since= limits to rows created after an RFC3339 timestamp.
func (s *svc) queue(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if v := strings.TrimSpace(r.URL.Query().Get("since")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			core.Fail(w, r, core.Bad("since must be RFC3339"))
			return
		}
		since = t
	}
	rows, err := s.d.DB.Query(r.Context(), `SELECT q.id, q.ref, q.from_root, q.reason, q.weight,
		e.kind, e.kinds, e.score, e.upheld, e.why, q.created
		FROM x_review_queue q LEFT JOIN x_evidence e ON e.id = q.evidence
		WHERE q.decided_at IS NULL AND ($1::timestamptz IS NULL OR q.created > $1) ORDER BY q.created DESC LIMIT 200`,
		nullTime(since))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	defer rows.Close()
	var items []queueItem
	var b strings.Builder
	for rows.Next() {
		var it queueItem
		var kind, kinds, why *string
		var score *int
		var upheld *bool
		if err := rows.Scan(&it.ID, &it.Ref, &it.FromRoot, &it.Reason, &it.Weight, &kind, &kinds, &score, &upheld, &why, &it.Created); err != nil {
			core.Fail(w, r, err)
			return
		}
		it.Kind, it.Kinds, it.Why = deref(kind), deref(kinds), deref(why)
		if score != nil {
			it.Score = *score
		}
		if upheld != nil {
			it.Upheld = *upheld
		}
		items = append(items, it)
		b.WriteString(strconv.FormatInt(it.ID, 10) + " " + it.Ref + " from=" + it.FromRoot +
			" reason=" + it.Reason + " kinds=" + dash(it.Kinds) + " score=" + strconv.Itoa(it.Score) +
			" upheld=" + strconv.FormatBool(it.Upheld) + "\n")
	}
	if err := rows.Err(); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, b.String(), map[string]any{"queue": items})
}

// decideIn is the POST /admin/x/decide body.
type decideIn struct {
	ID     int64  `json:"id"`
	Action string `json:"action"`
	Note   string `json:"note"`
}

// decide serves POST /admin/x/decide (ops token): purge deletes the reported ciphertext by locator,
// freeze freezes the sender root, dismiss closes the item. Every outcome records a content-free
// admin event and marks the queue row decided.
func (s *svc) decide(w http.ResponseWriter, r *http.Request) {
	var in decideIn
	if err := core.Decode(w, r, 1<<12, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	switch in.Action {
	case "purge", "freeze", "dismiss":
	default:
		core.Fail(w, r, core.Bad("action must be purge, freeze or dismiss"))
		return
	}
	if len(in.Note) > 300 {
		core.Fail(w, r, core.Bad("note must be <= 300 bytes"))
		return
	}
	err := core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		var ref, fromRoot string
		var decided *time.Time
		err := tx.QueryRow(r.Context(), `SELECT ref, from_root, decided_at FROM x_review_queue WHERE id = $1 FOR UPDATE`, in.ID).Scan(&ref, &fromRoot, &decided)
		if err == pgx.ErrNoRows {
			return core.E(404, "notfound", "no open review item "+strconv.FormatInt(in.ID, 10))
		}
		if err != nil {
			return err
		}
		if decided != nil {
			return core.E(409, "decided", "review item already decided")
		}
		switch in.Action {
		case "purge":
			if t, ok := s.d.Target("x"); ok {
				if err := t.Hide(r.Context(), tx, strings.TrimPrefix(ref, "m:")); err != nil {
					return err
				}
			}
		case "freeze":
			if err := freeze(r.Context(), tx, fromRoot, time.Now().Add(freezeDur)); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(r.Context(), `UPDATE x_review_queue SET decided_at = now(), decision = $2, note = $3 WHERE id = $1`,
			in.ID, in.Action, in.Note); err != nil {
			return err
		}
		return core.Event(r.Context(), tx, "ops", "x-decide", "", "review "+strconv.FormatInt(in.ID, 10)+" "+in.Action+" "+ref)
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, "ok decided "+in.Action+"\n", map[string]any{"ok": true, "action": in.Action})
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
