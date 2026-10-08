package mem

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Conditions (10.4): kind -> the ref grammar after "<kind>:" and before ":<verb>".
var condRe = regexp.MustCompile(`^(t):(\d{1,12}):(done)$|^(k):([a-z][a-z2-7]{6}):(ok)$|^(j):([a-z][a-z2-7]{6}):(done)$|^(kv):([A-Za-z0-9._:-]{1,72}/[A-Za-z0-9._:/-]{1,128}):(changed)$|^(b):([a-z][a-z2-7]{6}):(paid)$|^(r):([a-z][a-z2-7]{6}):(answered)$`)

// parseCond returns (kind, ref) of an `on` condition.
func parseCond(on string) (string, string, bool) {
	m := condRe.FindStringSubmatch(on)
	if m == nil {
		return "", "", false
	}
	for i := 1; i+2 < len(m); i += 3 {
		if m[i] != "" {
			return m[i], m[i+1], true
		}
	}
	return "", "", false
}

// parseAfter accepts "+<seconds>" or RFC 3339, at most LaterMaxAfter ahead.
func parseAfter(s string, now time.Time) (time.Time, error) {
	var t time.Time
	if strings.HasPrefix(s, "+") {
		n, err := strconv.ParseInt(s[1:], 10, 64)
		if err != nil || n < 0 {
			return t, core.Bad(`after must be "+<seconds>" or an RFC 3339 time`)
		}
		t = now.Add(time.Duration(n) * time.Second)
	} else {
		var err error
		if t, err = time.Parse(time.RFC3339, s); err != nil {
			return t, core.Bad(`after must be "+<seconds>" or an RFC 3339 time`)
		}
	}
	if t.After(now.Add(LaterMaxAfter)) {
		return t, core.Bad("after must be within 30 days")
	}
	return t.Truncate(time.Second), nil
}

// subjectOf is the first line of a message, <= 80 runes.
func subjectOf(text string) string {
	first, _, _ := strings.Cut(strings.TrimSpace(text), "\n")
	first = doc.SafeLine(strings.TrimSpace(first))
	if utf8.RuneCountInString(first) > 80 {
		first = string([]rune(first)[:80])
	}
	return first
}

// laterPut stores a self-message: scrub, caps (20 pending / 64 KiB per root), audit. Exactly one
// of after/on; the kv condition records the version seen so a later change (or a disappearance
// after it existed) delivers.
func laterPut(ctx context.Context, q, leak core.Q, actor, root, text string, after *time.Time, on string) (id, deliver string, err error) {
	text = doc.CleanMulti(text)
	if strings.TrimSpace(text) == "" {
		return "", "", core.Bad("text required")
	}
	if len(text) > MaxLaterText {
		return "", "", core.ErrSize
	}
	if _, err := check(ctx, leak, map[string]*string{"text": &text}); err != nil {
		return "", "", err
	}
	if (after == nil) == (on == "") {
		return "", "", core.Bad(`exactly one of after ("+<seconds>"|ISO) or on ("t:<n>:done" …) is required`)
	}
	kind, ref := "", ""
	if on != "" {
		var ok bool
		if kind, ref, ok = parseCond(on); !ok {
			return "", "", core.Bad("on must be t:<n>:done | k:<id>:ok | j:<id>:done | kv:<ns>/<k>:changed | b:<id>:paid | r:<id>:answered")
		}
	}
	id = core.NewID('m')
	err = inTx(ctx, q, func(tx core.Q) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "later:"+root); err != nil {
			return err
		}
		var n, bytes int
		if err := tx.QueryRow(ctx, `SELECT count(*), coalesce(sum(length(text)), 0) FROM mem_later WHERE root = $1 AND NOT delivered`, root).Scan(&n, &bytes); err != nil {
			return err
		}
		if n >= MaxLaterPending || bytes+len(text) > MaxLaterBytes {
			return core.ErrQuota
		}
		var seen int64
		if kind == "kv" {
			nsRaw, k, _ := strings.Cut(ref, "/")
			ns, err := parseNS(nsRaw, root)
			if err != nil {
				return err
			}
			if err := nsAccess(ctx, tx, ns, root, false, 0); err != nil {
				return err
			}
			ref = ns.raw + "/" + k
			if err := tx.QueryRow(ctx, `SELECT coalesce((SELECT ver FROM kv WHERE ns = $1 AND k = $2 AND expires_at > now()), 0)`, ns.raw, k).Scan(&seen); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO mem_later (id, root, text, subject, deliver_at, cond_kind, cond_ref, cond_seen)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, id, root, text, subjectOf(text), after, kind, ref, seen); err != nil {
			return err
		}
		if actor == "" {
			return nil
		}
		return core.Audit(ctx, tx, actor, "later", id, len(text))
	})
	if err != nil {
		return "", "", err
	}
	if after != nil {
		return id, rfc(*after), nil
	}
	return id, "cond", nil
}

// Later schedules a self-message for a root at `after` (service callers: sessions).
func Later(ctx context.Context, q core.Q, root, text string, after time.Time) (string, error) {
	if after.IsZero() {
		after = time.Now()
	}
	id, _, err := laterPut(ctx, q, nil, root, root, text, &after, "")
	return id, err
}

// condQueries deliver conditional rows: one statement per kind; the first EXISTS is the condition,
// the second its "gone" test (the referenced object no longer exists), which delivers the row with
// "(cond gone)" appended to its subject.
var condQueries = map[string]string{
	"t": `UPDATE mem_later l SET delivered = true, delivered_at = now(),
		subject = CASE WHEN NOT EXISTS (SELECT 1 FROM tasks t WHERE t.n = l.cond_ref::bigint) THEN left(l.subject || ' (cond gone)', 80) ELSE l.subject END
		WHERE NOT l.delivered AND l.cond_kind = 't'
		  AND (EXISTS (SELECT 1 FROM tasks t WHERE t.n = l.cond_ref::bigint AND t.state = 'done')
		    OR NOT EXISTS (SELECT 1 FROM tasks t WHERE t.n = l.cond_ref::bigint))`,
	"k": `UPDATE mem_later l SET delivered = true, delivered_at = now(),
		subject = CASE WHEN NOT EXISTS (SELECT 1 FROM kb k WHERE k.id = l.cond_ref) THEN left(l.subject || ' (cond gone)', 80) ELSE l.subject END
		WHERE NOT l.delivered AND l.cond_kind = 'k'
		  AND (EXISTS (SELECT 1 FROM kb k WHERE k.id = l.cond_ref AND (k.ok_w > 0 OR k.confirmed_at IS NOT NULL))
		    OR NOT EXISTS (SELECT 1 FROM kb k WHERE k.id = l.cond_ref))`,
	"j": `UPDATE mem_later l SET delivered = true, delivered_at = now(),
		subject = CASE WHEN NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = l.cond_ref) THEN left(l.subject || ' (cond gone)', 80) ELSE l.subject END
		WHERE NOT l.delivered AND l.cond_kind = 'j'
		  AND (EXISTS (SELECT 1 FROM jobs j WHERE j.id = l.cond_ref AND j.status IN ('done', 'failed'))
		    OR NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = l.cond_ref))`,
	"kv": `UPDATE mem_later l SET delivered = true, delivered_at = now(),
		subject = CASE WHEN NOT EXISTS (SELECT 1 FROM kv x WHERE x.ns = split_part(l.cond_ref, '/', 1) AND x.k = substr(l.cond_ref, strpos(l.cond_ref, '/') + 1) AND x.expires_at > now())
		  THEN left(l.subject || ' (cond gone)', 80) ELSE l.subject END
		WHERE NOT l.delivered AND l.cond_kind = 'kv'
		  AND (EXISTS (SELECT 1 FROM kv x WHERE x.ns = split_part(l.cond_ref, '/', 1) AND x.k = substr(l.cond_ref, strpos(l.cond_ref, '/') + 1) AND x.expires_at > now() AND x.ver > l.cond_seen)
		    OR (l.cond_seen > 0 AND NOT EXISTS (SELECT 1 FROM kv x WHERE x.ns = split_part(l.cond_ref, '/', 1) AND x.k = substr(l.cond_ref, strpos(l.cond_ref, '/') + 1) AND x.expires_at > now())))`,
	// bounties (0190) and reviews (0200) belong to later waves: their statements run only once the
	// tables exist (LaterRun checks to_regclass) and are best effort.
	"b": `UPDATE mem_later l SET delivered = true, delivered_at = now(),
		subject = CASE WHEN NOT EXISTS (SELECT 1 FROM bounties b WHERE b.id = l.cond_ref) THEN left(l.subject || ' (cond gone)', 80) ELSE l.subject END
		WHERE NOT l.delivered AND l.cond_kind = 'b'
		  AND (EXISTS (SELECT 1 FROM bounties b WHERE b.id = l.cond_ref AND b.status = 'paid') OR NOT EXISTS (SELECT 1 FROM bounties b WHERE b.id = l.cond_ref))`,
	"r": `UPDATE mem_later l SET delivered = true, delivered_at = now(),
		subject = CASE WHEN NOT EXISTS (SELECT 1 FROM reviews r WHERE r.id = l.cond_ref) THEN left(l.subject || ' (cond gone)', 80) ELSE l.subject END
		WHERE NOT l.delivered AND l.cond_kind = 'r'
		  AND (EXISTS (SELECT 1 FROM reviews r WHERE r.id = l.cond_ref AND r.status = 'answered') OR NOT EXISTS (SELECT 1 FROM reviews r WHERE r.id = l.cond_ref))`,
}

var condTables = map[string]string{"t": "tasks", "k": "kb", "j": "jobs", "kv": "kv", "b": "bounties", "r": "reviews"}

// LaterRun is the janitor task: time-locked rows flip at deliver_at, conditional rows when their
// condition holds or their object is gone, delivered rows are purged 30 d after delivery and
// undelivered ones 30 d after their deadline (deliver_at, or creation for conditions).
func LaterRun(ctx context.Context, q core.Q, log *slog.Logger) error {
	if _, err := q.Exec(ctx, `UPDATE mem_later SET delivered = true, delivered_at = now() WHERE NOT delivered AND cond_kind = '' AND deliver_at <= now()`); err != nil {
		return err
	}
	for _, kind := range []string{"t", "k", "j", "kv", "b", "r"} {
		var n int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM mem_later WHERE NOT delivered AND cond_kind = $1`, kind).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		var reg *string
		if err := q.QueryRow(ctx, `SELECT to_regclass($1)::text`, condTables[kind]).Scan(&reg); err != nil {
			return err
		}
		if reg == nil {
			continue
		}
		if _, err := q.Exec(ctx, condQueries[kind]); err != nil {
			if log != nil {
				log.Warn("later condition", "kind", kind, "err", err)
			}
		}
	}
	_, err := q.Exec(ctx, `DELETE FROM mem_later WHERE (delivered AND delivered_at < now() - interval '30 days')
		OR (NOT delivered AND coalesce(deliver_at, created) < now() - interval '30 days')`)
	return err
}

// laterUnread returns the count and the first subjects of the root's unread delivered messages.
func laterUnread(ctx context.Context, q core.Q, root string, k int) (int, []string, error) {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM mem_later WHERE root = $1 AND delivered AND read_at IS NULL`, root).Scan(&n); err != nil {
		return 0, nil, err
	}
	rows, err := q.Query(ctx, `SELECT subject FROM mem_later WHERE root = $1 AND delivered AND read_at IS NULL ORDER BY delivered_at LIMIT $2`, root, k)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	var subs []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return 0, nil, err
		}
		if s == "" {
			s = "(no subject)"
		}
		subs = append(subs, s)
	}
	return n, subs, rows.Err()
}

type laterReq struct {
	Text  string `json:"text"`
	After string `json:"after"`
	On    string `json:"on"`
}

func (s *svc) hLater(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in laterReq
	if err := core.Decode(w, r, int64(MaxLaterText)+2<<10, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	var after *time.Time
	if in.After != "" {
		t, err := parseAfter(in.After, time.Now())
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		after = &t
	}
	mid, deliver, err := laterPut(r.Context(), s.d.DB, s.d.DB, id.ID, id.Root, in.Text, after, in.On)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, http.StatusCreated, fmt.Sprintf("ok %s deliver=%s", mid, deliver), doc.GET("/v1/me/resume", ""))
}

var _ = pgx.ErrNoRows
