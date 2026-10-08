package swarm

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Topics (12.4): ordered pub/sub with cursors. seq comes from `UPDATE topics SET last_seq =
// last_seq + 1 RETURNING` inside the insert transaction, after the idempotent-key check, so the
// sequence is gapless and totally ordered.
const (
	psMaxText = 4096
	psMaxKey  = 64
	psKDef    = 10
	psKMax    = 50
	psPullMax = 100 // exported Pull ceiling (subscriptions pull 100)
	psMaxKB   = 64
	psKeep    = 1000
)

// Msg is one topic message as returned by Pull.
type Msg struct {
	Seq            int64
	By, Root, Text string
	Key            string
	Flags          []string
	Hidden         bool
	Created        time.Time
}

type pubIn struct {
	topic         Name
	by, root      string
	text, key     string
	flags         []string
	caps          func(ctx context.Context, tx core.Q) error // charged after the replay check
	masked, extra []string
}

// withTx runs fn inside a transaction when q is a pool, directly on q otherwise (a caller's tx).
func withTx(ctx context.Context, q core.Q, fn func(core.Q) error) error {
	if p, ok := q.(*pgxpool.Pool); ok {
		return core.Tx(ctx, p, func(tx pgx.Tx) error { return fn(tx) })
	}
	return fn(q)
}

func validKey(key string) bool {
	return len(key) <= psMaxKey && !strings.ContainsFunc(key, func(r rune) bool { return r < 0x21 || r > 0x7e })
}

// Publish appends text to topic as identity by (of root) with an optional 24 h idempotency key
// (exported for announce, lock expiry and DLQ notices, subscriptions and webhooks). Scrub and size
// caps always apply; for every root but the system root the namespace gate (Access) and the 4.3
// daily publish caps apply too, so callers acting as an identity need no gate of their own. A
// reused key returns the earlier seq without charging the caps.
func Publish(ctx context.Context, q core.Q, topic, by, root, text, key string) (int64, error) {
	seq, _, err := PublishFlags(ctx, q, topic, by, root, text, key, nil)
	return seq, err
}

// PublishFlags is Publish with message flags (via=sub is added for keys prefixed sub:) and a
// replay indicator.
func PublishFlags(ctx context.Context, q core.Q, topic, by, root, text, key string, flags []string) (seq int64, replay bool, err error) {
	n, err := ParseName(topic, root)
	if err != nil {
		return 0, false, err
	}
	in := pubIn{topic: n, by: by, root: root, text: text, key: key, flags: flags}
	if root != core.SystemID {
		if !core.ValidID(by) || !core.ValidID(root) {
			return 0, false, core.Bad("by/root: identity ids")
		}
		if err := Access(ctx, q, &core.Ident{ID: by, Root: root}, n, true); err != nil {
			return 0, false, err
		}
		in.caps = pubCaps(root, n)
	}
	err = withTx(ctx, q, func(tx core.Q) error {
		seq, replay, err = publishTx(ctx, tx, &in)
		return err
	})
	if err == nil && !replay {
		wake("ps:" + n.Full)
	}
	return seq, replay, err
}

// publishTx is the publish transaction: clean, lock (or create) the topic row, replay check on the
// key, caps, seq bump, insert.
func publishTx(ctx context.Context, tx core.Q, in *pubIn) (int64, bool, error) {
	masked, err := cleanText("text", &in.text, psMaxText)
	if err != nil {
		return 0, false, err
	}
	in.masked = masked
	if in.text == "" {
		return 0, false, core.Bad("text required")
	}
	if !validKey(in.key) {
		return 0, false, core.Bad("key: <= 64 printable ASCII chars")
	}
	if !core.ValidID(in.by) || !core.ValidID(in.root) {
		return 0, false, core.Bad("by/root: identity ids")
	}
	flags := in.flags
	if strings.HasPrefix(in.key, "sub:") && !slices.Contains(flags, "via=sub") {
		flags = append(flags, "via=sub")
	}
	if flags == nil {
		flags = []string{}
	}
	var lastSeq int64
	if err := tx.QueryRow(ctx, `INSERT INTO topics (name, owner_root, mode) VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING last_seq`, in.topic.Full, in.root, in.topic.Mode()).Scan(&lastSeq); err != nil {
		return 0, false, err
	}
	if in.key != "" {
		var seq int64
		err := tx.QueryRow(ctx, `SELECT seq FROM topic_msgs WHERE topic = $1 AND root = $2 AND key = $3`, in.topic.Full, in.root, in.key).Scan(&seq)
		if err == nil {
			return seq, true, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, false, err
		}
	}
	if in.caps != nil {
		if err := in.caps(ctx, tx); err != nil {
			return 0, false, err
		}
	}
	var seq int64
	if err := tx.QueryRow(ctx, `UPDATE topics SET last_seq = last_seq + 1, msgs = msgs + 1 WHERE name = $1 RETURNING last_seq`, in.topic.Full).Scan(&seq); err != nil {
		return 0, false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO topic_msgs (topic, seq, by, root, text, key, flags) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		in.topic.Full, seq, in.by, in.root, in.text, in.key, flags); err != nil {
		return 0, false, err
	}
	return seq, false, nil
}

// pubCaps charges the 4.3 publish caps of root: per topic (counter ps:<topic>) and per root.
func pubCaps(root string, n Name) func(ctx context.Context, tx core.Q) error {
	return func(ctx context.Context, tx core.Q) error {
		if err := useCap(ctx, tx, root, "ps:"+n.Full, "topic_pub", 1); err != nil {
			return err
		}
		return useCap(ctx, tx, root, "ps", "topic_pub_root", 1)
	}
}

// Pull returns up to k messages of topic after seq `after` in order (exported for subscriptions);
// a hidden message keeps its seq and flags but carries no text.
func Pull(ctx context.Context, q core.Q, topic string, after int64, k int) ([]Msg, error) {
	if k <= 0 {
		k = psKDef
	}
	k = min(k, psPullMax)
	rows, err := q.Query(ctx, `SELECT seq, by, root, CASE WHEN hidden THEN '' ELSE text END, key, flags, hidden, created FROM topic_msgs
		WHERE topic = $1 AND seq > $2 ORDER BY seq LIMIT $3`, topic, after, k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Msg
	for rows.Next() {
		var m Msg
		if err := rows.Scan(&m.Seq, &m.By, &m.Root, &m.Text, &m.Key, &m.Flags, &m.Hidden, &m.Created); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// line renders a message row: `<seq> <by> <date> <text indented>`; hidden rows keep their seq.
func (m Msg) line() string {
	by := m.By
	if by == "" {
		by = "-"
	}
	text := "[hidden]"
	if !m.Hidden {
		text = doc.Indent(m.Text)
	}
	return fmt.Sprintf("%d %s %s %s", m.Seq, by, stamp(m.Created), text)
}

// publish is POST /v1/ps/{topic} and op pub: access, caps (per topic and per root), scrub, gapless seq.
func (s *svc) publish(ctx context.Context, id *core.Ident, raw, text, key, idemKey string) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if err := Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	if err := s.frozen("topic_msgs"); err != nil {
		return reply{}, err
	}
	run := func() (int, string, error) {
		in := pubIn{topic: n, by: id.ID, root: id.Root, text: text, key: key, caps: pubCaps(id.Root, n)}
		var seq int64
		var replay bool
		err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			var err error
			seq, replay, err = publishTx(ctx, tx, &in)
			return err
		})
		if err != nil {
			return 0, "", err
		}
		if !replay {
			wake("ps:" + n.Full)
		}
		out := fmt.Sprintf("ok seq=%d", seq) + maskedField(in.masked)
		if replay {
			out += " idem=replay"
		}
		return http.StatusOK, out, nil
	}
	h := sha256.Sum256([]byte(text + "\x00" + key))
	status, body, err := core.Idem(ctx, s.d, id, idemKey, "pub "+n.Full, h[:], run)
	if err != nil {
		return reply{}, err
	}
	p := "/v1/ps/" + n.Full
	return reply{status: status, text: body, next: []doc.Action{doc.GET(p, "pull"), doc.POST(p, "publish")}}, nil
}

type pullIn struct {
	after        int64
	hasAfter     bool
	k, maxKB     int
	wait         int
	cursorIfNone bool
}

// pull is GET /v1/ps/{topic} and op pull: rows after the cursor (?after=, else the caller's saved
// cursor), bounded by k and max_kb, long-polling ps:<topic> when empty.
func (s *svc) pull(ctx context.Context, id *core.Ident, raw string, in pullIn, grp string) (reply, error) {
	n, err := ParseName(raw, rootOf(id))
	if err != nil {
		return reply{}, err
	}
	k, err := checkRange("k", in.k, psKDef, 1, psKMax)
	if err != nil {
		return reply{}, err
	}
	maxKB, err := checkRange("max_kb", in.maxKB, psMaxKB, 1, psMaxKB)
	if err != nil {
		return reply{}, err
	}
	if err := checkWait(in.wait); err != nil {
		return reply{}, err
	}
	if err := Access(ctx, s.d.DB, id, n, false); err != nil {
		return reply{}, err
	}
	after := in.after
	if !in.hasAfter && id != nil {
		if err := s.d.DB.QueryRow(ctx, `SELECT seq FROM topic_cursors WHERE topic = $1 AND root = $2`, n.Full, id.Root).Scan(&after); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return reply{}, err
		}
	}
	var msgs []Msg
	retry, err := s.poll(ctx, id, grp, in.wait, "ps:"+n.Full, func(ctx context.Context) (bool, error) {
		ms, err := Pull(ctx, s.d.DB, n.Full, after, k)
		msgs = ms
		return len(ms) > 0, err
	})
	if err != nil {
		return reply{}, err
	}
	var lastSeq int64
	var count int
	if err := s.d.DB.QueryRow(ctx, `SELECT last_seq, msgs FROM topics WHERE name = $1`, n.Full).Scan(&lastSeq, &count); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return reply{}, err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "ps %s last=%d msgs=%d", n.Full, lastSeq, count)
	if TopicExtraFn != nil {
		for _, f := range TopicExtraFn(ctx, s.d.DB, n.Full) {
			if f = doc.SafeLine(f); f != "" {
				sb.WriteString(" " + f)
			}
		}
	}
	if retry > 0 {
		sb.WriteString(" retry=" + strconv.Itoa(retry))
	}
	next := after
	total := 0
	for i, m := range msgs {
		if i > 0 && total+len(m.Text) > maxKB<<10 {
			break
		}
		total += len(m.Text)
		sb.WriteString("\n" + m.line())
		next = m.Seq
	}
	fmt.Fprintf(&sb, "\nnext=%d", next)
	p := "/v1/ps/" + n.Full
	return reply{text: sb.String(), next: []doc.Action{
		doc.GET(fmt.Sprintf("%s?after=%d&wait=85", p, next), "poll"), doc.POST(p, "publish"), {Method: "PUT", Path: "/v1/pscur/" + n.Full, Hint: "save cursor"}}}, nil
}

// cursorSet is PUT /v1/pscur/{topic} and op cur{topic,seq}.
func (s *svc) cursorSet(ctx context.Context, id *core.Ident, raw string, seq int64) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if seq < 0 {
		return reply{}, core.Bad("seq must be >= 0")
	}
	if err := Access(ctx, s.d.DB, id, n, false); err != nil {
		return reply{}, err
	}
	if _, err := s.d.DB.Exec(ctx, `INSERT INTO topic_cursors (topic, root, seq) VALUES ($1, $2, $3)
		ON CONFLICT (topic, root) DO UPDATE SET seq = EXCLUDED.seq, updated = now()`, n.Full, id.Root, seq); err != nil {
		return reply{}, err
	}
	return reply{text: fmt.Sprintf("ok seq=%d", seq), next: []doc.Action{doc.GET(fmt.Sprintf("/v1/ps/%s?after=%d", n.Full, seq), "pull")}}, nil
}

// cursorGet is GET /v1/pscur/{topic} and op cur{topic}.
func (s *svc) cursorGet(ctx context.Context, id *core.Ident, raw string) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if err := Access(ctx, s.d.DB, id, n, false); err != nil {
		return reply{}, err
	}
	var seq int64
	if err := s.d.DB.QueryRow(ctx, `SELECT seq FROM topic_cursors WHERE topic = $1 AND root = $2`, n.Full, id.Root).Scan(&seq); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return reply{}, err
	}
	return reply{text: fmt.Sprintf("seq=%d", seq), next: []doc.Action{doc.GET(fmt.Sprintf("/v1/ps/%s?after=%d", n.Full, seq), "pull")}}, nil
}

// --- HTTP ---------------------------------------------------------------------------------------

func (s *svc) psPub(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		Text string `json:"text"`
		Key  string `json:"key"`
	}
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.publish(r.Context(), id, r.PathValue("topic"), in.Text, in.Key, core.IdemKey(r.Header))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) psPull(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in pullIn
	if in.after, in.hasAfter, err = queryInt64(r, "after"); err != nil {
		doc.Fail(w, r, err)
		return
	}
	for _, p := range []struct {
		name string
		dst  *int
	}{{"k", &in.k}, {"max_kb", &in.maxKB}, {"wait", &in.wait}} {
		if *p.dst, err = queryInt(r, p.name); err != nil {
			doc.Fail(w, r, err)
			return
		}
	}
	rep, err := s.pull(r.Context(), id, r.PathValue("topic"), in, s.grp(r))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) psCurSet(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		Seq int64 `json:"seq"`
	}
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.cursorSet(r.Context(), id, r.PathValue("topic"), in.Seq)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) psCurGet(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.cursorGet(r.Context(), id, r.PathValue("topic"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

// --- feed, report target, janitor ---------------------------------------------------------------

// psFeed serves /f/ps/<topic>.atom|.json for open (g:) topics.
func (s *svc) psFeed(ctx context.Context, sub string, n int) ([]core.FeedItem, error) {
	nm, err := ParseName(sub, "")
	if err != nil || nm.NS != 'g' {
		return nil, core.ErrNotFound
	}
	rows, err := s.d.DB.Query(ctx, `SELECT seq, by, text, created FROM topic_msgs WHERE topic = $1 AND NOT hidden ORDER BY seq DESC LIMIT $2`, nm.Full, max(1, min(n, 100)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.FeedItem
	for rows.Next() {
		var seq int64
		var by, text string
		var created time.Time
		if err := rows.Scan(&seq, &by, &text, &created); err != nil {
			return nil, err
		}
		title, _, _ := strings.Cut(text, "\n")
		if len(title) > 80 {
			title = title[:80]
		}
		out = append(out, core.FeedItem{ID: nm.Full + "/" + strconv.FormatInt(seq, 10),
			URL: fmt.Sprintf("%s/v1/ps/%s?after=%d&k=1", doc.Base(), nm.Full, seq-1), Title: doc.SafeLine(title), Summary: text,
			Updated: created, Published: created, Author: by})
	}
	return out, rows.Err()
}

// psRef splits a report ref `<topic>/<seq>`.
func psRef(ref string) (string, int64, error) {
	i := strings.LastIndexByte(ref, '/')
	if i <= 0 {
		return "", 0, core.ErrNotFound
	}
	seq, err := strconv.ParseInt(ref[i+1:], 10, 64)
	if err != nil || seq <= 0 {
		return "", 0, core.ErrNotFound
	}
	return ref[:i], seq, nil
}

func (s *svc) psExists(ctx context.Context, q core.Q, ref string) error {
	topic, seq, err := psRef(ref)
	if err != nil {
		return err
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM topic_msgs WHERE topic = $1 AND seq = $2)`, topic, seq).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func (s *svc) psHide(ctx context.Context, q core.Q, ref string) error {
	return s.psSetHidden(ctx, q, ref, true)
}

func (s *svc) psRestore(ctx context.Context, q core.Q, ref string) error {
	return s.psSetHidden(ctx, q, ref, false)
}

func (s *svc) psSetHidden(ctx context.Context, q core.Q, ref string, hidden bool) error {
	topic, seq, err := psRef(ref)
	if err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `UPDATE topic_msgs SET hidden = $3 WHERE topic = $1 AND seq = $2`, topic, seq, hidden)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return nil
}

// janTopics applies retention (7 d or the last 1000 messages per topic) and refreshes counts.
func (s *svc) janTopics(ctx context.Context) error {
	for _, st := range []string{
		`DELETE FROM topic_msgs WHERE created < now() - interval '7 days'`,
		`DELETE FROM topic_msgs m USING topics t WHERE m.topic = t.name AND m.seq <= t.last_seq - ` + strconv.Itoa(psKeep),
		`UPDATE topics t SET msgs = c.n FROM (SELECT topic, count(*) AS n FROM topic_msgs GROUP BY topic) c WHERE c.topic = t.name AND t.msgs <> c.n`,
		`UPDATE topics SET msgs = 0 WHERE msgs <> 0 AND NOT EXISTS (SELECT 1 FROM topic_msgs WHERE topic = topics.name)`,
		`DELETE FROM topic_cursors WHERE updated < now() - interval '30 days'`,
	} {
		if _, err := s.d.DB.Exec(ctx, st); err != nil {
			return err
		}
	}
	return nil
}
