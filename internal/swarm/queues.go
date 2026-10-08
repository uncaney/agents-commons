package swarm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// Work queues (12.5): visibility timeouts, per-item receipts as fencing tokens, requeue and DLQ.
const (
	wqMaxItems = 100
	wqMaxBody  = 4096
	wqKMax     = 10
	wqVisDef   = 60
	wqVisMin   = 30
	wqVisMax   = 3600
	wqDelayMax = 3600
	wqDead     = 5 // deliveries before an item goes to the DLQ
	wqDLQList  = 50
	wqDLQPubs  = 20 // DLQ events published per janitor tick
)

var (
	errNoQueue   = core.E(404, "notfound", "no such queue")
	errReceipt   = core.E(409, "taken", "receipt unknown or stale")
	receiptRe    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	qKeyIdxOnce  sync.Once
	qKeyIdxExist bool
)

type queue struct {
	name, owner, mode string
	onDLQ             bool
}

func wqLoad(ctx context.Context, q core.Q, name string, lock bool) (queue, error) {
	qu := queue{name: name}
	sql := `SELECT owner_root, mode, on_dlq FROM queues WHERE name = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	err := q.QueryRow(ctx, sql, name).Scan(&qu.owner, &qu.mode, &qu.onDLQ)
	if errors.Is(err, pgx.ErrNoRows) {
		return qu, errNoQueue
	}
	return qu, err
}

func newReceipt() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// scopeOK enforces the per-name wq:<glob> scope of scoped tokens (3.5).
func scopeOK(id *core.Ident, n Name) error {
	if id != nil && id.Scopes != nil && !core.ScopeAllowed(id.Scopes, "wq:"+n.Full) {
		return core.E(403, "scope", "wq:"+n.Full)
	}
	return nil
}

// itemsCap refuses pushes past the per-queue live-items cap of the queue owner's level.
func itemsCap(ctx context.Context, q core.Q, qu queue, add int) error {
	var live int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM q_items WHERE queue = $1 AND state IN ('ready', 'leased')`, qu.name).Scan(&live); err != nil {
		return err
	}
	if capN := trust.Cap("queue_items", core.Level(ctx, q, qu.owner)); live+add > capN {
		return quotaErr("queue_items", capN)
	}
	return nil
}

// hasQKeyIndex reports whether the 0131 partial unique index on (queue, key) exists (checked once).
func hasQKeyIndex(ctx context.Context, q core.Q) bool {
	qKeyIdxOnce.Do(func() {
		q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'q_items' AND indexdef LIKE '%UNIQUE%(queue, key)%')`).Scan(&qKeyIdxExist)
	})
	return qKeyIdxExist
}

// Push appends one item to queue (exported for subscriptions and webhooks). A non-empty key makes
// the push exactly-once per (queue, key): with the 0131 partial unique index the insert is `ON
// CONFLICT DO NOTHING`, before it a pre-check serves the same purpose. The queue is created when
// missing (owned by the a: root, else the system root). Returns the item id.
func Push(ctx context.Context, q core.Q, queueName, body, key string) (int64, error) {
	n, err := ParseName(queueName, "")
	if err != nil {
		return 0, err
	}
	if _, err := cleanText("body", &body, wqMaxBody); err != nil {
		return 0, err
	}
	if body == "" {
		return 0, core.Bad("body required")
	}
	if !validKey(key) {
		return 0, core.Bad("key: <= 64 printable ASCII chars")
	}
	var id int64
	err = withTx(ctx, q, func(tx core.Q) error {
		qu, err := wqLoad(ctx, tx, n.Full, true)
		if errors.Is(err, errNoQueue) {
			owner := core.SystemID
			if n.NS == 'a' {
				owner = n.Owner
			}
			if _, err := tx.Exec(ctx, `INSERT INTO queues (name, owner_root, mode) VALUES ($1, $2, $3) ON CONFLICT (name) DO NOTHING`, n.Full, owner, n.Mode()); err != nil {
				return err
			}
			qu, err = wqLoad(ctx, tx, n.Full, true)
		}
		if err != nil {
			return err
		}
		if key != "" && !hasQKeyIndex(ctx, tx) {
			err := tx.QueryRow(ctx, `SELECT id FROM q_items WHERE queue = $1 AND key = $2`, n.Full, key).Scan(&id)
			if err == nil {
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if err := itemsCap(ctx, tx, qu, 1); err != nil {
			return err
		}
		sql := `INSERT INTO q_items (queue, body, key) VALUES ($1, $2, $3) RETURNING id`
		if key != "" && hasQKeyIndex(ctx, tx) {
			sql = `INSERT INTO q_items (queue, body, key) VALUES ($1, $2, $3) ON CONFLICT (queue, key) WHERE key <> '' DO NOTHING RETURNING id`
		}
		err = tx.QueryRow(ctx, sql, n.Full, body, key).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return tx.QueryRow(ctx, `SELECT id FROM q_items WHERE queue = $1 AND key = $2`, n.Full, key).Scan(&id)
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE queues SET items = items + 1, last_at = now() WHERE name = $1`, n.Full)
		return err
	})
	if err != nil {
		return 0, err
	}
	wake("wq:" + n.Full)
	return id, nil
}

type wqPushIn struct {
	Items []string `json:"items"`
	Key   string   `json:"key"`
	OnDLQ bool     `json:"on_dlq"`
}

// push is POST /v1/wq/{name} and op wq: create the queue on first use (live-queues cap), items
// cap of the owner, pushes/day cap of the caller, scrub, idempotent by key.
func (s *svc) push(ctx context.Context, id *core.Ident, raw string, in wqPushIn, idemKey string) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if err := scopeOK(id, n); err != nil {
		return reply{}, err
	}
	if len(in.Items) == 0 || len(in.Items) > wqMaxItems {
		return reply{}, core.Bad("items: 1..100 bodies")
	}
	kinds := map[string]bool{}
	for i := range in.Items {
		m, err := cleanText("items", &in.Items[i], wqMaxBody)
		if err != nil {
			return reply{}, err
		}
		if in.Items[i] == "" {
			return reply{}, core.Bad("items: empty body")
		}
		for _, k := range m {
			kinds[k] = true
		}
	}
	if err := Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	if err := s.frozen("swarm"); err != nil {
		return reply{}, err
	}
	run := func() (int, string, error) {
		var ids []string
		err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			qu, err := wqLoad(ctx, tx, n.Full, true)
			if errors.Is(err, errNoQueue) {
				if err := rootLock(ctx, tx, id.Root); err != nil {
					return err
				}
				if err := liveCap(ctx, tx, id.Root, "queues", `SELECT count(*) FROM queues WHERE owner_root = $1`); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO queues (name, owner_root, mode, on_dlq) VALUES ($1, $2, $3, $4) ON CONFLICT (name) DO NOTHING`,
					n.Full, id.Root, n.Mode(), in.OnDLQ); err != nil {
					return err
				}
				qu, err = wqLoad(ctx, tx, n.Full, true)
			}
			if err != nil {
				return err
			}
			if in.OnDLQ && !qu.onDLQ && qu.owner == id.Root {
				if _, err := tx.Exec(ctx, `UPDATE queues SET on_dlq = true WHERE name = $1`, n.Full); err != nil {
					return err
				}
			}
			if err := itemsCap(ctx, tx, qu, len(in.Items)); err != nil {
				return err
			}
			if err := useCap(ctx, tx, id.Root, "wq_push", "queue_pushes", 1); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `INSERT INTO q_items (queue, body) SELECT $1, unnest($2::text[]) RETURNING id`, n.Full, in.Items)
			if err != nil {
				return err
			}
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				ids = append(ids, strconv.FormatInt(id, 10))
			}
			rows.Close()
			_, err = tx.Exec(ctx, `UPDATE queues SET items = items + $2, last_at = now() WHERE name = $1`, n.Full, len(ids))
			return err
		})
		if err != nil {
			return 0, "", err
		}
		wake("wq:" + n.Full)
		var masked []string
		for k := range kinds {
			masked = append(masked, k)
		}
		sort.Strings(masked)
		return http.StatusOK, fmt.Sprintf("ok n=%d ids=%s", len(ids), strings.Join(ids, ",")) + maskedField(masked), nil
	}
	h := sha256.New()
	for _, it := range in.Items {
		h.Write([]byte(it))
		h.Write([]byte{0})
	}
	status, body, err := core.Idem(ctx, s.d, id, idemKey, "wq "+n.Full, h.Sum(nil), run)
	if err != nil {
		return reply{}, err
	}
	p := "/v1/wq/" + n.Full
	return reply{status: status, text: body, next: []doc.Action{doc.POST(p+"/take", "take"), doc.GET(p, "counts")}}, nil
}

type wqTakeIn struct {
	K    int `json:"k"`
	VisS int `json:"vis_s"`
	Wait int `json:"wait"`
}

type leased struct {
	id            int64
	deliveries    int
	receipt, body string
}

// take is POST /v1/wq/{name}/take and op wqt.
func (s *svc) take(ctx context.Context, id *core.Ident, raw string, in wqTakeIn, grp string) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if err := scopeOK(id, n); err != nil {
		return reply{}, err
	}
	k, err := checkRange("k", in.K, 1, 1, wqKMax)
	if err != nil {
		return reply{}, err
	}
	vis, err := checkRange("vis_s", in.VisS, wqVisDef, wqVisMin, wqVisMax)
	if err != nil {
		return reply{}, err
	}
	if err := checkWait(in.Wait); err != nil {
		return reply{}, err
	}
	if err := Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	if err := s.frozen("swarm"); err != nil {
		return reply{}, err
	}
	if _, err := wqLoad(ctx, s.d.DB, n.Full, false); err != nil {
		return reply{}, err
	}
	var items []leased
	retry, err := s.pollHint(ctx, id, grp, in.Wait, "wq:"+n.Full, func(ctx context.Context) (bool, time.Time, error) {
		ls, err := s.takeTx(ctx, n.Full, k, vis)
		items = ls
		if err != nil || len(ls) > 0 || in.Wait == 0 {
			return len(ls) > 0, time.Time{}, err
		}
		// A nack delay ends without a wake: sleep at most until the earliest one.
		var next *time.Time
		err = s.d.DB.QueryRow(ctx, `SELECT min(vis_until) FROM q_items WHERE queue = $1 AND state = 'ready' AND vis_until > now()`, n.Full).Scan(&next)
		if err != nil || next == nil {
			return false, time.Time{}, err
		}
		return false, *next, nil
	})
	if err != nil {
		return reply{}, err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "ok k=%d", len(items))
	if retry > 0 {
		sb.WriteString(" retry=" + strconv.Itoa(retry))
	}
	for _, it := range items {
		fmt.Fprintf(&sb, "\n%d deliveries=%d receipt=%s\n  %s", it.id, it.deliveries, it.receipt, doc.Indent(it.body))
	}
	p := "/v1/wq/" + n.Full
	return reply{text: sb.String(), next: []doc.Action{doc.POST(p+"/ack", "ack receipt"), doc.POST(p+"/nack", "nack receipt"), doc.POST(p+"/take", "take")}}, nil
}

// takeTx leases up to k ready items (FOR UPDATE SKIP LOCKED) with fresh receipts.
func (s *svc) takeTx(ctx context.Context, name string, k, vis int) ([]leased, error) {
	var out []leased
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, body FROM q_items WHERE queue = $1 AND state = 'ready' AND (vis_until IS NULL OR vis_until <= now())
			ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED`, name, k)
		if err != nil {
			return err
		}
		for rows.Next() {
			var it leased
			if err := rows.Scan(&it.id, &it.body); err != nil {
				rows.Close()
				return err
			}
			out = append(out, it)
		}
		rows.Close()
		for i := range out {
			out[i].receipt = newReceipt()
			if err := tx.QueryRow(ctx, `UPDATE q_items SET state = 'leased', deliveries = deliveries + 1, receipt = $2, vis_until = now() + $3 * interval '1 second'
				WHERE id = $1 RETURNING deliveries`, out[i].id, out[i].receipt, vis).Scan(&out[i].deliveries); err != nil {
				return err
			}
		}
		if len(out) > 0 {
			_, err = tx.Exec(ctx, `UPDATE queues SET last_at = now() WHERE name = $1`, name)
		}
		return err
	})
	return out, err
}

type wqAckIn struct {
	Receipt string `json:"receipt"`
	Lock    string `json:"lock"`
	Fence   int64  `json:"fence"`
}

// ack is POST /v1/wq/{name}/ack and op wqa: the receipt is the per-item fencing token; an optional
// lock + fence pair is enforced through CheckFence in the same transaction.
func (s *svc) ack(ctx context.Context, id *core.Ident, raw string, in wqAckIn) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if err := scopeOK(id, n); err != nil {
		return reply{}, err
	}
	if err := Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	if !receiptRe.MatchString(in.Receipt) {
		return reply{}, errReceipt
	}
	var lockName string
	if in.Lock != "" {
		ln, err := ParseName(in.Lock, id.Root)
		if err != nil {
			return reply{}, core.Bad("lock: lock name")
		}
		lockName = ln.Full
	}
	var itemID int64
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if lockName != "" {
			if err := CheckFence(ctx, tx, lockName, in.Fence); err != nil {
				return err
			}
		}
		err := tx.QueryRow(ctx, `UPDATE q_items SET state = 'done', vis_until = NULL, done_at = now()
			WHERE queue = $1 AND receipt = $2 AND state = 'leased' AND vis_until > now() RETURNING id`, n.Full, in.Receipt).Scan(&itemID)
		if errors.Is(err, pgx.ErrNoRows) {
			return errReceipt
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE queues SET items = greatest(items - 1, 0), last_at = now() WHERE name = $1`, n.Full)
		return err
	})
	if err != nil {
		return reply{}, err
	}
	p := "/v1/wq/" + n.Full
	return reply{text: fmt.Sprintf("ok done=%d", itemID), next: []doc.Action{doc.POST(p+"/take", "take"), doc.GET(p, "counts")}}, nil
}

type wqNackIn struct {
	Receipt string `json:"receipt"`
	DelayS  int    `json:"delay_s"`
}

// nack is POST /v1/wq/{name}/nack and op wqn: back to ready after delay_s.
func (s *svc) nack(ctx context.Context, id *core.Ident, raw string, in wqNackIn) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if err := scopeOK(id, n); err != nil {
		return reply{}, err
	}
	if in.DelayS < 0 || in.DelayS > wqDelayMax {
		return reply{}, core.Bad("delay_s must be 0..3600")
	}
	if err := Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	if !receiptRe.MatchString(in.Receipt) {
		return reply{}, errReceipt
	}
	var itemID int64
	err = s.d.DB.QueryRow(ctx, `UPDATE q_items SET state = 'ready', receipt = NULL, vis_until = now() + $3 * interval '1 second'
		WHERE queue = $1 AND receipt = $2 AND state = 'leased' RETURNING id`, n.Full, in.Receipt, in.DelayS).Scan(&itemID)
	if errors.Is(err, pgx.ErrNoRows) {
		return reply{}, errReceipt
	}
	if err != nil {
		return reply{}, err
	}
	wake("wq:" + n.Full)
	p := "/v1/wq/" + n.Full
	return reply{text: fmt.Sprintf("ok ready=%d", itemID), next: []doc.Action{doc.POST(p+"/take", "take"), doc.GET(p, "counts")}}, nil
}

type wqExtendIn struct {
	Receipt string `json:"receipt"`
	VisS    int    `json:"vis_s"`
}

// extend is POST /v1/wq/{name}/extend and op wqx.
func (s *svc) extend(ctx context.Context, id *core.Ident, raw string, in wqExtendIn) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if err := scopeOK(id, n); err != nil {
		return reply{}, err
	}
	vis, err := checkRange("vis_s", in.VisS, wqVisDef, wqVisMin, wqVisMax)
	if err != nil {
		return reply{}, err
	}
	if err := Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	if !receiptRe.MatchString(in.Receipt) {
		return reply{}, errReceipt
	}
	var until time.Time
	err = s.d.DB.QueryRow(ctx, `UPDATE q_items SET vis_until = now() + $3 * interval '1 second'
		WHERE queue = $1 AND receipt = $2 AND state = 'leased' AND vis_until > now() RETURNING vis_until`, n.Full, in.Receipt, vis).Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		return reply{}, errReceipt
	}
	if err != nil {
		return reply{}, err
	}
	p := "/v1/wq/" + n.Full
	return reply{text: "ok until=" + unix(until), next: []doc.Action{doc.POST(p+"/ack", "ack"), doc.POST(p+"/extend", "extend")}}, nil
}

// stats is GET /v1/wq/{name} (anonymous for g:): counts, plus the dead items with ?dlq=1.
func (s *svc) stats(ctx context.Context, id *core.Ident, raw string, dlq bool) (reply, error) {
	n, err := ParseName(raw, rootOf(id))
	if err != nil {
		return reply{}, err
	}
	if err := scopeOK(id, n); err != nil {
		return reply{}, err
	}
	if err := Access(ctx, s.d.DB, id, n, false); err != nil {
		return reply{}, err
	}
	qu, err := wqLoad(ctx, s.d.DB, n.Full, false)
	if err != nil {
		return reply{}, err
	}
	var ready, leasedN, done, dead int
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'ready'), count(*) FILTER (WHERE state = 'leased'),
		count(*) FILTER (WHERE state = 'done'), count(*) FILTER (WHERE state = 'dead') FROM q_items WHERE queue = $1`, n.Full).
		Scan(&ready, &leasedN, &done, &dead); err != nil {
		return reply{}, err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "wq %s ready=%d leased=%d done=%d dead=%d", n.Full, ready, leasedN, done, dead)
	if qu.onDLQ {
		sb.WriteString(" on_dlq=1")
	}
	if dlq {
		rows, err := s.d.DB.Query(ctx, `SELECT id, deliveries, body FROM q_items WHERE queue = $1 AND state = 'dead' ORDER BY id DESC LIMIT $2`, n.Full, wqDLQList)
		if err != nil {
			return reply{}, err
		}
		defer rows.Close()
		for rows.Next() {
			var itemID int64
			var deliveries int
			var body string
			if err := rows.Scan(&itemID, &deliveries, &body); err != nil {
				return reply{}, err
			}
			fmt.Fprintf(&sb, "\n%d deliveries=%d\n  %s", itemID, deliveries, doc.Indent(body))
		}
	}
	p := "/v1/wq/" + n.Full
	return reply{text: sb.String(), next: []doc.Action{doc.POST(p+"/take", "take"), doc.POST(p, "push"), doc.GET(p+"?dlq=1", "dead letters")}}, nil
}

// --- HTTP ---------------------------------------------------------------------------------------

func (s *svc) wqPush(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in wqPushIn
	if err := core.Decode(w, r, pushMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	key := in.Key
	if key == "" {
		key = core.IdemKey(r.Header)
	}
	rep, err := s.push(r.Context(), id, r.PathValue("name"), in, key)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) wqTake(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in wqTakeIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.take(r.Context(), id, r.PathValue("name"), in, s.grp(r))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) wqAck(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in wqAckIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.ack(r.Context(), id, r.PathValue("name"), in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) wqNack(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in wqNackIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.nack(r.Context(), id, r.PathValue("name"), in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) wqExtend(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in wqExtendIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.extend(r.Context(), id, r.PathValue("name"), in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) wqGet(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	v := r.URL.Query().Get("dlq")
	rep, err := s.stats(r.Context(), id, r.PathValue("name"), v == "1" || v == "true")
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

// --- janitor ------------------------------------------------------------------------------------

// janQueues requeues expired leases (dead after 5 deliveries, with a DLQ event when configured),
// applies the 7 d retention of done/dead items, refreshes the count caches and drops idle queues.
func (s *svc) janQueues(ctx context.Context) error {
	q := s.d.DB
	rows, err := q.Query(ctx, `UPDATE q_items SET state = CASE WHEN deliveries >= $1 THEN 'dead' ELSE 'ready' END, receipt = NULL, vis_until = NULL,
		done_at = CASE WHEN deliveries >= $1 THEN now() ELSE NULL END
		WHERE state = 'leased' AND vis_until <= now() RETURNING id, queue, state, deliveries`, wqDead)
	if err != nil {
		return err
	}
	type moved struct {
		id         int64
		queue      string
		dead       bool
		deliveries int
	}
	var ms []moved
	for rows.Next() {
		var m moved
		var state string
		if err := rows.Scan(&m.id, &m.queue, &state, &m.deliveries); err != nil {
			rows.Close()
			return err
		}
		m.dead = state == "dead"
		ms = append(ms, m)
	}
	rows.Close()
	woken := map[string]bool{}
	pubs := 0
	for _, m := range ms {
		if !woken[m.queue] {
			woken[m.queue] = true
			wake("wq:" + m.queue)
		}
		if !m.dead {
			continue
		}
		qu, err := wqLoad(ctx, q, m.queue, false)
		if err != nil || !qu.onDLQ || pubs >= wqDLQPubs {
			continue
		}
		pubs++
		text := fmt.Sprintf("dlq %s %d deliveries=%d", m.queue, m.id, m.deliveries)
		if _, err := Publish(ctx, q, m.queue+".dlq", core.SystemID, core.SystemID, text, ""); err != nil {
			s.d.Log.Warn("swarm dlq publish", "queue", m.queue, "err", err)
		}
	}
	for _, st := range []string{
		`DELETE FROM q_items WHERE state IN ('done', 'dead') AND done_at < now() - interval '7 days'`,
		`UPDATE queues t SET items = c.live, dlq = c.dead FROM (SELECT queue, count(*) FILTER (WHERE state IN ('ready', 'leased')) AS live,
			count(*) FILTER (WHERE state = 'dead') AS dead FROM q_items GROUP BY queue) c WHERE c.queue = t.name AND (t.items <> c.live OR t.dlq <> c.dead)`,
		`UPDATE queues SET items = 0, dlq = 0 WHERE (items <> 0 OR dlq <> 0) AND NOT EXISTS (SELECT 1 FROM q_items WHERE queue = queues.name)`,
		`DELETE FROM queues WHERE last_at < now() - interval '7 days' AND NOT EXISTS (SELECT 1 FROM q_items WHERE queue = queues.name)`,
	} {
		if _, err := q.Exec(ctx, st); err != nil {
			return err
		}
	}
	return nil
}
