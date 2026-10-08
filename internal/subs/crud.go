package subs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/mem"
	"ekaii.fr/commons/internal/swarm"
)

var svcNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)

// CreateIn is the POST /v1/sub body.
type CreateIn struct {
	Topic   string `json:"topic"`
	Sink    string `json:"sink"`
	To      string `json:"to"`
	Filter  string `json:"filter"`
	Mode    string `json:"mode"`
	HopMax  int    `json:"hop_max"`
	TTLh    int    `json:"ttl_h"`
	MaxCred int    `json:"max_credits_day"`
}

// Create registers a subscription for id (acting as its root): validates the topic, sink, filter
// and (for fn) the output target, rechecks sink authorisation, enforces the per-root and per-topic
// caps, and returns the new sub.
func (s *Service) Create(ctx context.Context, id *core.Ident, in CreateIn) (*Sub, error) {
	if id == nil {
		return nil, core.ErrAuth
	}
	if id.Banned {
		return nil, core.ErrBanned
	}
	if s.d.Frozen("write") {
		return nil, core.Frozen("write")
	}
	topic, err := swarm.ParseName(in.Topic, id.Root)
	if err != nil {
		return nil, err
	}
	// The subscriber must be able to read the topic it binds.
	if err := swarm.Access(ctx, s.d.DB, id, topic, false); err != nil {
		return nil, err
	}
	mode := in.Mode
	if mode == "" {
		mode = "each"
	}
	if mode != "each" && mode != "digest" {
		return nil, core.Bad("mode must be each or digest")
	}
	if len(in.Filter) > maxFilter {
		return nil, core.Bad(fmt.Sprintf("filter must be <= %d chars", maxFilter))
	}
	if err := s.compileFilter(in.Filter); err != nil {
		return nil, err
	}
	kind, rest, err := parseSink(in.Sink)
	if err != nil {
		return nil, err
	}
	if mode == "digest" && kind != "mb" {
		return nil, core.Bad("digest mode is only for a mailbox sink")
	}
	sub := &Sub{
		ID: core.NewID('u'), Root: id.Root, Topic: topic.Full,
		SinkKind: kind, Sink: in.Sink, Filter: in.Filter, Mode: mode,
		HopMax: in.HopMax, MaxCreditsDay: in.MaxCred,
	}
	if sub.HopMax <= 0 {
		sub.HopMax = hopMaxDefault
	}
	if sub.HopMax > 16 {
		return nil, core.Bad("hop_max must be 1..16")
	}
	if sub.MaxCreditsDay <= 0 {
		sub.MaxCreditsDay = maxCreditsDay
	}
	if kind == "fn" {
		if !svcRefOK(rest) {
			return nil, core.Bad("fn sink must be fn:<svc>@<ver> or fn:<svc>")
		}
		if in.To == "" {
			return nil, core.Bad("fn sink needs a to: destination")
		}
		tk, key, err := parseTo(in.To)
		if err != nil {
			return nil, err
		}
		sub.ToKind, sub.ToKey = tk, key
	} else if in.To != "" {
		return nil, core.Bad("to: is only for fn sinks")
	}
	if in.TTLh > 0 {
		if in.TTLh > 24*365 {
			return nil, core.Bad("ttl_h too large")
		}
		u := time.Now().Add(time.Duration(in.TTLh) * time.Hour)
		sub.Until = &u
	}
	// Authorisation of the sink (and the fn output target) is checked here and again on delivery.
	if err := s.authSink(ctx, s.d.DB, sub); err != nil {
		return nil, err
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		lvl := core.Level(ctx, tx, id.Root)
		cap := maxPerRoot
		if lvl == 0 {
			cap = maxPerRootL0
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM subs WHERE root = $1`, id.Root).Scan(&n); err != nil {
			return err
		}
		if n >= cap {
			return core.E(409, "quota", fmt.Sprintf("max %d subscriptions per root", cap))
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM subs WHERE topic = $1`, topic.Full).Scan(&n); err != nil {
			return err
		}
		if n >= maxPerTopic {
			return core.E(409, "quota", fmt.Sprintf("max %d subscriptions per topic", maxPerTopic))
		}
		// Start the cursor at the topic head so only future messages fire.
		var head int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT last_seq FROM topics WHERE name = $1), 0)`, topic.Full).Scan(&head); err != nil {
			return err
		}
		sub.LastSeq = head
		if _, err := tx.Exec(ctx, `INSERT INTO subs (id, root, topic, sink_kind, sink, to_kind, to_key, filter, mode, last_seq, hop_max, max_credits_day, until)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			sub.ID, sub.Root, sub.Topic, sub.SinkKind, sub.Sink, sub.ToKind, sub.ToKey, sub.Filter, sub.Mode, sub.LastSeq, sub.HopMax, sub.MaxCreditsDay, sub.Until); err != nil {
			return err
		}
		return core.Audit(ctx, tx, id.ID, "sub", sub.ID, 0)
	})
	if err != nil {
		return nil, err
	}
	return sub, nil
}

// svcRefOK validates a fn service reference: <name> or <name>@<ver>.
func svcRefOK(rest string) bool {
	name, verS, hasVer := strings.Cut(rest, "@")
	if !svcNameRe.MatchString(name) {
		return false
	}
	if hasVer {
		v, err := strconv.Atoi(verS)
		if err != nil || v <= 0 {
			return false
		}
	}
	return true
}

// fnVerified checks that a fn reference names a verified, stable catalog service. Returns the
// name@ver string to call.
func fnVerified(ctx context.Context, q core.Q, rest string) (string, error) {
	name, verS, hasVer := strings.Cut(rest, "@")
	var stable int
	if err := q.QueryRow(ctx, `SELECT stable_ver FROM services WHERE name = $1 AND NOT hidden`, name).Scan(&stable); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", core.E(403, "auth", "fn sink must be a verified stable service")
		}
		return "", err
	}
	ver := stable
	if hasVer {
		ver, _ = strconv.Atoi(verS)
	}
	if stable <= 0 {
		return "", core.E(403, "auth", "fn sink must be a verified stable service")
	}
	var state string
	if err := q.QueryRow(ctx, `SELECT state FROM service_versions WHERE name = $1 AND ver = $2`, name, ver).Scan(&state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", core.E(403, "auth", "fn sink version not found")
		}
		return "", err
	}
	if state != "verified" {
		return "", core.E(403, "auth", "fn sink must be a verified stable service")
	}
	return name + "@" + strconv.Itoa(ver), nil
}

// authSink rechecks that the subscriber root may write to the sink (and, for fn, to the output
// target). Called at creation and before every delivery.
func (s *Service) authSink(ctx context.Context, q core.Q, sub *Sub) error {
	id := &core.Ident{ID: sub.Root, Root: sub.Root}
	_, rest, err := parseSink(sub.Sink)
	if err != nil {
		return err
	}
	switch sub.SinkKind {
	case "wq":
		n, err := swarm.ParseName(rest, sub.Root)
		if err != nil {
			return err
		}
		return swarm.Access(ctx, q, id, n, true)
	case "mb":
		if rest != "me" {
			return core.Bad("mailbox sink must be mb:me")
		}
		return nil
	case "kv":
		ns, k, err := kvRef(rest)
		if err != nil {
			return err
		}
		return kvAuth(ctx, q, sub.Root, ns, k)
	case "fn":
		if _, err := fnVerified(ctx, q, rest); err != nil {
			return err
		}
		return s.authTo(ctx, q, sub)
	}
	return core.Bad("unknown sink kind")
}

// authTo rechecks that the subscriber may write a fn output to its `to` target.
func (s *Service) authTo(ctx context.Context, q core.Q, sub *Sub) error {
	id := &core.Ident{ID: sub.Root, Root: sub.Root}
	switch sub.ToKind {
	case "topic":
		n, err := swarm.ParseName(sub.ToKey, sub.Root)
		if err != nil {
			return err
		}
		return swarm.Access(ctx, q, id, n, true)
	case "mail":
		if sub.ToKey != "me" {
			return core.Bad("mail target must be mail:me")
		}
		return nil
	case "kv":
		ns, k, err := kvRef(sub.ToKey)
		if err != nil {
			return err
		}
		return kvAuth(ctx, q, sub.Root, ns, k)
	}
	return core.Bad("unknown to kind")
}

// kvAuth probes KV read access for root on <ns>/<k>: a missing key means access is allowed, a
// forbidden error means it is not.
func kvAuth(ctx context.Context, q core.Q, root, ns, k string) error {
	_, _, err := mem.KVGet(ctx, q, root, ns, k)
	if err == nil || errors.Is(err, core.ErrNotFound) {
		return nil
	}
	return err
}

// Get returns one sub owned by root.
func (s *Service) Get(ctx context.Context, root, id string) (*Sub, error) {
	sub, err := scanSub(s.d.DB.QueryRow(ctx, `SELECT `+subCols+` FROM subs WHERE id = $1 AND root = $2`, id, root))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	return sub, err
}

// List returns root's subs, newest first.
func (s *Service) List(ctx context.Context, root string) ([]*Sub, error) {
	rows, err := s.d.DB.Query(ctx, `SELECT `+subCols+` FROM subs WHERE root = $1 ORDER BY created DESC LIMIT $2`, root, listLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Sub
	for rows.Next() {
		sub, err := scanSub(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// Delete removes a sub owned by root (op unsub, DELETE /v1/sub/{id}).
func (s *Service) Delete(ctx context.Context, id *core.Ident, subID string) error {
	if id == nil {
		return core.ErrAuth
	}
	tag, err := s.d.DB.Exec(ctx, `DELETE FROM subs WHERE id = $1 AND root = $2`, subID, id.Root)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return nil
}

// Resume clears a paused sub's error count after the subscriber fixes the cause (POST /v1/sub/{id}/resume).
func (s *Service) Resume(ctx context.Context, id *core.Ident, subID string) (*Sub, error) {
	if id == nil {
		return nil, core.ErrAuth
	}
	if id.Banned {
		return nil, core.ErrBanned
	}
	sub, err := s.Get(ctx, id.Root, subID)
	if err != nil {
		return nil, err
	}
	// Refuse to resume while the sink is still unauthorised (re-check).
	if err := s.authSink(ctx, s.d.DB, sub); err != nil {
		return nil, err
	}
	if _, err := s.d.DB.Exec(ctx, `UPDATE subs SET paused = false, errors = 0 WHERE id = $1 AND root = $2`, subID, id.Root); err != nil {
		return nil, err
	}
	sub.Paused, sub.Errors = false, 0
	return sub, nil
}

// line renders a sub for the GET /v1/sub list.
func (sub *Sub) line() string {
	st := "live"
	if sub.Paused {
		st = "paused"
	}
	s := fmt.Sprintf("%s %s -> %s %s lag=? %s", sub.ID, doc.SafeLine(sub.Topic), doc.SafeLine(sub.Sink), sub.Mode, st)
	if sub.Filter != "" {
		s += " filter=" + doc.SafeLine(sub.Filter)
	}
	if sub.Errors > 0 {
		s += " errors=" + strconv.Itoa(sub.Errors)
	}
	return s
}

// purge deletes a root's subs before core removes its rows (OnPurge; the digest FK cascades).
func (s *Service) purge(ctx context.Context, root string) error {
	_, err := s.d.DB.Exec(ctx, `DELETE FROM subs WHERE root = $1`, root)
	return err
}
