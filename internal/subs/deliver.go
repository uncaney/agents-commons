package subs

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/mem"
	"ekaii.fr/commons/internal/swarm"
)

// deliverAll is the janitor pass (and the ps:* wake handler): it runs one delivery pass per live
// sub. It is registered under a per-task advisory lock so only one gateway instance runs it.
func (s *Service) deliverAll(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT id FROM subs WHERE NOT paused AND (until IS NULL OR until > now()) ORDER BY created`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if err := s.deliverSub(ctx, id); err != nil && ctx.Err() == nil {
			s.d.Log.Warn("subs delivery", "sub", id, "err", err)
		}
	}
	return nil
}

// deliverSub runs one delivery pass for a sub under an advisory lock on the sub id, so concurrent
// passes never double-fire the same message.
func (s *Service) deliverSub(ctx context.Context, id string) error {
	var locked bool
	if err := s.d.DB.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext($1))`, "sub:"+id).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return nil
	}
	defer s.d.DB.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext($1))`, "sub:"+id)

	sub, err := scanSub(s.d.DB.QueryRow(ctx, `SELECT `+subCols+` FROM subs WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	if sub.Paused || (sub.Until != nil && sub.Until.Before(time.Now())) {
		return nil
	}
	msgs, err := swarm.Pull(ctx, s.d.DB, sub.Topic, sub.LastSeq, pullBatch)
	if err != nil {
		return err
	}
	for _, m := range msgs {
		stop, err := s.one(ctx, sub, m)
		if err != nil {
			return err
		}
		if stop {
			break
		}
	}
	// Flush a due digest even when no new message arrived this pass.
	return s.flushDigest(ctx, sub)
}

// one handles a single topic message for a sub. It returns stop=true when the pass must halt
// (a refusal, a shed cap, or a paused state) without advancing past this message.
func (s *Service) one(ctx context.Context, sub *Sub, m swarm.Msg) (stop bool, err error) {
	// Skip (advance cursor) for messages that never fire: hidden, sub-published (via=sub, never
	// re-matched), over the hop ceiling, or filtered out.
	if m.Hidden || slices.Contains(m.Flags, "via=sub") || hopOf(m.Text) >= sub.HopMax || !s.matches(sub.Filter, m.Text) {
		return false, s.advance(ctx, sub, m.Seq)
	}
	// Firing caps: 200/day/root and 2000/h globally are shed (the message retries next window).
	day, err := readCounter(ctx, s.d.DB, sub.Root, "sub_fire")
	if err != nil {
		return true, err
	}
	if day >= firePerDayRoot {
		return true, nil
	}
	hr, err := readCounter(ctx, s.d.DB, "sub:global", hourKind())
	if err != nil {
		return true, err
	}
	if hr >= firePerHourAll {
		return true, nil
	}
	// Re-check sink authorisation on every delivery.
	if err := s.authSink(ctx, s.d.DB, sub); err != nil {
		return true, s.refuse(ctx, sub, "sink unauthorised: "+msgOf(err))
	}
	switch sub.SinkKind {
	case "fn":
		return s.fireFn(ctx, sub, m)
	default:
		return s.fireCopy(ctx, sub, m)
	}
}

// fireCopy delivers a message to a wq, mb (each or digest) or kv sink in one transaction that also
// advances the cursor, so delivery is exactly-once.
func (s *Service) fireCopy(ctx context.Context, sub *Sub, m swarm.Msg) (bool, error) {
	_, rest, _ := parseSink(sub.Sink)
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := s.advanceTx(ctx, tx, sub, m.Seq); err != nil {
			return err
		}
		switch sub.SinkKind {
		case "wq":
			body := fmt.Sprintf("%s %d %s\n%s", sub.Topic, m.Seq, byOf(m), m.Text)
			_, err := swarm.Push(ctx, tx, rest, body, fmt.Sprintf("sub:%s:%d", sub.ID, m.Seq))
			return err
		case "mb":
			if sub.Mode == "digest" {
				_, err := tx.Exec(ctx, `INSERT INTO sub_digest (sub, seq, line) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
					sub.ID, m.Seq, digestLine(sub.Topic, m))
				return err
			}
			return s.mailOne(ctx, tx, sub.Root, fmt.Sprintf("ps:%s/%d", sub.Topic, m.Seq), m.Text)
		case "kv":
			ns, k, _ := kvRef(rest)
			v := m.Text
			if len(v) > fnOutKVMax {
				v = v[:fnOutKVMax]
			}
			_, err := mem.KVPut(ctx, tx, sub.Root, ns, k, []byte(v), 0)
			return err
		}
		return nil
	})
	if err != nil {
		if credErr(err) {
			return true, s.pause(ctx, sub, "out of credits")
		}
		return true, s.refuse(ctx, sub, msgOf(err))
	}
	sub.LastSeq = m.Seq
	return false, s.ok(ctx, sub)
}

// fireFn runs the message through the fn service and writes the output back to the sub's target.
func (s *Service) fireFn(ctx context.Context, sub *Sub, m swarm.Msg) (bool, error) {
	spent, err := readCounter(ctx, s.d.DB, sub.Root, "sub_cred_"+sub.ID)
	if err != nil {
		return true, err
	}
	if spent >= sub.MaxCreditsDay { // daily credit budget exhausted: shed until tomorrow
		return true, nil
	}
	_, rest, _ := parseSink(sub.Sink)
	nameAtVer, err := fnVerified(ctx, s.d.DB, rest)
	if err != nil {
		return true, s.refuse(ctx, sub, "fn unavailable: "+msgOf(err))
	}
	id, err := loadIdent(ctx, s.d.DB, sub.Root)
	if err != nil {
		return true, s.refuse(ctx, sub, "subscriber gone")
	}
	status, out, err := callService(ctx, s.d, id, nameAtVer, m.Text, fnWait)
	if err != nil {
		if credErr(err) {
			return true, s.pause(ctx, sub, "out of credits")
		}
		return true, s.refuse(ctx, sub, "fn error: "+msgOf(err))
	}
	if _, cerr := bumpCounter(ctx, s.d.DB, sub.Root, "sub_cred_"+sub.ID); cerr != nil {
		return true, cerr
	}
	if status != "done" {
		return true, s.refuse(ctx, sub, "fn "+status)
	}
	hop := hopOf(m.Text) + 1
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := s.advanceTx(ctx, tx, sub, m.Seq); err != nil {
			return err
		}
		return s.writeOut(ctx, tx, sub, m.Seq, hop, out)
	})
	if err != nil {
		if credErr(err) {
			return true, s.pause(ctx, sub, "out of credits")
		}
		return true, s.refuse(ctx, sub, msgOf(err))
	}
	sub.LastSeq = m.Seq
	return false, s.ok(ctx, sub)
}

// writeOut writes a fn output to the sub's `to` target as the subscriber, carrying hop=<n+1> so a
// further sub that matches it sees the incremented counter.
func (s *Service) writeOut(ctx context.Context, tx pgx.Tx, sub *Sub, seq int64, hop int, out string) error {
	switch sub.ToKind {
	case "topic":
		body := withHop(hop, out)
		if len(body) > fnOutTopicMax {
			body = body[:fnOutTopicMax]
		}
		n, err := swarm.ParseName(sub.ToKey, sub.Root)
		if err != nil {
			return err
		}
		// Key prefix sub: makes swarm flag the message via=sub (never re-matched).
		_, _, err = swarm.PublishFlags(ctx, tx, n.Full, sub.Root, sub.Root, body, fmt.Sprintf("sub:%s:%d", sub.ID, seq), nil)
		return err
	case "mail":
		body := withHop(hop, out)
		return s.mailOne(ctx, tx, sub.Root, fmt.Sprintf("ps:%s/%d", sub.Topic, seq), body)
	case "kv":
		ns, k, _ := kvRef(sub.ToKey)
		body := withHop(hop, out)
		if len(body) > fnOutKVMax {
			body = body[:fnOutKVMax]
		}
		_, err := mem.KVPut(ctx, tx, sub.Root, ns, k, []byte(body), 0)
		return err
	}
	return nil
}

// mailOne delivers one sys mail to a root with a reference line, replicating SendSys but keeping Re.
func (s *Service) mailOne(ctx context.Context, q core.Q, root, re, text string) error {
	b, err := mail.Resolve(ctx, q, nil, root)
	if err != nil {
		return err
	}
	subject := re
	if len(subject) > 80 {
		subject = subject[:80]
	}
	_, err = mail.Deliver(ctx, q, nil, b, &mail.Msg{Subject: subject, Re: re, Text: text})
	return err
}

// flushDigest sends one mail for a digest-mode sub when its window has elapsed and lines are buffered.
func (s *Service) flushDigest(ctx context.Context, sub *Sub) error {
	if sub.SinkKind != "mb" || sub.Mode != "digest" {
		return nil
	}
	if sub.DigestAt != nil && time.Since(*sub.DigestAt) < digestEvery {
		return nil
	}
	rows, err := s.d.DB.Query(ctx, `SELECT seq, line FROM sub_digest WHERE sub = $1 ORDER BY seq LIMIT $2`, sub.ID, digestMaxLines)
	if err != nil {
		return err
	}
	var seqs []int64
	var lines []string
	for rows.Next() {
		var seq int64
		var line string
		if err := rows.Scan(&seq, &line); err != nil {
			rows.Close()
			return err
		}
		seqs = append(seqs, seq)
		lines = append(lines, line)
	}
	rows.Close()
	if len(lines) == 0 {
		return nil
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := s.mailOne(ctx, tx, sub.Root, "ps:"+sub.Topic+"/digest", strings.Join(lines, "\n")); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM sub_digest WHERE sub = $1 AND seq = ANY($2)`, sub.ID, seqs); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE subs SET digest_at = now() WHERE id = $1`, sub.ID)
		return err
	})
	if err == nil {
		now := time.Now()
		sub.DigestAt = &now
	}
	return err
}

// advance moves the cursor past a skipped message (its own statement).
func (s *Service) advance(ctx context.Context, sub *Sub, seq int64) error {
	if _, err := s.d.DB.Exec(ctx, `UPDATE subs SET last_seq = $2 WHERE id = $1 AND last_seq < $2`, sub.ID, seq); err != nil {
		return err
	}
	sub.LastSeq = seq
	return nil
}

// advanceTx moves the cursor inside a delivery transaction, guarded so a message is counted once.
func (s *Service) advanceTx(ctx context.Context, tx pgx.Tx, sub *Sub, seq int64) error {
	tag, err := tx.Exec(ctx, `UPDATE subs SET last_seq = $2 WHERE id = $1 AND last_seq = $3`, sub.ID, seq, sub.LastSeq)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errSeqRaced
	}
	return nil
}

var errSeqRaced = errors.New("cursor advanced concurrently")

// ok resets the error count and charges the firing caps after a successful delivery.
func (s *Service) ok(ctx context.Context, sub *Sub) error {
	if sub.Errors != 0 {
		if _, err := s.d.DB.Exec(ctx, `UPDATE subs SET errors = 0 WHERE id = $1`, sub.ID); err != nil {
			return err
		}
		sub.Errors = 0
	}
	if _, err := bumpCounter(ctx, s.d.DB, sub.Root, "sub_fire"); err != nil {
		return err
	}
	_, err := bumpCounter(ctx, s.d.DB, "sub:global", hourKind())
	return err
}

// refuse records a delivery refusal: errors+1, and at pauseAfterErr consecutive refusals the sub is
// paused with a sys mail. A credits failure pauses immediately through pause().
func (s *Service) refuse(ctx context.Context, sub *Sub, reason string) error {
	var n int
	if err := s.d.DB.QueryRow(ctx, `UPDATE subs SET errors = errors + 1 WHERE id = $1 RETURNING errors`, sub.ID).Scan(&n); err != nil {
		return err
	}
	sub.Errors = n
	if n >= pauseAfterErr {
		return s.pause(ctx, sub, reason)
	}
	return nil
}

// pause pauses a sub and mails the subscriber why.
func (s *Service) pause(ctx context.Context, sub *Sub, reason string) error {
	if _, err := s.d.DB.Exec(ctx, `UPDATE subs SET paused = true WHERE id = $1`, sub.ID); err != nil {
		return err
	}
	sub.Paused = true
	_ = mail.SendSys(ctx, s.d.DB, sub.Root, "subscription "+sub.ID+" paused",
		doc.CleanMulti(fmt.Sprintf("subscription %s on %s paused: %s\nresume with POST /v1/sub/%s/resume", sub.ID, sub.Topic, reason, sub.ID)))
	return nil
}

func byOf(m swarm.Msg) string {
	if m.By == "" {
		return "-"
	}
	return m.By
}

func digestLine(topic string, m swarm.Msg) string {
	head := m.Text
	if i := strings.IndexByte(head, '\n'); i >= 0 {
		head = head[:i]
	}
	return doc.SafeLine(fmt.Sprintf("%d %s %s", m.Seq, byOf(m), head))
}

func credErr(err error) bool {
	return errors.Is(err, core.ErrCredits) || errors.Is(err, core.ErrEarned)
}

// msgOf renders an error for a sys-mail reason line (the APIError message, else the error text).
func msgOf(err error) string {
	var ae *core.APIError
	if errors.As(err, &ae) {
		return ae.Msg
	}
	return err.Error()
}
