package mail

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// deps is the Deps installed by Register: the notifier that wakes long-polls and the server
// secret that verifies cold postage. SendSys works without it (notices are never dropped).
var deps atomic.Pointer[core.Deps]

// Box is a resolved mailbox.
type Box struct {
	Name      string // box key: identity id, g<slug> or r<id>
	Kind      byte   // 'a' personal, 'g' group, 'r' room
	OwnerRoot string // root of a personal box's owner; "" for group and room boxes
	Mode      string
	Allow     []string
}

// Msg is one message to deliver. Enc marks an opaque sealed body (flag enc, never scanned); PoW
// is the cold postage header; IP feeds content_origin ("" writes no row: the sealed lane).
type Msg struct {
	Subject, Text, Re string
	Enc               bool
	PoW               string
	IP                string
	Flags             []string
}

// Result of a delivery. Phantom: the sender is blocked, nothing was stored (seq 0).
type Result struct {
	ID      string
	Seq     int64
	Masked  []string
	Phantom bool
	Cold    bool
}

var (
	errClosed     = core.E(403, "auth", "box closed")
	errAllow      = core.E(403, "auth", "not on the allow list")
	errPolicy     = core.E(403, "policy", "e2ee: the recipient accepts sealed mail only")
	errContext    = core.E(429, "quota", "context: the recipient takes mail from co-members, roots it replied to within 7 d, task peers and L2 roots")
	errPending    = core.E(429, "quota", "pending: one unread message per recipient until it is read")
	errRecipient  = core.E(429, "quota", "recipient: 10 per day to one box until it replies")
	errInboxFull  = core.E(429, "quota", "inbox full")
	errBurst      = core.E(429, "quota", "burst: too many distinct recipients in 10 min")
	errAge        = core.E(429, "quota", "root younger than 1 h")
	errGroupShut  = core.E(403, "auth", "group boxes are closed")
	errNotMember  = core.E(403, "auth", "not a member of this group")
	errNoBox      = core.E(404, "notfound", "no such box")
	errBadTo      = core.Bad("to must be an identity id (a…), g<slug>, r<id> or me")
	errNoDeps     = core.E(400, "pow", "cold postage unavailable")
	errPersonalOp = core.Bad("only personal boxes have settings")
)

// Resolve maps a `to` (identity id, me, g<slug>, r<id>) to its box, checking group and room
// membership for from (nil = the system sender, personal boxes only). Unknown identities, rooms
// and closed rooms answer the same 404.
func Resolve(ctx context.Context, q core.Q, from *core.Ident, to string) (*Box, error) {
	if to == "me" {
		if from == nil {
			return nil, errBadTo
		}
		to = from.ID
	}
	var b *Box
	switch {
	case core.ValidIDPrefix(to, 'a'):
		var root string
		var revoked *time.Time
		err := q.QueryRow(ctx, `SELECT root, revoked_at FROM identities WHERE id = $1`, to).Scan(&root, &revoked)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && revoked != nil) {
			return nil, errNoBox
		}
		if err != nil {
			return nil, err
		}
		b = &Box{Name: to, Kind: 'a', OwnerRoot: root}
	case len(to) > 1 && to[0] == 'g' && slugRe.MatchString(to[1:]):
		if from == nil {
			return nil, errBadTo
		}
		if MemberFn == nil {
			return nil, errGroupShut
		}
		ok, err := MemberFn(ctx, q, to[1:], from.Root)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errNotMember
		}
		b = &Box{Name: to, Kind: 'g'}
	case len(to) == 8 && to[0] == 'r' && core.ValidIDPrefix(to[1:], 'o'):
		if from == nil || RoomFn == nil {
			return nil, errNoBox
		}
		ok, err := RoomFn(ctx, q, to[1:], from.Root)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errNoBox
		}
		b = &Box{Name: to, Kind: 'r'}
	default:
		return nil, errBadTo
	}
	b.Mode = "context"
	if b.Kind != 'a' {
		b.Mode = "members"
	}
	err := q.QueryRow(ctx, `SELECT mode, allow FROM mb_boxes WHERE box = $1`, b.Name).Scan(&b.Mode, &b.Allow)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return b, nil
}

// Send is the exported plaintext send with the normal gates (a2ahost, webhook): to is resolved,
// the text goes through normalise -> scrub -> lexicon, then Deliver. Call it inside a transaction
// so a refused send charges nothing.
func Send(ctx context.Context, q core.Q, from *core.Ident, to, subject, re, text string) (id string, seq int64, err error) {
	if from == nil {
		return "", 0, core.ErrAuth
	}
	b, err := Resolve(ctx, q, from, to)
	if err != nil {
		return "", 0, err
	}
	m := &Msg{Subject: subject, Text: text, Re: re}
	if _, err := prepare(ctx, q, m); err != nil {
		return "", 0, err
	}
	res, err := Deliver(ctx, q, from, b, m)
	if err != nil {
		return "", 0, err
	}
	return res.ID, res.Seq, nil
}

// SendSys delivers a system notice from the reserved sender `sys` to a root (or any identity id):
// no gates, never dropped, no origin row. core.SysMailFn points here once wired.
func SendSys(ctx context.Context, q core.Q, toRoot, subject, text string) error {
	if !core.ValidIDPrefix(toRoot, 'a') {
		return core.Bad("recipient must be an identity id")
	}
	b, err := Resolve(ctx, q, nil, toRoot)
	if err != nil {
		return err
	}
	m := &Msg{Subject: cutRunes(doc.SafeLine(scrub.Normalize(subject)), MaxSubject), Text: scrub.Normalize(doc.CleanMulti(text))}
	if len(m.Text) > MaxText {
		m.Text = strings.ToValidUTF8(m.Text[:MaxText], "")
	}
	if strings.TrimSpace(m.Text) == "" {
		m.Text = m.Subject
	}
	_, err = Deliver(ctx, q, nil, b, m)
	return err
}

// prepare runs the write pipeline on m in place: normalise, size and shape checks, the sealed
// shortcut (opaque bodies are flagged enc and never scanned), tier-1 reject with the leak link,
// tier-2 mask, lexicon flags. Returns the kinds masked.
func prepare(ctx context.Context, q core.Q, m *Msg) ([]string, error) {
	m.Subject = scrub.Normalize(strings.TrimSpace(m.Subject))
	m.Text = strings.TrimRight(doc.CleanMulti(scrub.Normalize(m.Text)), "\n")
	m.Re = strings.TrimSpace(m.Re)
	switch {
	case strings.TrimSpace(m.Text) == "":
		return nil, core.Bad("text required")
	case len(m.Text) > MaxText:
		return nil, core.ErrSize
	case !doc.OneLine(m.Subject):
		return nil, core.Bad("subject must be one line")
	case utf8.RuneCountInString(m.Subject) > MaxSubject:
		return nil, core.Bad(fmt.Sprintf("subject must be <= %d chars", MaxSubject))
	case m.Re != "" && !reRe.MatchString(m.Re):
		return nil, core.Bad("re must match [A-Za-z0-9._:/-]{1,64}")
	}
	fields := map[string]*string{"subject": &m.Subject}
	if sealedRe.MatchString(strings.TrimSpace(m.Text)) {
		m.Enc = true
		m.Text = strings.TrimSpace(m.Text)
	} else {
		fields["text"] = &m.Text
		// Leak link (3.4): the caller's own live token is rotated, another identity's revoked.
		if tok := tokenRe.FindString(m.Subject + "\n" + m.Text); tok != "" {
			if action, err := core.LeakedToken(ctx, q, tok); err == nil && action != "" {
				return nil, core.E(400, "scrub", "token ("+doc.SafeLine(action)+")")
			}
		}
	}
	masked, aerr := scrub.RejectOrMask(fields)
	if aerr != nil {
		return nil, aerr
	}
	if m.Enc {
		m.Flags = append(m.Flags, "enc")
		return masked, nil
	}
	if _, flags, _ := scrub.Flags(m.Subject + "\n" + m.Text); len(flags) > 0 {
		m.Flags = append(m.Flags, flags...)
	}
	return masked, nil
}

type pair struct {
	FirstAt, LastAt time.Time
	LastReply       *time.Time
	Sent, Replies   int
	Reads           int
}

func (p pair) unlocked() bool {
	return p.LastReply != nil && time.Since(*p.LastReply) < ReplyWindow
}

func pairGet(ctx context.Context, q core.Q, from, to string) (pair, error) {
	var p pair
	err := q.QueryRow(ctx, `SELECT first_at, last_at, last_reply, sent, replies, reads FROM mb_pairs WHERE from_root = $1 AND to_root = $2`, from, to).
		Scan(&p.FirstAt, &p.LastAt, &p.LastReply, &p.Sent, &p.Replies, &p.Reads)
	if errors.Is(err, pgx.ErrNoRows) {
		return pair{}, nil
	}
	return p, err
}

// hasContext is the context-mode rule (11): L2 sender, a reply from the recipient within 7 d, a
// shared space (CoMemberFn) or a shared task thread (creator / claim holder).
func hasContext(ctx context.Context, q core.Q, fromRoot string, lvl int, p pair, owner string) (bool, error) {
	if lvl >= 2 || p.unlocked() {
		return true, nil
	}
	if CoMemberFn != nil {
		ok, err := CoMemberFn(ctx, q, fromRoot, owner)
		if err != nil || ok {
			return ok, err
		}
	}
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tasks t JOIN task_claims c ON c.n = t.n
		WHERE (t.root = $1 AND c.root = $2) OR (t.root = $2 AND c.root = $1))`, fromRoot, owner).Scan(&ok)
	return ok, err
}

func bump(ctx context.Context, q core.Q, scope, kind string, delta int) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, scope, kind, delta).Scan(&n)
	return n, err
}

// Deliver applies the sender gates and stores m in b. from == nil is the system sender (no
// gates, never dropped); a send inside the sender's own tree skips the gates too.
func Deliver(ctx context.Context, q core.Q, from *core.Ident, b *Box, m *Msg) (*Result, error) {
	sys := from == nil
	self := !sys && b.Kind == 'a' && b.OwnerRoot == from.Root
	lvl := 0
	if !sys && !self {
		st, err := trust.Load(ctx, q, from.Root)
		if err != nil {
			return nil, err
		}
		lvl = st.Level()
		res, err := gates(ctx, q, from, st, b, m)
		if err != nil || res != nil {
			return res, err
		}
	}
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "mb:"+b.Name); err != nil {
		return nil, err
	}
	if b.Kind == 'a' && !self {
		if err := evict(ctx, q, b, lvl, sys); err != nil {
			return nil, err
		}
	}
	var seq int64
	if err := q.QueryRow(ctx, `INSERT INTO mb_boxes (box, owner_root, next_seq) VALUES ($1, $2, 2)
		ON CONFLICT (box) DO UPDATE SET next_seq = mb_boxes.next_seq + 1, updated = now() RETURNING next_seq - 1`, b.Name, b.OwnerRoot).Scan(&seq); err != nil {
		return nil, err
	}
	fromID, fromRoot := SysID, core.SystemID
	if !sys {
		fromID, fromRoot = from.ID, from.Root
	}
	id := core.NewID('m')
	flags := m.Flags
	if flags == nil {
		flags = []string{}
	}
	if _, err := q.Exec(ctx, `INSERT INTO mail (id, box, seq, from_id, from_root, re, subject, text, size, expires, flags, scrub_v)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + $10::interval, $11, $12)`,
		id, b.Name, seq, fromID, fromRoot, m.Re, m.Subject, m.Text, len(m.Text), TTL.String(), flags, scrub.RulesV); err != nil {
		return nil, err
	}
	if !sys && !self {
		if b.Kind == 'a' {
			if _, err := q.Exec(ctx, `INSERT INTO mb_pairs (from_root, to_root, sent) VALUES ($1, $2, 1)
				ON CONFLICT (from_root, to_root) DO UPDATE SET sent = mb_pairs.sent + 1, last_at = now()`, from.Root, b.OwnerRoot); err != nil {
				return nil, err
			}
			// The reverse pair: the recipient hearing from this sender unlocks its own sends to
			// it for 7 d, whether or not it had written first.
			if _, err := q.Exec(ctx, `INSERT INTO mb_pairs (from_root, to_root, sent, replies, last_reply) VALUES ($1, $2, 0, 1, now())
				ON CONFLICT (from_root, to_root) DO UPDATE SET replies = mb_pairs.replies + 1, last_reply = now()`, b.OwnerRoot, from.Root); err != nil {
				return nil, err
			}
		}
		if _, err := q.Exec(ctx, `INSERT INTO mb_sent (from_root, box) VALUES ($1, $2)`, from.Root, b.Name); err != nil {
			return nil, err
		}
	}
	if !sys && m.IP != "" {
		if err := core.Origin(ctx, q, "m", id, from.Root, from.ID, m.IP); err != nil {
			return nil, err
		}
	}
	if b.Kind == 'a' {
		if err := core.Event(ctx, q, "mail", id, b.OwnerRoot, "mail "+id+" from "+fromID); err != nil {
			return nil, err
		}
	}
	if !sys {
		if err := core.Audit(ctx, q, from.ID, "mb", id, len(m.Text)); err != nil {
			return nil, err
		}
	}
	wake(b)
	return &Result{ID: id, Seq: seq, Cold: hasFlag(flags, "cold")}, nil
}

// gates runs every sender gate of 11 and 27.8 in refusal order; a non-nil Result is the phantom
// reply of a blocked sender.
func gates(ctx context.Context, q core.Q, from *core.Ident, st trust.Standing, b *Box, m *Msg) (*Result, error) {
	lvl := st.Level()
	var until *time.Time
	err := q.QueryRow(ctx, `SELECT until FROM mb_mutes WHERE root = $1 AND until > now()`, from.Root).Scan(&until)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if until != nil {
		return nil, core.E(429, "quota", "muted until "+core.Date(*until))
	}
	if b.Kind == 'a' {
		var blocked bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mb_blocks WHERE owner_root = $1 AND from_root = $2)`, b.OwnerRoot, from.Root).Scan(&blocked); err != nil {
			return nil, err
		}
		if blocked {
			return &Result{ID: core.NewID('m'), Phantom: true}, nil
		}
		if !m.Enc && PolicyFn != nil {
			plain, err := PolicyFn(ctx, q, b.OwnerRoot)
			if err != nil {
				return nil, err
			}
			if !plain {
				return nil, errPolicy
			}
		}
	}
	if b.Mode == "require_enc" && !m.Enc {
		return nil, errPolicy
	}
	var p pair
	ctxOK := true
	if b.Kind == 'a' {
		if p, err = pairGet(ctx, q, from.Root, b.OwnerRoot); err != nil {
			return nil, err
		}
		if ctxOK, err = hasContext(ctx, q, from.Root, lvl, p, b.OwnerRoot); err != nil {
			return nil, err
		}
		switch b.Mode {
		case "open", "require_enc":
		case "closed":
			return nil, errClosed
		case "allow":
			if !contains(b.Allow, from.ID) && !contains(b.Allow, from.Root) {
				return nil, errAllow
			}
		default:
			if !ctxOK {
				return nil, errContext
			}
		}
	}
	if !st.Seed && st.Age < MinRootAge {
		return nil, errAge
	}
	var pending bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mail WHERE box = $1 AND from_root = $2 AND read_at IS NULL AND delivered AND NOT hidden AND expires > now())`,
		b.Name, from.Root).Scan(&pending); err != nil {
		return nil, err
	}
	if pending {
		return nil, errPending
	}
	if b.Kind == 'a' {
		n, err := bump(ctx, q, from.Root, "mail:"+b.Name, 1)
		if err != nil {
			return nil, err
		}
		if n > PerRecipient && !p.unlocked() {
			return nil, errRecipient
		}
	}
	if err := trust.UseCap(ctx, q, st, "mail"); err != nil {
		return nil, err
	}
	if err := burst(ctx, q, from.Root, b.Name); err != nil {
		return nil, err
	}
	if b.Kind == 'a' && p.Replies == 0 && !ctxOK {
		if err := cold(ctx, q, from.Root, st, b.OwnerRoot, m); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// burst refuses more than BurstBoxes distinct boxes in BurstWindow (27.8); the mb_sent row that
// counts this send is written by Deliver after the gates.
func burst(ctx context.Context, q core.Q, root, box string) error {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(DISTINCT box) FROM mb_sent WHERE from_root = $1 AND box <> $2 AND at > now() - $3::interval`,
		root, box, BurstWindow.String()).Scan(&n); err != nil {
		return err
	}
	if n+1 > BurstBoxes {
		return errBurst
	}
	return nil
}

// cold is the cold-contact postage (27.8): a frozen sender cannot start cold pairs; beyond the
// daily budget of distinct cold recipients the send needs X-PoW (purpose mb) at ColdBits.
func cold(ctx context.Context, q core.Q, root string, st trust.Standing, to string, m *Msg) error {
	var frozen *time.Time
	if err := q.QueryRow(ctx, `SELECT mail_cold_frozen_until FROM identities WHERE id = $1`, root).Scan(&frozen); err != nil {
		return err
	}
	if frozen != nil && frozen.After(time.Now()) {
		return core.E(429, "quota", "cold-frozen until "+core.Date(*frozen))
	}
	if _, err := q.Exec(ctx, `INSERT INTO mb_cold (from_root, to_root, day) VALUES ($1, $2, current_date) ON CONFLICT DO NOTHING`, root, to); err != nil {
		return err
	}
	bits, today, budget, err := ColdBits(ctx, q, root, st.CapLevel(), 0)
	if err != nil {
		return err
	}
	m.Flags = append(m.Flags, "cold")
	if today <= budget {
		return nil
	}
	if m.PoW == "" {
		return core.E(400, "pow", fmt.Sprintf("cold postage needed: bits=%d cold=%d/%d (POST /v1/mb/challenge, then X-PoW)", bits, today, budget))
	}
	return verifyPostage(ctx, q, m.PoW, bits)
}

// ColdBits is the cold postage of a root: POW_BITS_W + 2*ceil(cold_today/budget) +
// 4*[unanswered_7d > 0.8], capped at MaxColdBits, with today's distinct cold recipients (plus
// `pending` sends being prepared: the challenge endpoint passes 1) and the level's budget (27.8).
// A budget of 0 makes every cold send pay the cap.
func ColdBits(ctx context.Context, q core.Q, root string, capLevel, pending int) (bits, today, budget int, err error) {
	budget = trust.Cap("mail_cold", capLevel)
	if err = q.QueryRow(ctx, `SELECT count(*) FROM mb_cold WHERE from_root = $1 AND day = current_date`, root).Scan(&today); err != nil {
		return
	}
	today += pending
	var total, unanswered int
	if err = q.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE c.day <= current_date - 2 AND p.reads = 0 AND p.replies = 0)
		FROM mb_cold c LEFT JOIN mb_pairs p ON p.from_root = c.from_root AND p.to_root = c.to_root
		WHERE c.from_root = $1 AND c.day > current_date - 7`, root).Scan(&total, &unanswered); err != nil {
		return
	}
	bits = baseBits()
	if budget <= 0 {
		bits = MaxColdBits
	} else {
		bits += 2 * int(math.Ceil(float64(today)/float64(budget)))
	}
	if total > 0 && float64(unanswered)/float64(total) > 0.8 {
		bits += 4
	}
	return min(bits, MaxColdBits), today, budget, nil
}

func baseBits() int {
	if d := deps.Load(); d != nil && d.Cfg.PowBitsW > 0 {
		return d.Cfg.PowBitsW
	}
	return core.DefaultPowBitsW
}

// Challenge mints a cold postage challenge at bits (purpose mb, 10 min).
func Challenge(bits int) (c string, exp time.Time, err error) {
	d := deps.Load()
	if d == nil {
		return "", time.Time{}, errNoDeps
	}
	exp = time.Now().Add(10 * time.Minute).Truncate(time.Second)
	return pow.New(d.Cfg.ServerSecret, exp, bits, PurposeMail), exp, nil
}

// verifyPostage checks an X-PoW value against a mail challenge of at least `bits` and consumes it.
func verifyPostage(ctx context.Context, q core.Q, h string, bits int) error {
	d := deps.Load()
	if d == nil {
		return errNoDeps
	}
	c, nonce, ok := strings.Cut(strings.TrimSpace(h), ":")
	if !ok || len(c) > 64 || nonce == "" || len(nonce) > 40 {
		return core.E(400, "pow", "X-PoW must be <challenge>:<nonce>")
	}
	info, err := pow.VerifyV2(d.Cfg.ServerSecret, c, time.Now())
	if err != nil {
		return core.E(400, "pow", err.Error())
	}
	if info.Purpose != PurposeMail {
		return core.E(400, "pow", "challenge purpose is not mb (POST /v1/mb/challenge)")
	}
	if info.Bits < bits {
		return core.E(400, "pow", fmt.Sprintf("challenge too weak: need bits=%d (POST /v1/mb/challenge)", bits))
	}
	if !pow.Check(c, nonce, info.Bits) {
		return core.ErrPow
	}
	if _, err := q.Exec(ctx, `INSERT INTO used_challenges (c, exp) VALUES ($1, $2)`, c, info.Exp); err != nil {
		if core.IsUniqueViolation(err) {
			return core.E(400, "pow", "challenge already used")
		}
		return err
	}
	return nil
}

// evict keeps a personal box at InboxCap unread messages: the oldest unread message of the
// lowest-standing sender goes first, only when that sender ranks strictly below the new one (the
// system sender drops the lowest whatever its level and is never refused). Own-tree and sys rows
// are never evicted.
func evict(ctx context.Context, q core.Q, b *Box, senderLvl int, force bool) error {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM mail WHERE box = $1 AND read_at IS NULL AND delivered AND NOT hidden AND expires > now()`, b.Name).Scan(&n); err != nil {
		return err
	}
	if n < InboxCap {
		return nil
	}
	rows, err := q.Query(ctx, `SELECT id, from_root FROM mail WHERE box = $1 AND read_at IS NULL AND delivered AND NOT hidden AND expires > now()
		AND from_root <> $2 AND from_root <> $3 ORDER BY created, id`, b.Name, b.OwnerRoot, core.SystemID)
	if err != nil {
		return err
	}
	type cand struct{ id, root string }
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.id, &c.root); err != nil {
			rows.Close()
			return err
		}
		cands = append(cands, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	levels := map[string]int{}
	victim, vLvl := "", 4
	for _, c := range cands {
		l, ok := levels[c.root]
		if !ok {
			l = trust.LevelOf(ctx, q, c.root)
			levels[c.root] = l
		}
		if l < vLvl {
			victim, vLvl = c.id, l
		}
	}
	if victim == "" || (!force && vLvl >= senderLvl) {
		if force {
			return nil
		}
		return errInboxFull
	}
	_, err = q.Exec(ctx, `DELETE FROM mail WHERE id = $1`, victim)
	return err
}

// wake releases the long-polls of a box and, for a subkey's box, of its root's tree pulls.
func wake(b *Box) {
	d := deps.Load()
	if d == nil {
		return
	}
	d.Notify.Wake("mb:" + b.Name)
	if b.Kind == 'a' && b.OwnerRoot != "" && b.OwnerRoot != b.Name {
		d.Notify.Wake("mb:" + b.OwnerRoot)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func hasFlag(fs []string, f string) bool { return contains(fs, f) }

func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return strings.TrimSpace(string([]rune(s)[:n]))
}
