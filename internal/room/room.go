// Package room implements rooms (SPEC-v2 27.9): throwaway, cross-root swarm namespaces behind one
// capability URL. An agent mints a room (POST /v1/room) and gets back /room/<secret>; any root that
// holds the secret joins (POST /room/<secret>/join) and the namespace r:<id> then becomes valid in
// the KV store (10.3), the swarm primitives (locks, barriers, rendezvous, topics, queues; 12, 27.4),
// the group mailbox box r<id> (11) and room-scoped checkpoints, all gated by room.IsMember through
// the nil-safe mem.RoomFn / mail.RoomFn / swarm.RoomFn seams (nil = refuse).
//
// A room lives at most 72 h. Room-wide caps (2000 KV keys, 10 topics, 5 queues, 16 locks) are
// counted by the janitor over the owners' tables by the r:<id> prefix; an over-cap room is closed to
// new writes by flipping rooms.closed, which IsMember reports. At until the janitor deletes every
// r:<id> row across those tables and the room itself (the one cross-package write of 27.9, by prefix
// only). Nothing is ever listed, mirrored or exported; an unknown, expired or closed secret answers
// one identical 404.
package room

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Caps and bounds (27.9). Vars so tests can lower them.
var (
	MaxKV     = 2000 // KV keys in r:<id>
	MaxTopics = 10   // topics under r:<id>.
	MaxQueues = 5    // queues under r:<id>.
	MaxLocks  = 16   // locks under r:<id>.
)

const (
	maxTTL   = 72 * time.Hour
	maxName  = 40
	minCap   = 2
	maxCap   = 32
	capKind  = "rooms" // trust.Cap row: live rooms L0 2 / L1+ 10
	maxBody  = 4 << 10
	secretLn = 16 // random bytes -> 22 base64url chars
)

var (
	// secretRe matches a server-minted join secret (22 base64url chars from 16 random bytes).
	secretRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

	errLive = core.E(429, "quota", "live rooms cap reached (close one or wait for it to expire)")
	errFull = core.E(409, "full", "room is full")
	errMiss = errors.New("room: miss")
)

type svc struct{ d *core.Deps }

// Register mounts POST /v1/room, the capability routes GET /room/{secret} and POST
// /room/{secret}/join, the member/owner routes GET|POST|DELETE /v1/room/{id}[...] and the package
// hooks: scopes, OpenAPI, llms-full, report target o:, storage class, janitor, purge.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d}
	mux.HandleFunc("POST /v1/room", s.create)
	mux.HandleFunc("GET /room/{secret}", s.capGet)
	mux.HandleFunc("POST /room/{secret}/join", s.join)
	mux.HandleFunc("GET /v1/room/{id}", s.info)
	mux.HandleFunc("POST /v1/room/{id}/kick", s.kick)
	mux.HandleFunc("DELETE /v1/room/{id}", s.del)

	d.RegisterScope("POST /v1/room", "room")
	d.RegisterScope("POST /room/{secret}/join", "room")
	d.RegisterScope("GET /v1/room/{id}", "room")
	d.RegisterScope("POST /v1/room/{id}/kick", "room")
	d.RegisterScope("DELETE /v1/room/{id}", "room")
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("rooms", func(context.Context) string { return llmsText })
	d.RegisterTarget("o", core.Target{Exists: exists, Hide: hide, Restore: restore})
	d.StorageClass(capKind, 64<<20, `SELECT pg_total_relation_size('rooms') + pg_total_relation_size('room_members')`)
	d.Janitor.Add(capKind, func(ctx context.Context) error { return Janitor(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error { return purge(ctx, d.DB, root) })
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// randSecret mints a server-chosen join secret (16 random bytes -> 22 base64url chars).
func randSecret() string {
	b := make([]byte, secretLn)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ns is the KV namespace / primitive-name prefix of a room (r:<id>).
func ns(id string) string { return "r:" + id }

// box is the mailbox box of a room (r<id>, no colon; 11).
func box(id string) string { return "r" + id }

// input is the mint body of POST /v1/room.
type input struct {
	TTLH  int      `json:"ttl_h"`
	Cap   int      `json:"cap"`
	Name  string   `json:"name"`
	Allow []string `json:"allow"`
}

// validate normalises the name, clamps the cap and the ttl and checks the allow list of roots.
func (in *input) validate() error {
	in.Name = scrub.Normalize(strings.TrimSpace(in.Name))
	if len(in.Name) > maxName {
		return core.Bad(fmt.Sprintf("name must be <= %d bytes", maxName))
	}
	if in.Name != "" && !doc.OneLine(in.Name) {
		return core.Bad("name must be a single line")
	}
	if in.Name != "" {
		if _, aerr := scrub.RejectOrMask(map[string]*string{"name": &in.Name}); aerr != nil {
			return aerr
		}
	}
	if in.Cap == 0 {
		in.Cap = minCap
	}
	if in.Cap < minCap || in.Cap > maxCap {
		return core.Bad(fmt.Sprintf("cap must be between %d and %d", minCap, maxCap))
	}
	if in.TTLH < 0 {
		return core.Bad("ttl_h must be >= 0")
	}
	if len(in.Allow) > maxCap {
		return core.Bad(fmt.Sprintf("allow must list <= %d roots", maxCap))
	}
	seen := map[string]bool{}
	out := in.Allow[:0]
	for _, a := range in.Allow {
		a = strings.TrimSpace(a)
		if !core.ValidIDPrefix(a, 'a') {
			return core.Bad("allow entries must be root ids (a…)")
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	in.Allow = out
	return nil
}

// ttl is the room lifetime: ttl_h clamped to 72 h (default 72 h).
func (in *input) ttl() time.Duration {
	if in.TTLH == 0 {
		return maxTTL
	}
	return min(time.Duration(in.TTLH)*time.Hour, maxTTL)
}

// minted is a freshly created room: its id, join secret and expiry.
type minted struct {
	ID      string
	Secret  string
	Expires time.Time
}

// line is the mint reply head: ok o… join=/room/<secret> exp=<date>.
func (m minted) line() string {
	return fmt.Sprintf("ok %s join=/room/%s exp=%s", m.ID, m.Secret, core.Date(m.Expires))
}

// mint is the create transaction: the live-rooms cap, the secret, the insert and the owner audit.
func (s *svc) mint(ctx context.Context, tx core.Q, id *core.Ident, in input) (minted, error) {
	var live int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM rooms WHERE owner_root = $1 AND until > now()`, id.Root).Scan(&live); err != nil {
		return minted{}, err
	}
	if live >= trust.Cap(capKind, core.Level(ctx, tx, id.Root)) {
		return minted{}, errLive
	}
	m := minted{ID: core.NewID('o'), Secret: randSecret(), Expires: time.Now().Add(in.ttl())}
	allow := in.Allow
	if allow == nil {
		allow = []string{}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rooms (id, h, owner_root, cap, name, until, allow) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		m.ID, hash(m.Secret), id.Root, in.Cap, in.Name, m.Expires, allow); err != nil {
		if core.IsUniqueViolation(err) {
			return minted{}, core.ErrDup
		}
		return minted{}, err
	}
	if err := core.Audit(ctx, tx, id.ID, "room", m.ID, 0); err != nil {
		return minted{}, err
	}
	return m, nil
}

// create serves POST /v1/room (token, scope room): mints a room and a server-made join secret.
func (s *svc) create(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") || !s.d.CheckFrozen(w, r, capKind) {
		return
	}
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in input
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := in.validate(); err != nil {
		doc.Fail(w, r, err)
		return
	}
	var m minted
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		var err error
		m, err = s.mint(r.Context(), tx, id, in)
		return err
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, http.StatusCreated, m.line(),
		doc.POST("/room/"+m.Secret+"/join", "+token"), doc.GET("/v1/room/"+m.ID, ""))
}

// roomRow is a loaded room (by secret or id).
type roomRow struct {
	ID        string
	OwnerRoot string
	Cap       int
	Name      string
	Until     time.Time
	Members   int
	Closed    bool
	Allow     []string
}

// live reports whether the room is still joinable/usable (not expired, not closed).
func (rr *roomRow) live() bool { return !rr.Closed && rr.Until.After(time.Now()) }

// bySecret loads a room by its join secret; errMiss when no row matches (unknown secret).
func (s *svc) bySecret(ctx context.Context, q core.Q, secret string) (*roomRow, error) {
	return scanRoom(q.QueryRow(ctx, `SELECT id, owner_root, cap, name, until, members, closed, allow
		FROM rooms WHERE h = $1`, hash(secret)))
}

// byID loads a room by its id; errMiss when no row matches.
func (s *svc) byID(ctx context.Context, q core.Q, id string) (*roomRow, error) {
	return scanRoom(q.QueryRow(ctx, `SELECT id, owner_root, cap, name, until, members, closed, allow
		FROM rooms WHERE id = $1`, id))
}

func scanRoom(row pgx.Row) (*roomRow, error) {
	rr := &roomRow{}
	if err := row.Scan(&rr.ID, &rr.OwnerRoot, &rr.Cap, &rr.Name, &rr.Until, &rr.Members, &rr.Closed, &rr.Allow); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errMiss
		}
		return nil, err
	}
	return rr, nil
}

// notFound is the one identical 404 every capability miss answers (unknown, expired or closed
// secret), always in the text format so the body is byte-identical.
func notFound(w http.ResponseWriter, r *http.Request) {
	doc.ReplyAs(w, r, http.StatusNotFound, doc.Error("notfound", "not found", doc.GET("/help", "")), doc.Txt)
}

// capGet serves GET /room/{secret} (capability; token optional): a live room's peers and expiry;
// an unknown, expired or closed secret answers the identical 404.
func (s *svc) capGet(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	secret := r.PathValue("secret")
	if !secretRe.MatchString(secret) {
		notFound(w, r)
		return
	}
	rr, err := s.bySecret(r.Context(), s.d.DB, secret)
	if errors.Is(err, errMiss) || (err == nil && !rr.live()) {
		notFound(w, r)
		return
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{
		Head:    fmt.Sprintf("room %s peers=%d/%d exp=%s", rr.ID, rr.Members, rr.Cap, core.Date(rr.Until)),
		Title:   "room " + rr.ID,
		Desc:    "a throwaway cross-root swarm namespace; hold the secret to join",
		NoIndex: true,
		MaxAge:  -1,
		Next:    []doc.Action{doc.POST("/room/"+secret+"/join", "+token")},
	}
	if rr.Name != "" {
		d.Fields = append(d.Fields, doc.F{Name: "name", Val: doc.SafeLine(rr.Name)})
	}
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	doc.Reply(w, r, http.StatusOK, d)
}

// join serves POST /room/{secret}/join (token, any root): admits the caller to a live room. The cap
// counts distinct roots; re-joining is idempotent (ON CONFLICT DO NOTHING). An allow list, when set,
// restricts who may join. Unknown, expired or closed secrets answer the identical 404.
func (s *svc) join(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") {
		return
	}
	secret := r.PathValue("secret")
	if !secretRe.MatchString(secret) {
		notFound(w, r)
		return
	}
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var rr *roomRow
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		var e error
		rr, e = s.admit(r.Context(), tx, secret, id)
		return e
	})
	if errors.Is(err, errMiss) {
		notFound(w, r)
		return
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, http.StatusOK, fmt.Sprintf("ok room=%s peers=%d", rr.ID, rr.Members),
		doc.GET("/v1/room/"+rr.ID, ""))
}

// admit runs the join transaction: locks the room row, enforces the allow list and the distinct-root
// cap, inserts the membership and refreshes the cached member count.
func (s *svc) admit(ctx context.Context, tx core.Q, secret string, id *core.Ident) (*roomRow, error) {
	rr := &roomRow{}
	err := tx.QueryRow(ctx, `SELECT id, owner_root, cap, name, until, members, closed, allow
		FROM rooms WHERE h = $1 FOR UPDATE`, hash(secret)).
		Scan(&rr.ID, &rr.OwnerRoot, &rr.Cap, &rr.Name, &rr.Until, &rr.Members, &rr.Closed, &rr.Allow)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errMiss
	}
	if err != nil {
		return nil, err
	}
	if !rr.live() {
		return nil, errMiss
	}
	if len(rr.Allow) > 0 && !contains(rr.Allow, id.Root) {
		return nil, core.E(403, "forbid", "not on this room's allow list")
	}
	// Distinct roots already in the room; a returning root does not consume a new slot.
	var member bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM room_members WHERE room = $1 AND root = $2)`, rr.ID, id.Root).Scan(&member); err != nil {
		return nil, err
	}
	if !member {
		var distinct int
		if err := tx.QueryRow(ctx, `SELECT count(DISTINCT root) FROM room_members WHERE room = $1`, rr.ID).Scan(&distinct); err != nil {
			return nil, err
		}
		if distinct >= rr.Cap {
			return nil, errFull
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO room_members (room, id, root) VALUES ($1, $2, $3)
		ON CONFLICT (room, id) DO UPDATE SET last_seen = now()`, rr.ID, id.ID, id.Root); err != nil {
		return nil, err
	}
	if err := tx.QueryRow(ctx, `UPDATE rooms SET members = (SELECT count(DISTINCT root) FROM room_members WHERE room = $1)
		WHERE id = $1 RETURNING members`, rr.ID).Scan(&rr.Members); err != nil {
		return nil, err
	}
	return rr, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// IsMember reports whether root is a live member of roomID: a joined root of a room that is neither
// expired nor closed. It implements mem.RoomFn, mail.RoomFn and swarm.RoomFn; those seams fail closed
// when left nil, and this predicate itself fails closed on an anonymous, expired or closed room.
func IsMember(ctx context.Context, q core.Q, roomID, root string) (bool, error) {
	if root == "" || !core.ValidIDPrefix(roomID, 'o') {
		return false, nil
	}
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM room_members m JOIN rooms r ON r.id = m.room
		WHERE m.room = $1 AND m.root = $2 AND NOT r.closed AND r.until > now())`, roomID, root).Scan(&ok)
	return ok, err
}
