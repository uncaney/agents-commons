package room

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/mem"
	"ekaii.fr/commons/internal/swarm"
	"ekaii.fr/commons/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("room", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping room DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
}

// newEnv wires room on its own. wireSwarm wires swarm+mem+mail and points their RoomFn seams at
// room.IsMember (the integration package's job in production).
func newEnv(t *testing.T, wireSwarm bool) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	if wireSwarm {
		swarm.Register(mux, d)
		mem.Register(mux, d)
		mail.Register(mux, d)
		swarm.RoomFn = IsMember
		mem.RoomFn = IsMember
		mail.RoomFn = IsMember
		t.Cleanup(func() { swarm.RoomFn, mem.RoomFn, mail.RoomFn = nil, nil, nil })
	}
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &tenv{d: d, srv: srv}
}

func randIP() string {
	var b [2]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.9.%d.%d", b[0], b[1])
}

// do sends a request; token "" is anonymous.
func (e *tenv) do(t *testing.T, method, path, token, body string) (int, string, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", randIP())
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func newRoot(t *testing.T) (id, token string) {
	t.Helper()
	id, token, err := core.CreateRoot(context.Background(), testPool, "room-test", randIP())
	if err != nil {
		t.Fatal(err)
	}
	return id, token
}

var createRe = regexp.MustCompile(`^ok (o[a-z2-7]{6}) join=/room/([A-Za-z0-9_-]{22}) exp=(\d{4}-\d{2}-\d{2})`)

// create mints a room and returns its id and join secret.
func (e *tenv) create(t *testing.T, token, body string) (id, secret string) {
	t.Helper()
	st, b, _ := e.do(t, "POST", "/v1/room", token, body)
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	m := createRe.FindStringSubmatch(b)
	if m == nil {
		t.Fatalf("create reply: %q", b)
	}
	return m[1], m[2]
}

func ctx() context.Context { return context.Background() }

func scalar[T any](t *testing.T, sql string, args ...any) T {
	t.Helper()
	var v T
	if err := testPool.QueryRow(ctx(), sql, args...).Scan(&v); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
	return v
}

// --- tests ---------------------------------------------------------------------------------------

func TestCreateCapsAndSecret(t *testing.T) {
	e := newEnv(t, false)
	_, token := newRoot(t)

	id, secret := e.create(t, token, `{"cap":4,"name":"plan"}`)
	if !core.ValidIDPrefix(id, 'o') {
		t.Fatalf("bad room id %q", id)
	}
	if !secretRe.MatchString(secret) {
		t.Fatalf("secret %q is not 22 base64url chars", secret)
	}
	// 16 random bytes -> exactly 22 base64url chars, and it must decode.
	if _, err := base64.RawURLEncoding.DecodeString(secret); err != nil {
		t.Fatalf("secret not base64url: %v", err)
	}
	if got := scalar[int](t, `SELECT cap FROM rooms WHERE id = $1`, id); got != 4 {
		t.Fatalf("cap stored = %d, want 4", got)
	}

	// L0 live cap is 2: the second create is fine, the third is refused.
	e.create(t, token, `{}`)
	st, b, _ := e.do(t, "POST", "/v1/room", token, `{}`)
	if st != 429 {
		t.Fatalf("third create: %d %s, want 429", st, b)
	}

	// cap bounds are enforced.
	if st, _, _ := e.do(t, "POST", "/v1/room", token, `{"cap":1}`); st != 400 {
		t.Fatalf("cap=1: %d, want 400", st)
	}
	if st, _, _ := e.do(t, "POST", "/v1/room", token, `{"cap":99}`); st != 400 {
		t.Fatalf("cap=99: %d, want 400", st)
	}
}

func TestJoinAllowListAndCap(t *testing.T) {
	e := newEnv(t, false)
	_, owner := newRoot(t)
	bID, bTok := newRoot(t)
	_, cTok := newRoot(t)
	_, dTok := newRoot(t)

	// allow list: only root B may join.
	_, secret := e.create(t, owner, fmt.Sprintf(`{"cap":8,"allow":["%s"]}`, bID))
	if st, b, _ := e.do(t, "POST", "/room/"+secret+"/join", bTok, ""); st != 200 {
		t.Fatalf("B join allowed: %d %s", st, b)
	}
	if st, _, _ := e.do(t, "POST", "/room/"+secret+"/join", cTok, ""); st != 403 {
		t.Fatalf("C join (not on allow list): %d, want 403", st)
	}

	// cap counts distinct roots; the third distinct root is refused, a re-join is idempotent.
	id2, secret2 := e.create(t, owner, `{"cap":2}`)
	if st, _, _ := e.do(t, "POST", "/room/"+secret2+"/join", bTok, ""); st != 200 {
		t.Fatalf("B join room2: %d", st)
	}
	if st, _, _ := e.do(t, "POST", "/room/"+secret2+"/join", cTok, ""); st != 200 {
		t.Fatalf("C join room2: %d", st)
	}
	if st, _, _ := e.do(t, "POST", "/room/"+secret2+"/join", dTok, ""); st != 409 {
		t.Fatalf("D join full room2: %d, want 409", st)
	}
	// B re-joins: idempotent, still two distinct roots.
	if st, _, _ := e.do(t, "POST", "/room/"+secret2+"/join", bTok, ""); st != 200 {
		t.Fatalf("B re-join: %d", st)
	}
	if got := scalar[int](t, `SELECT members FROM rooms WHERE id = $1`, id2); got != 2 {
		t.Fatalf("members = %d, want 2", got)
	}
	if got := scalar[int](t, `SELECT count(*) FROM room_members WHERE room = $1`, id2); got != 2 {
		t.Fatalf("member rows = %d, want 2", got)
	}
}

func TestIsMemberFailClosed(t *testing.T) {
	e := newEnv(t, false)
	_, owner := newRoot(t)
	bID, bTok := newRoot(t)
	cID, _ := newRoot(t)

	id, secret := e.create(t, owner, `{"cap":4}`)
	if st, _, _ := e.do(t, "POST", "/room/"+secret+"/join", bTok, ""); st != 200 {
		t.Fatalf("B join: %d", st)
	}

	check := func(want bool, roomID, root string) {
		t.Helper()
		got, err := IsMember(ctx(), testPool, roomID, root)
		if err != nil {
			t.Fatalf("IsMember(%s,%s): %v", roomID, root, err)
		}
		if got != want {
			t.Fatalf("IsMember(%s,%s) = %v, want %v", roomID, root, got, want)
		}
	}
	check(true, id, bID)         // a joined root
	check(false, id, cID)        // a non-member
	check(false, id, "")         // anonymous
	check(false, "ozzzzzz", bID) // unknown room (invalid id -> false)

	// closed room: IsMember refuses.
	if _, err := testPool.Exec(ctx(), `UPDATE rooms SET closed = true WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	check(false, id, bID)

	// reopened but expired: IsMember refuses.
	if _, err := testPool.Exec(ctx(), `UPDATE rooms SET closed = false, until = now() - interval '1 h' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	check(false, id, bID)
}

func TestIdentical404ExpiredClosedUnknown(t *testing.T) {
	e := newEnv(t, false)
	_, owner := newRoot(t)
	_, bTok := newRoot(t)

	unknown := randSecret()
	stU, bodyU, _ := e.do(t, "GET", "/room/"+unknown, "", "")
	if stU != 404 {
		t.Fatalf("unknown GET: %d, want 404", stU)
	}

	id, secret := e.create(t, owner, `{"cap":4}`)
	if st, _, _ := e.do(t, "POST", "/room/"+secret+"/join", bTok, ""); st != 200 {
		t.Fatalf("B join: %d", st)
	}

	// expired -> identical 404 on GET and on join.
	if _, err := testPool.Exec(ctx(), `UPDATE rooms SET until = now() - interval '1 h' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	stE, bodyE, _ := e.do(t, "GET", "/room/"+secret, "", "")
	stJ, bodyJ, _ := e.do(t, "POST", "/room/"+secret+"/join", bTok, "")
	if stE != 404 || bodyE != bodyU {
		t.Fatalf("expired GET: %d body=%q, want 404 body=%q", stE, bodyE, bodyU)
	}
	if stJ != 404 || bodyJ != bodyU {
		t.Fatalf("expired join: %d body=%q, want 404 identical body", stJ, bodyJ)
	}

	// closed -> same 404.
	if _, err := testPool.Exec(ctx(), `UPDATE rooms SET until = now() + interval '1 h', closed = true WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	stC, bodyC, _ := e.do(t, "GET", "/room/"+secret, "", "")
	if stC != 404 || bodyC != bodyU {
		t.Fatalf("closed GET: %d body=%q, want identical 404", stC, bodyC)
	}
}

func TestKickAndDelete(t *testing.T) {
	e := newEnv(t, false)
	_, owner := newRoot(t)
	bID, bTok := newRoot(t)
	_, cTok := newRoot(t)

	id, secret := e.create(t, owner, `{"cap":4}`)
	e.do(t, "POST", "/room/"+secret+"/join", bTok, "")
	if got := scalar[int](t, `SELECT members FROM rooms WHERE id = $1`, id); got != 1 {
		t.Fatalf("members after join = %d, want 1", got)
	}

	// a non-owner cannot kick (and never learns the room exists -> 404).
	if st, _, _ := e.do(t, "POST", "/v1/room/"+id+"/kick", cTok, fmt.Sprintf(`{"id":"%s"}`, bID)); st != 404 {
		t.Fatalf("non-owner kick: %d, want 404", st)
	}
	// owner kicks B by its identity id.
	if st, b, _ := e.do(t, "POST", "/v1/room/"+id+"/kick", owner, fmt.Sprintf(`{"id":"%s"}`, bID)); st != 200 {
		t.Fatalf("owner kick: %d %s", st, b)
	}
	if got := scalar[int](t, `SELECT members FROM rooms WHERE id = $1`, id); got != 0 {
		t.Fatalf("members after kick = %d, want 0", got)
	}

	// owner deletes the room; it is gone and so are its members.
	if st, b, _ := e.do(t, "DELETE", "/v1/room/"+id, owner, ""); st != 200 {
		t.Fatalf("owner delete: %d %s", st, b)
	}
	if got := scalar[int](t, `SELECT count(*) FROM rooms WHERE id = $1`, id); got != 0 {
		t.Fatalf("room still present after delete")
	}
	// the capability URL now answers 404.
	if st, _, _ := e.do(t, "GET", "/room/"+secret, "", ""); st != 404 {
		t.Fatalf("deleted room GET: %d, want 404", st)
	}
}

// seedPrimitive inserts one row of each room-scoped primitive directly, plus one unrelated row that
// must survive the janitor.
func seedRoomRows(t *testing.T, id string) {
	t.Helper()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := testPool.Exec(ctx(), sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	n := ns(id)
	exec(`INSERT INTO kv (ns, k, v, expires_at, root) VALUES ($1, 'plan', 'x', now() + interval '1 d', 'asystem')`, n)
	exec(`INSERT INTO locks (name, holder, root, until) VALUES ($1, 'h', 'asystem', now() + interval '1 h')`, n+".build")
	exec(`INSERT INTO topics (name, owner_root) VALUES ($1, 'asystem')`, n+".chat")
	exec(`INSERT INTO topic_msgs (topic, seq, by, root, text) VALUES ($1, 1, 'h', 'asystem', 'hi')`, n+".chat")
	exec(`INSERT INTO topic_cursors (topic, root, seq) VALUES ($1, 'asystem', 1)`, n+".chat")
	exec(`INSERT INTO queues (name, owner_root) VALUES ($1, 'asystem')`, n+".jobs")
	exec(`INSERT INTO q_items (queue, body) VALUES ($1, 'task')`, n+".jobs")
	exec(`INSERT INTO barriers (name, n, until, owner_root) VALUES ($1, 2, now() + interval '1 h', 'asystem')`, n+".sync")
	exec(`INSERT INTO mb_boxes (box, owner_root) VALUES ($1, 'asystem')`, box(id))
	exec(`INSERT INTO mail (id, box, seq, from_id, from_root, text) VALUES ($1, $2, 1, 'asystem', 'asystem', 'hi')`, core.NewID('m'), box(id))
	// unrelated rows that must survive (idempotent so the shared DB tolerates re-runs).
	exec(`INSERT INTO kv (ns, k, v, expires_at, root) VALUES ('a:asystem', 'keep', 'y', now() + interval '1 d', 'asystem') ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO locks (name, holder, root, until) VALUES ('g:keep', 'h', 'asystem', now() + interval '1 h') ON CONFLICT DO NOTHING`)
}

func TestTTLCleanupByPrefix(t *testing.T) {
	e := newEnv(t, false)
	_, owner := newRoot(t)
	id, secret := e.create(t, owner, `{"cap":4}`)
	seedRoomRows(t, id)

	// expire the room, then run the janitor.
	if _, err := testPool.Exec(ctx(), `UPDATE rooms SET until = now() - interval '1 h' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := Janitor(ctx(), testPool); err != nil {
		t.Fatalf("janitor: %v", err)
	}

	n := ns(id)
	gone := map[string][]any{
		`SELECT count(*) FROM kv WHERE ns = $1`:               {n},
		`SELECT count(*) FROM locks WHERE name = $1`:          {n + ".build"},
		`SELECT count(*) FROM topics WHERE name = $1`:         {n + ".chat"},
		`SELECT count(*) FROM topic_msgs WHERE topic = $1`:    {n + ".chat"},
		`SELECT count(*) FROM topic_cursors WHERE topic = $1`: {n + ".chat"},
		`SELECT count(*) FROM queues WHERE name = $1`:         {n + ".jobs"},
		`SELECT count(*) FROM q_items WHERE queue = $1`:       {n + ".jobs"},
		`SELECT count(*) FROM barriers WHERE name = $1`:       {n + ".sync"},
		`SELECT count(*) FROM mail WHERE box = $1`:            {box(id)},
		`SELECT count(*) FROM mb_boxes WHERE box = $1`:        {box(id)},
		`SELECT count(*) FROM rooms WHERE id = $1`:            {id},
		`SELECT count(*) FROM room_members WHERE room = $1`:   {id},
	}
	for sql, args := range gone {
		if got := scalar[int](t, sql, args...); got != 0 {
			t.Errorf("%q = %d, want 0 (room row survived cleanup)", sql, got)
		}
	}
	// unrelated rows survive.
	if got := scalar[int](t, `SELECT count(*) FROM kv WHERE ns = 'a:asystem' AND k = 'keep'`); got != 1 {
		t.Errorf("unrelated kv row deleted")
	}
	if got := scalar[int](t, `SELECT count(*) FROM locks WHERE name = 'g:keep'`); got != 1 {
		t.Errorf("unrelated lock row deleted")
	}
	// the capability URL now answers 404.
	if st, _, _ := e.do(t, "GET", "/room/"+secret, "", ""); st != 404 {
		t.Fatalf("expired+cleaned room GET: %d, want 404", st)
	}
}

func TestNothingListed(t *testing.T) {
	e := newEnv(t, false)
	// no feed or sitemap surfaces rooms.
	for name := range e.d.Feeds() {
		if strings.Contains(name, "room") {
			t.Fatalf("rooms exposed via feed %q", name)
		}
	}
	for name := range e.d.Sitemaps() {
		if strings.Contains(name, "room") {
			t.Fatalf("rooms exposed via sitemap %q", name)
		}
	}
	// the capability view is noindex and never cached.
	_, owner := newRoot(t)
	_, secret := e.create(t, owner, `{"cap":4}`)
	_, _, h := e.do(t, "GET", "/room/"+secret, "", "")
	if !strings.Contains(h.Get("Cache-Control"), "no-store") {
		t.Errorf("capability view Cache-Control = %q, want no-store", h.Get("Cache-Control"))
	}
	if !strings.Contains(h.Get("X-Robots-Tag"), "noindex") {
		t.Errorf("capability view X-Robots-Tag = %q, want noindex", h.Get("X-Robots-Tag"))
	}
}

// TestEndToEndTTL is acceptance item 2: two roots join /room/<secret>, write kv r:<id>/plan and
// acquire lock r:<id>.build through the real swarm/mem handlers; after the TTL both rows are gone and
// the URL answers 404.
func TestEndToEndTTL(t *testing.T) {
	e := newEnv(t, true)
	_, owner := newRoot(t)
	_, aTok := newRoot(t)
	_, bTok := newRoot(t)

	id, secret := e.create(t, owner, `{"cap":4}`)
	for who, tok := range map[string]string{"A": aTok, "B": bTok} {
		if st, b, _ := e.do(t, "POST", "/room/"+secret+"/join", tok, ""); st != 200 {
			t.Fatalf("%s join: %d %s", who, st, b)
		}
	}
	n := ns(id)
	// member A writes a room KV key and acquires a room lock.
	if st, b, _ := e.do(t, "PUT", "/v1/kv/"+n+"/plan", aTok, "the plan"); st != 200 && st != 201 {
		t.Fatalf("kv put: %d %s", st, b)
	}
	if st, b, _ := e.do(t, "POST", "/v1/lk/"+n+".build", aTok, `{}`); st != 200 {
		t.Fatalf("lock acquire: %d %s", st, b)
	}
	// a non-member is refused the same namespace.
	_, nmTok := newRoot(t)
	if st, _, _ := e.do(t, "PUT", "/v1/kv/"+n+"/sneak", nmTok, "no"); st == 200 || st == 201 {
		t.Fatalf("non-member kv write succeeded (%d), want refusal", st)
	}
	if got := scalar[int](t, `SELECT count(*) FROM kv WHERE ns = $1`, n); got != 1 {
		t.Fatalf("kv rows = %d, want 1", got)
	}
	if got := scalar[int](t, `SELECT count(*) FROM locks WHERE name = $1`, n+".build"); got != 1 {
		t.Fatalf("lock rows = %d, want 1", got)
	}

	// expire and run the janitor: both rows and the room vanish, the URL 404s.
	if _, err := testPool.Exec(ctx(), `UPDATE rooms SET until = now() - interval '1 h' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := Janitor(ctx(), testPool); err != nil {
		t.Fatalf("janitor: %v", err)
	}
	if got := scalar[int](t, `SELECT count(*) FROM kv WHERE ns = $1`, n); got != 0 {
		t.Errorf("kv row survived TTL cleanup")
	}
	if got := scalar[int](t, `SELECT count(*) FROM locks WHERE name = $1`, n+".build"); got != 0 {
		t.Errorf("lock row survived TTL cleanup")
	}
	if st, _, _ := e.do(t, "GET", "/room/"+secret, "", ""); st != 404 {
		t.Fatalf("post-TTL GET: %d, want 404", st)
	}
}

func TestOpenAPIValid(t *testing.T) {
	if !json.Valid(openAPI) {
		t.Fatal("openAPI fragment is not valid JSON")
	}
	if len(Help) > 1200 {
		t.Errorf("Help is %d bytes, keep it compact", len(Help))
	}
}
