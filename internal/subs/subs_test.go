package subs

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/mem"
	"ekaii.fr/commons/internal/swarm"
	"ekaii.fr/commons/internal/testdb"
)

var (
	testPool *pgxpool.Pool
	levels   sync.Map
	members  sync.Map // "<slug>|<root>" -> bool, drives swarm.MemberFn
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	var cleanup func()
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("subs", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL unset: skipping subs DB tests")
		os.Exit(0)
	}
	core.LevelFn = func(ctx context.Context, q core.Q, root string) int {
		v, _ := levels.Load(root)
		n, _ := v.(int)
		return n
	}
	swarm.MemberFn = func(ctx context.Context, q core.Q, slug, root string) (bool, error) {
		v, _ := members.Load(slug + "|" + root)
		b, _ := v.(bool)
		return b, nil
	}
	mem.MemberFn = func(ctx context.Context, q core.Q, slug, root string) (bool, error) {
		v, _ := members.Load(slug + "|" + root)
		b, _ := v.(bool)
		return b, nil
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func newDeps(t *testing.T) (*core.Deps, *Service) {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 4, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20, PGNotify: false}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d, svc(d)
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

func mkRoot(t *testing.T) *core.Ident {
	t.Helper()
	id := core.NewID('a')
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, earned, reg_ip, rep, created, verified_noncompute)
		VALUES ($1, 'r', NULL, $1, $2, 1000, 1000, $3, 9, now() - interval '5 days', 1)`, id, id, randIP()); err != nil {
		t.Fatal(err)
	}
	levels.Store(id, 2)
	return &core.Ident{ID: id, Root: id, Credits: 1000, Earned: 1000, Rep: 9, Created: time.Now().Add(-5 * 24 * time.Hour)}
}

func pub(t *testing.T, by *core.Ident, topic, text, key string) int64 {
	t.Helper()
	seq, err := swarm.Publish(context.Background(), testPool, topic, by.ID, by.Root, text, key)
	if err != nil {
		t.Fatalf("publish %q: %v", text, err)
	}
	return seq
}

func qitems(t *testing.T, queue string) []string {
	t.Helper()
	rows, err := testPool.Query(context.Background(), `SELECT body FROM q_items WHERE queue = $1 ORDER BY id`, queue)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func sysMails(t *testing.T, root string) []string {
	t.Helper()
	b, err := mail.Resolve(context.Background(), testPool, nil, root)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := testPool.Query(context.Background(), `SELECT text FROM mail WHERE box = $1 AND from_root = 'asystem' ORDER BY seq`, b.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func deliver(t *testing.T, s *Service) {
	t.Helper()
	if err := s.deliverAll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func mkSub(t *testing.T, s *Service, id *core.Ident, in CreateIn) *Sub {
	t.Helper()
	sub, err := s.Create(context.Background(), id, in)
	if err != nil {
		t.Fatalf("create sub: %v", err)
	}
	return sub
}

// verifiedSvc inserts a verified, stable one-version catalog service so fnVerified passes.
func verifiedSvc(t *testing.T, owner, name string) {
	t.Helper()
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `INSERT INTO services (name, owner_root, stable_ver, stable_at) VALUES ($1, $2, 1, now())`, name, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO service_versions (name, ver, wasm, state, verified_at) VALUES ($1, 1, $2, 'verified', now())`, name, name+"hash"); err != nil {
		t.Fatal(err)
	}
}

// --- tests ---

func TestFilterPrefixAndRE2(t *testing.T) {
	_, s := newDeps(t)
	a := mkRoot(t)
	topic := "g:f" + core.NewID('a')[1:5]
	ps := mkSub(t, s, a, CreateIn{Topic: topic, Sink: "wq:a:" + a.Root + ".pfx", Filter: "prefix:ALERT"})
	re := mkSub(t, s, a, CreateIn{Topic: topic, Sink: "wq:a:" + a.Root + ".rex", Filter: "re:^ERR[0-9]+"})
	pub(t, a, topic, "ALERT: disk full", "")
	pub(t, a, topic, "ERR42 boom", "")
	pub(t, a, topic, "info nothing", "")
	deliver(t, s)

	pfx := qitems(t, "a:"+a.Root+".pfx")
	if len(pfx) != 1 || !strings.Contains(pfx[0], "ALERT: disk full") {
		t.Fatalf("prefix sink got %v", pfx)
	}
	rex := qitems(t, "a:"+a.Root+".rex")
	if len(rex) != 1 || !strings.Contains(rex[0], "ERR42 boom") {
		t.Fatalf("re sink got %v", rex)
	}
	_ = ps
	_ = re
}

func TestQueueSinkExactlyOnce(t *testing.T) {
	_, s := newDeps(t)
	a := mkRoot(t)
	mkSub(t, s, a, CreateIn{Topic: "g:ci.events", Sink: "wq:g:team.inbox"})
	pub(t, a, "g:ci.events", "build passed", "")
	// The delivery loop runs twice: still exactly one queue item.
	deliver(t, s)
	deliver(t, s)
	items := qitems(t, "g:team.inbox")
	if len(items) != 1 {
		t.Fatalf("want exactly one queue item, got %d: %v", len(items), items)
	}
	if !strings.Contains(items[0], "build passed") {
		t.Fatalf("body = %q", items[0])
	}
}

func TestMailEachAndDigest(t *testing.T) {
	_, s := newDeps(t)
	// each mode
	a := mkRoot(t)
	mkSub(t, s, a, CreateIn{Topic: "g:me" + core.NewID('a')[1:5], Sink: "mb:me", Mode: "each"})
	subs, _ := s.List(context.Background(), a.Root)
	topic := subs[0].Topic
	pub(t, a, topic, "one", "")
	pub(t, a, topic, "two", "")
	deliver(t, s)
	if ms := sysMails(t, a.Root); len(ms) != 2 {
		t.Fatalf("each mode: want 2 mails, got %d: %v", len(ms), ms)
	}

	// digest mode: force the window open so a pass flushes immediately.
	old := digestEvery
	digestEvery = 0
	defer func() { digestEvery = old }()
	b := mkRoot(t)
	dtopic := "g:dg" + core.NewID('a')[1:5]
	mkSub(t, s, b, CreateIn{Topic: dtopic, Sink: "mb:me", Mode: "digest"})
	pub(t, b, dtopic, "d-one", "")
	pub(t, b, dtopic, "d-two", "")
	deliver(t, s)
	ms := sysMails(t, b.Root)
	if len(ms) != 1 {
		t.Fatalf("digest mode: want 1 mail, got %d: %v", len(ms), ms)
	}
	if !strings.Contains(ms[0], "d-one") || !strings.Contains(ms[0], "d-two") {
		t.Fatalf("digest mail missing lines: %q", ms[0])
	}
}

func TestKVSinkLatest(t *testing.T) {
	_, s := newDeps(t)
	a := mkRoot(t)
	topic := "g:kv" + core.NewID('a')[1:5]
	mkSub(t, s, a, CreateIn{Topic: topic, Sink: "kv:a:" + a.Root + "/latest"})
	pub(t, a, topic, "first", "")
	pub(t, a, topic, "second", "")
	deliver(t, s)
	v, _, err := mem.KVGet(context.Background(), testPool, a.Root, "a:"+a.Root, "latest")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "second" {
		t.Fatalf("kv latest = %q, want second", v)
	}
}

func TestFnSinkRunsServiceAndWritesBack(t *testing.T) {
	d, s := newDeps(t)
	_ = d
	a := mkRoot(t)
	name := "echo" + core.NewID('a')[1:6]
	verifiedSvc(t, a.Root, name)
	old := callService
	callService = func(ctx context.Context, dd *core.Deps, id *core.Ident, nameAtVer, inText string, wait int) (string, string, error) {
		return "done", "RESULT:" + inText, nil
	}
	defer func() { callService = old }()

	topic := "g:fn" + core.NewID('a')[1:5]
	mkSub(t, s, a, CreateIn{Topic: topic, Sink: "fn:" + name + "@1", To: "kv:a:" + a.Root + "/out", HopMax: 3})
	pub(t, a, topic, "hello", "")
	deliver(t, s)
	v, _, err := mem.KVGet(context.Background(), testPool, a.Root, "a:"+a.Root, "out")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(v); got != "hop=1\nRESULT:hello" {
		t.Fatalf("fn output = %q, want hop=1\\nRESULT:hello", got)
	}
}

func TestHopCounterStopsLoops(t *testing.T) {
	d, s := newDeps(t)
	_ = d
	a := mkRoot(t)
	name := "echo" + core.NewID('a')[1:6]
	verifiedSvc(t, a.Root, name)
	old := callService
	callService = func(ctx context.Context, dd *core.Deps, id *core.Ident, nameAtVer, inText string, wait int) (string, string, error) {
		return "done", "echoed", nil
	}
	defer func() { callService = old }()

	// Direct hop-gate: a message already at hop_max must not fire.
	topic := "g:hop" + core.NewID('a')[1:5]
	mkSub(t, s, a, CreateIn{Topic: topic, Sink: "fn:" + name + "@1", To: "kv:a:" + a.Root + "/h", HopMax: 2})
	pub(t, a, topic, "hop=2\npayload", "") // hop >= hop_max: skipped
	deliver(t, s)
	if _, _, err := mem.KVGet(context.Background(), testPool, a.Root, "a:"+a.Root, "h"); err == nil {
		t.Fatal("message at hop_max fired; expected it to be skipped")
	}
	pub(t, a, topic, "hop=1\npayload", "") // hop < hop_max: fires -> hop=2 output
	deliver(t, s)
	v, _, err := mem.KVGet(context.Background(), testPool, a.Root, "a:"+a.Root, "h")
	if err != nil || string(v) != "hop=2\nechoed" {
		t.Fatalf("hop<max should fire with hop+1 output, got %q err=%v", v, err)
	}

	// A fn loop onto its own topic terminates: the sub-published message carries via=sub and is
	// never re-matched, so repeated passes add nothing.
	loop := "g:lp" + core.NewID('a')[1:5]
	mkSub(t, s, a, CreateIn{Topic: loop, Sink: "fn:" + name + "@1", To: "topic:" + loop, HopMax: 5})
	pub(t, a, loop, "seed", "")
	for i := 0; i < 5; i++ {
		deliver(t, s)
	}
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM topic_msgs WHERE topic = $1`, loop).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 { // the seed plus exactly one fn output
		t.Fatalf("loop produced %d messages, want 2 (bounded)", n)
	}
}

func TestSinkAuthRechecked(t *testing.T) {
	_, s := newDeps(t)
	a := mkRoot(t)
	slug := "sp" + core.NewID('a')[1:6]
	members.Store(slug+"|"+a.Root, true)
	topic := "g:au" + core.NewID('a')[1:5]
	sub := mkSub(t, s, a, CreateIn{Topic: topic, Sink: "wq:s:" + slug + ".inbox"})
	// Revoke membership: the sink is no longer writable.
	members.Store(slug+"|"+a.Root, false)
	pub(t, a, topic, "secret", "")
	deliver(t, s)
	if items := qitems(t, "s:"+slug+".inbox"); len(items) != 0 {
		t.Fatalf("unauthorised sink still received %v", items)
	}
	got, err := s.Get(context.Background(), a.Root, sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Errors == 0 {
		t.Fatal("expected an error count after refusal")
	}
}

func TestPauseAfterErrors(t *testing.T) {
	_, s := newDeps(t)
	old := pauseAfterErr
	pauseAfterErr = 3
	defer func() { pauseAfterErr = old }()
	a := mkRoot(t)
	slug := "pz" + core.NewID('a')[1:6]
	members.Store(slug+"|"+a.Root, true)
	topic := "g:pe" + core.NewID('a')[1:5]
	sub := mkSub(t, s, a, CreateIn{Topic: topic, Sink: "wq:s:" + slug + ".inbox"})
	members.Store(slug+"|"+a.Root, false)
	pub(t, a, topic, "x", "")
	for i := 0; i < 3; i++ {
		deliver(t, s)
	}
	got, err := s.Get(context.Background(), a.Root, sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Paused {
		t.Fatalf("sub not paused after %d refusals (errors=%d)", pauseAfterErr, got.Errors)
	}
	if ms := sysMails(t, a.Root); len(ms) == 0 {
		t.Fatal("expected a pause notice mail")
	}
}

func TestCapsAndCredits(t *testing.T) {
	_, s := newDeps(t)

	// per-root sub cap.
	a := mkRoot(t)
	oldMax := maxPerRoot
	maxPerRoot = 2
	defer func() { maxPerRoot = oldMax }()
	mkSub(t, s, a, CreateIn{Topic: "g:c1", Sink: "wq:a:" + a.Root + ".q1"})
	mkSub(t, s, a, CreateIn{Topic: "g:c2", Sink: "wq:a:" + a.Root + ".q2"})
	if _, err := s.Create(context.Background(), a, CreateIn{Topic: "g:c3", Sink: "wq:a:" + a.Root + ".q3"}); err == nil {
		t.Fatal("expected a per-root sub cap refusal")
	}

	// daily firing cap sheds the extra message.
	b := mkRoot(t)
	oldDay := firePerDayRoot
	firePerDayRoot = 1
	defer func() { firePerDayRoot = oldDay }()
	topic := "g:cd" + core.NewID('a')[1:5]
	mkSub(t, s, b, CreateIn{Topic: topic, Sink: "wq:a:" + b.Root + ".cap"})
	pub(t, b, topic, "m1", "")
	pub(t, b, topic, "m2", "")
	deliver(t, s)
	if items := qitems(t, "a:"+b.Root+".cap"); len(items) != 1 {
		t.Fatalf("daily cap: want 1 delivered, got %d", len(items))
	}

	// out-of-credits on a fn sink pauses the sub with a notice.
	c := mkRoot(t)
	verifiedSvc(t, c.Root, "svc"+core.NewID('a')[1:5])
	var svcName string
	testPool.QueryRow(context.Background(), `SELECT name FROM services WHERE owner_root = $1 LIMIT 1`, c.Root).Scan(&svcName)
	old := callService
	callService = func(ctx context.Context, dd *core.Deps, id *core.Ident, nameAtVer, inText string, wait int) (string, string, error) {
		return "", "", core.ErrCredits
	}
	defer func() { callService = old }()
	ftopic := "g:cc" + core.NewID('a')[1:5]
	sub := mkSub(t, s, c, CreateIn{Topic: ftopic, Sink: "fn:" + svcName + "@1", To: "kv:a:" + c.Root + "/o"})
	pub(t, c, ftopic, "go", "")
	deliver(t, s)
	got, err := s.Get(context.Background(), c.Root, sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Paused {
		t.Fatal("fn sub should pause when the subscriber is out of credits")
	}
}
