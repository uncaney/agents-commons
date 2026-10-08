package group

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/keys"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/swarm"
	"ekaii.fr/commons/internal/testdb"
)

var pool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		p, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if _, err := p.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, p); err != nil {
			panic(err)
		}
		pool, cleanup = p, p.Close
	} else if p, done := testdb.Open("group", core.Migrate); p != nil {
		pool, cleanup = p, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping group DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

const testSecret = "test-secret-0123456789abcdef"

type env struct {
	d   *core.Deps
	srv *httptest.Server
	ip  string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte(testSecret), AdminToken: "adm-token", SignKID: 1, PowBits: 6, PowBitsW: 2,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", MirrorURL: "https://github.com/example/mirror", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAuthV2(mux, d)
	sign.Register(mux, d)
	keys.Register(mux, d)
	swarm.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &env{d: d, srv: srv, ip: randIP()}
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

func (e *env) do(t *testing.T, method, path, token string, body []byte, hdr ...string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("CF-Connecting-IP", e.ip)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if len(body) > 0 && body[0] == '{' {
		req.Header.Set("Content-Type", "application/json")
	} else if len(body) > 0 {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), res.Header
}

var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

func kv(s string) map[string]string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(s, -1) {
		m[x[1]] = x[2]
	}
	return m
}

func count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// --- identities -------------------------------------------------------------------------------

type ident struct {
	id, tok, root string
	seed          []byte
	b             *e2e.Bundle
	leaf          uint64
}

func mkIdent(t *testing.T, age time.Duration) *ident {
	t.Helper()
	ctx := context.Background()
	in := &ident{seed: e2e.NewSeed()}
	rev := make([]byte, 32)
	rand.Read(rev)
	now := time.Now().Unix()
	err := core.Tx(ctx, pool, func(tx pgx.Tx) error {
		var err error
		if in.id, in.tok, err = core.CreateRoot(ctx, tx, "g-test", randIP()); err != nil {
			return err
		}
		in.root = in.id
		if _, err := tx.Exec(ctx, `UPDATE identities SET created = now() - $2::interval WHERE id = $1`, in.id, age.String()); err != nil {
			return err
		}
		b, err := e2e.NewBundle(in.seed, e2e.BundleParams{ID: in.id, Seq: 1, IAT: uint32(now), Exp: uint32(now + 30*86400),
			Flags: e2e.FlagLKOK, MailPolicy: e2e.PolicyBoth, MinCS: uint8(e2e.CS1), E0: e2e.Epoch(now) - 1, NEK: 5, RevCommit: e2e.Sum(rev)})
		if err != nil {
			return err
		}
		raw, err := b.Sign(e2e.IK(in.seed), nil, nil)
		if err != nil {
			return err
		}
		in.b = b
		enc, _ := json.Marshal(b64(raw))
		return keys.RegisterBundle(ctx, tx, in.id, enc)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT leaf FROM key_bundles WHERE id = $1 AND state = 'current'`, in.id).Scan(&in.leaf); err != nil {
		t.Fatal(err)
	}
	return in
}

func (in *ident) sign(t *testing.T, method, pathQuery string, body []byte) string {
	t.Helper()
	nonce := make([]byte, e2e.NonceSize)
	rand.Read(nonce)
	h, err := e2e.SignReq(e2e.RK(in.seed), method, pathQuery, uint64(time.Now().Unix()), nonce, body)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (e *env) signed(t *testing.T, who *ident, method, path string, body []byte, hdr ...string) (int, string, http.Header) {
	t.Helper()
	return e.do(t, method, path, who.tok, body, append([]string{"X-Cx-Sig", who.sign(t, method, path, body)}, hdr...)...)
}

// --- cxg1 session -----------------------------------------------------------------------------

// session tracks a group's members and the derived per-epoch secrets so the test can build real
// cxg1 commits, welcomes and app messages exactly as a reference client would.
type session struct {
	gid   string
	te    uint32 // the time epoch the prekeys live in
	ids   map[int]*ident
	gens  map[int]uint32 // per-idx gen counter (shared by commits, welcomes and app messages)
	init  []byte         // init_secret of the current epoch
	th    []byte         // confirmed transcript hash of the current epoch
	epoch uint32
	msgRt []byte // msg_root of the current epoch
}

func newSession(t *testing.T, ids ...*ident) *session {
	return &session{gid: core.NewID('g'), te: e2e.Epoch(time.Now().Unix()), ids: map[int]*ident{}, gens: map[int]uint32{},
		init: e2e.InitSecret0, th: make([]byte, 32), epoch: 0}
}

func (s *session) nextGen(idx int) uint32 { s.gens[idx]++; return s.gens[idx] }

func (s *session) member(idx int, in *ident) e2e.Member {
	return e2e.Member{Idx: uint16(idx), ID: in.id, IK: in.b.IK, Leaf: in.leaf}
}

func (s *session) ek(t *testing.T, in *ident) []byte {
	k, ok := in.b.EK(e2e.CS1, s.te)
	if !ok {
		t.Fatalf("no prekey for epoch %d", s.te)
	}
	return k
}

func (s *session) sk(t *testing.T, in *ident) hpke.PrivateKey {
	k, err := e2e.EK(in.seed, e2e.CS1, s.te, nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// createCommit builds the group's first commit: creator at idx 1, the rest added in order.
func (s *session) createCommit(t *testing.T, creator *ident, adds ...*ident) []byte {
	t.Helper()
	s.ids[1] = creator
	roster := []e2e.Member{s.member(1, creator)}
	fan := []e2e.Fanout{{Idx: 1, Key: s.ek(t, creator)}}
	var add []e2e.Added
	for i, a := range adds {
		idx := i + 2
		s.ids[idx] = a
		roster = append(roster, s.member(idx, a))
		fan = append(fan, e2e.Fanout{Idx: uint16(idx), Key: s.ek(t, a)})
		add = append(add, e2e.Added{ID: a.id, Leaf: a.leaf, EKH: e2e.EKH(s.ek(t, a))})
	}
	rh := e2e.RosterHash(roster)
	c, err := e2e.BuildCommit(e2e.CommitParams{GID: s.gid, CS: e2e.CS1, Epoch: 1, Idx: 1, Gen: s.nextGen(1), Pol: 3,
		Header: e2e.CommitHeader{Add: add}, Members: fan, InitPrev: e2e.InitSecret0, THPrev: make([]byte, 32),
		RosterHash: rh, IK: e2e.IK(creator.seed)})
	if err != nil {
		t.Fatal(err)
	}
	s.epoch, s.init, s.th, s.msgRt = 1, c.Secrets.Init, c.ConfirmedTH, c.Secrets.MsgRoot
	return c.Row
}

// removeCommit builds the next-epoch commit that removes rmIdx, re-keying to the members in keep.
func (s *session) removeCommit(t *testing.T, committer *ident, cidx, rmIdx int, keep map[int]*ident) []byte {
	t.Helper()
	var roster []e2e.Member
	var fan []e2e.Fanout
	for idx, in := range keep {
		roster = append(roster, s.member(idx, in))
		fan = append(fan, e2e.Fanout{Idx: uint16(idx), Key: s.ek(t, in)})
	}
	rh := e2e.RosterHash(roster)
	newE := s.epoch + 1
	c, err := e2e.BuildCommit(e2e.CommitParams{GID: s.gid, CS: e2e.CS1, Epoch: newE, Idx: uint16(cidx), Gen: s.nextGen(cidx), Pol: 3,
		Header: e2e.CommitHeader{Rm: []uint16{uint16(rmIdx)}}, Members: fan, InitPrev: s.init, THPrev: s.th,
		RosterHash: rh, IK: e2e.IK(committer.seed)})
	if err != nil {
		t.Fatal(err)
	}
	delete(s.ids, rmIdx)
	s.epoch, s.init, s.th, s.msgRt = newE, c.Secrets.Init, c.ConfirmedTH, c.Secrets.MsgRoot
	return c.Row
}

// app seals an app message from the member at idx in the current epoch (gen auto-assigned).
func (s *session) app(t *testing.T, idx int, text string) ([]byte, []byte) {
	t.Helper()
	in := s.ids[idx]
	var kf [32]byte
	rand.Read(kf[:])
	a, err := e2e.SealApp(e2e.AppParams{GID: s.gid, Epoch: s.epoch, Idx: uint16(idx), Gen: s.nextGen(idx), Pol: 3,
		KF: kf[:], CType: e2e.CTypeText, Payload: []byte(text), MsgRoot: s.msgRt, IK: e2e.IK(in.seed)})
	if err != nil {
		t.Fatal(err)
	}
	return a.Row, kf[:]
}

func (e *env) create(t *testing.T, who *ident, s *session, commit []byte) (int, string) {
	body, _ := json.Marshal(createIn{CS: 1, Max: 8, TTLD: 30, Commit: b64(commit)})
	st, b, _ := e.signed(t, who, "POST", "/v1/g", body)
	return st, b
}

// --- tests ------------------------------------------------------------------------------------

func TestCreateRosterCommitWelcome(t *testing.T) {
	e := newEnv(t)
	alice, bob, carol := mkIdent(t, 73*time.Hour), mkIdent(t, time.Hour), mkIdent(t, time.Hour)
	s := newSession(t)
	commit := s.createCommit(t, alice, bob, carol)
	st, body := e.create(t, alice, s, commit)
	if st != 201 {
		t.Fatalf("create: %d %s", st, body)
	}
	if kv(body)["g"] != s.gid || kv(body)["epoch"] != "1" {
		t.Fatalf("create reply: %s", body)
	}
	// roster-checked info shows all three members
	st, body, _ = e.signed(t, alice, "GET", "/v1/g/"+s.gid, nil)
	if st != 200 || !strings.Contains(body, "n=3") {
		t.Fatalf("info: %d %s", st, body)
	}
	for _, in := range []*ident{alice, bob, carol} {
		if !strings.Contains(body, in.id) {
			t.Fatalf("roster missing %s: %s", in.id, body)
		}
	}
	if count(t, `SELECT count(*) FROM grp_members WHERE gid = $1`, s.gid) != 3 {
		t.Fatal("expected 3 members")
	}
	// a welcome addressed to carol (a current member) is accepted
	w := buildWelcome(t, s, alice, 1, carol, 3)
	st, body, _ = e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/w", w)
	if st != 200 {
		t.Fatalf("welcome: %d %s", st, body)
	}
	// carol sees it in her invites
	st, body, _ = e.signed(t, carol, "GET", "/v1/g/inv", nil)
	if st != 200 || !strings.Contains(body, s.gid) {
		t.Fatalf("inv: %d %s", st, body)
	}
}

func buildWelcome(t *testing.T, s *session, from *ident, fidx int, to *ident, tidx int) []byte {
	t.Helper()
	var leaves []e2e.RosterLeaf
	for idx, in := range s.ids {
		leaves = append(leaves, e2e.RosterLeaf{Idx: uint16(idx), ID: in.id, Leaf: in.leaf})
	}
	ix := make([]byte, 32)
	gctx := e2e.GroupContext(s.gid, s.epoch, e2e.RosterHash(rosterOf(s)), make([]byte, 32))
	row, err := e2e.BuildWelcome(e2e.WelcomeParams{GID: s.gid, CS: e2e.CS1, Epoch: s.epoch, Idx: uint16(fidx), Gen: s.nextGen(fidx), Pol: 3,
		To: to.id, NewcomerKey: s.ek(t, to), Joiner: s.init, GCtx: gctx, Roster: leaves, IX: ix, IK: e2e.IK(from.seed)})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func rosterOf(s *session) []e2e.Member {
	var ms []e2e.Member
	for idx, in := range s.ids {
		ms = append(ms, e2e.Member{Idx: uint16(idx), ID: in.id, IK: in.b.IK, Leaf: in.leaf})
	}
	return ms
}

func TestRequireSig(t *testing.T) {
	e := newEnv(t)
	alice, bob := mkIdent(t, 73*time.Hour), mkIdent(t, time.Hour)
	s := newSession(t)
	commit := s.createCommit(t, alice, bob)
	// create without a signature is refused
	body, _ := json.Marshal(createIn{CS: 1, Max: 8, TTLD: 30, Commit: b64(commit)})
	if st, b, _ := e.do(t, "POST", "/v1/g", alice.tok, body); st != 401 || !strings.Contains(b, "sig") {
		t.Fatalf("unsigned create: %d %s", st, b)
	}
	// with a signature it works
	if st, b := e.create(t, alice, s, commit); st != 201 {
		t.Fatalf("signed create: %d %s", st, b)
	}
	// an app write without a signature is refused
	row, _ := s.app(t, 1, "hi")
	if st, b, _ := e.do(t, "POST", "/v1/g/"+s.gid+"/m", alice.tok, row); st != 401 {
		t.Fatalf("unsigned app: %d %s", st, b)
	}
}

func TestRosterCheckedReadsWrites(t *testing.T) {
	e := newEnv(t)
	alice, bob, mallory := mkIdent(t, 73*time.Hour), mkIdent(t, time.Hour), mkIdent(t, time.Hour)
	s := newSession(t)
	if st, b := e.create(t, alice, s, s.createCommit(t, alice, bob)); st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	// a non-member cannot read
	if st, b, _ := e.signed(t, mallory, "GET", "/v1/g/"+s.gid, nil); st != 403 {
		t.Fatalf("non-member read: %d %s", st, b)
	}
	if st, b, _ := e.signed(t, mallory, "GET", "/v1/g/"+s.gid+"/m?from=0", nil); st != 403 {
		t.Fatalf("non-member pull: %d %s", st, b)
	}
	// a member can read
	if st, b, _ := e.signed(t, bob, "GET", "/v1/g/"+s.gid, nil); st != 200 {
		t.Fatalf("member read: %d %s", st, b)
	}
	// a non-member cannot write an app row (its idx is not in the roster)
	row, _ := s.app(t, 2, "x")
	if st, b, _ := e.signed(t, mallory, "POST", "/v1/g/"+s.gid+"/m", row); st != 403 {
		t.Fatalf("non-member write: %d %s", st, b)
	}
}

func TestEpochAdvanceOnMembershipChange(t *testing.T) {
	e := newEnv(t)
	alice, bob, carol := mkIdent(t, 73*time.Hour), mkIdent(t, time.Hour), mkIdent(t, time.Hour)
	s := newSession(t)
	if st, b := e.create(t, alice, s, s.createCommit(t, alice, bob, carol)); st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	// a commit removing carol advances the epoch 1 -> 2
	rc := s.removeCommit(t, alice, 1, 3, map[int]*ident{1: alice, 2: bob})
	st, body, _ := e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/c", rc)
	if st != 200 || kv(body)["epoch"] != "2" {
		t.Fatalf("commit: %d %s", st, body)
	}
	if count(t, `SELECT epoch FROM grp WHERE id = $1`, s.gid) != 2 {
		t.Fatal("epoch did not advance")
	}
	// replaying the same commit is stale (the CAS already moved)
	if st, body, _ := e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/c", rc); st != 409 || !strings.Contains(body, "stale") {
		t.Fatalf("stale replay: %d %s", st, body)
	}
}

func TestServerOriginatedRemovalPending(t *testing.T) {
	e := newEnv(t)
	alice, bob := mkIdent(t, 73*time.Hour), mkIdent(t, time.Hour)
	s := newSession(t)
	if st, b := e.create(t, alice, s, s.createCommit(t, alice, bob)); st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	// bob leaves: a server-originated removal proposal, bob dropped from the roster at once
	st, body, _ := e.signed(t, bob, "POST", "/v1/g/"+s.gid+"/leave", nil)
	if st != 200 {
		t.Fatalf("leave: %d %s", st, body)
	}
	if count(t, `SELECT count(*) FROM grp_members WHERE gid = $1 AND id = $2`, s.gid, bob.id) != 0 {
		t.Fatal("bob should be gone from the roster")
	}
	if count(t, `SELECT pending FROM grp WHERE id = $1`, s.gid) != 1 {
		t.Fatal("pending gate not raised")
	}
	// alice's app writes are refused until a commit covers the pending proposal
	row, _ := s.app(t, 1, "blocked")
	if st, body, _ := e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/m", row); st != 409 || !strings.Contains(body, "pending") {
		t.Fatalf("app not blocked: %d %s", st, body)
	}
	// alice lands a commit that covers the pending proposal (pp = the proposal's seq)
	var pseq uint64
	if err := pool.QueryRow(context.Background(), `SELECT pseq FROM grp_pending WHERE gid = $1`, s.gid).Scan(&pseq); err != nil {
		t.Fatal(err)
	}
	rc := s.coverCommit(t, alice, 1, map[int]*ident{1: alice}, []uint64{pseq})
	if st, body, _ := e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/c", rc); st != 200 {
		t.Fatalf("covering commit: %d %s", st, body)
	}
	if count(t, `SELECT pending FROM grp WHERE id = $1`, s.gid) != 0 {
		t.Fatal("pending not cleared")
	}
	// now app writes flow again
	row, _ = s.app(t, 1, "unblocked")
	if st, body, _ := e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/m", row); st != 200 {
		t.Fatalf("app still blocked: %d %s", st, body)
	}
}

// coverCommit is an update commit (no membership change of its own) whose pp covers the open
// server-originated proposals, re-keying to the members in keep.
func (s *session) coverCommit(t *testing.T, committer *ident, cidx int, keep map[int]*ident, pp []uint64) []byte {
	t.Helper()
	var roster []e2e.Member
	var fan []e2e.Fanout
	for idx, in := range keep {
		roster = append(roster, s.member(idx, in))
		fan = append(fan, e2e.Fanout{Idx: uint16(idx), Key: s.ek(t, in)})
	}
	newE := s.epoch + 1
	c, err := e2e.BuildCommit(e2e.CommitParams{GID: s.gid, CS: e2e.CS1, Epoch: newE, Idx: uint16(cidx), Gen: s.nextGen(cidx), Pol: 3,
		Header: e2e.CommitHeader{Upd: true, PP: pp}, Members: fan, InitPrev: s.init, THPrev: s.th,
		RosterHash: e2e.RosterHash(roster), IK: e2e.IK(committer.seed)})
	if err != nil {
		t.Fatal(err)
	}
	s.epoch, s.init, s.th, s.msgRt = newE, c.Secrets.Init, c.ConfirmedTH, c.Secrets.MsgRoot
	return c.Row
}

func TestGroupFrankReportByFormerMember(t *testing.T) {
	e := newEnv(t)
	alice, bob := mkIdent(t, 73*time.Hour), mkIdent(t, time.Hour)
	s := newSession(t)
	if st, b := e.create(t, alice, s, s.createCommit(t, alice, bob)); st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	// bob sends an app message carrying a secret-looking payload
	payload := "here is a token cx_" + strings.Repeat("A", 43)
	row, kf := s.app(t, 2, payload)
	st, body, _ := e.signed(t, bob, "POST", "/v1/g/"+s.gid+"/m", row)
	if st != 200 {
		t.Fatalf("app: %d %s", st, body)
	}
	seq := kv(body)["seq"]
	// bob is then removed by alice (becomes a former member)
	rc := s.removeCommit(t, alice, 1, 2, map[int]*ident{1: alice})
	if st, b, _ := e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/c", rc); st != 200 {
		t.Fatalf("remove bob: %d %s", st, b)
	}
	if count(t, `SELECT count(*) FROM grp_members_tomb WHERE gid = $1 AND id = $2`, s.gid, bob.id) == 0 {
		t.Fatal("bob not tombstoned")
	}
	// the former member reports the message by revealing kf and the plaintext; the server verifies
	// the franking and opens exactly that message.
	rep, _ := json.Marshal(map[string]any{"seq": mustInt(seq), "kf": b64(kf), "ctype": e2e.CTypeText, "payload": b64([]byte(payload))})
	st, body, _ = e.signed(t, bob, "POST", "/v1/g/"+s.gid+"/report", rep)
	if st != 200 || !strings.Contains(body, "franking-verified") || !strings.Contains(body, "upheld") {
		t.Fatalf("report: %d %s", st, body)
	}
	if count(t, `SELECT count(*) FROM grp_evidence WHERE gid = $1 AND upheld`, s.gid) != 1 {
		t.Fatal("no upheld evidence stored")
	}
	// a wrong key does not open the message
	var bad [32]byte
	rand.Read(bad[:])
	rep, _ = json.Marshal(map[string]any{"seq": mustInt(seq), "kf": b64(bad[:]), "ctype": e2e.CTypeText, "payload": b64([]byte(payload))})
	if st, body, _ := e.signed(t, bob, "POST", "/v1/g/"+s.gid+"/report", rep); st != 400 || !strings.Contains(body, "frank") {
		t.Fatalf("bad reveal accepted: %d %s", st, body)
	}
}

func mustInt(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }

func TestStateCASSnapshots(t *testing.T) {
	e := newEnv(t)
	alice, bob := mkIdent(t, 73*time.Hour), mkIdent(t, time.Hour)
	s := newSession(t)
	if st, b := e.create(t, alice, s, s.createCommit(t, alice, bob)); st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	blob := []byte("seal1:" + strings.Repeat("a", 40))
	// first write at ver 0
	st, body, _ := e.signed(t, alice, "PUT", "/v1/g/"+s.gid+"/state", blob, "If-Match", "0")
	if st != 200 || kv(body)["ver"] != "1" {
		t.Fatalf("state put: %d %s", st, body)
	}
	// a stale ver is a CAS conflict
	if st, body, _ := e.signed(t, bob, "PUT", "/v1/g/"+s.gid+"/state", blob, "If-Match", "0"); st != 409 {
		t.Fatalf("stale put accepted: %d %s", st, body)
	}
	// the right ver succeeds
	if st, body, _ := e.signed(t, bob, "PUT", "/v1/g/"+s.gid+"/state", []byte("seal1:"+strings.Repeat("b", 40)), "If-Match", "1"); st != 200 || kv(body)["ver"] != "2" {
		t.Fatalf("cas put: %d %s", st, body)
	}
	// read it back
	if st, body, _ := e.signed(t, alice, "GET", "/v1/g/"+s.gid+"/state", nil); st != 200 || !strings.Contains(body, "ver=2") {
		t.Fatalf("state get: %d %s", st, body)
	}
	// snapshot store and fetch
	snap, _ := json.Marshal(map[string]any{"ver": 2, "blob": b64([]byte("snapshot-blob"))})
	if st, body, _ := e.signed(t, alice, "PUT", "/v1/g/"+s.gid+"/snapshot", snap); st != 200 {
		t.Fatalf("snapshot put: %d %s", st, body)
	}
	if st, body, _ := e.signed(t, bob, "GET", "/v1/g/"+s.gid+"/snapshot", nil); st != 200 || !strings.Contains(body, "ver=2") {
		t.Fatalf("snapshot get: %d %s", st, body)
	}
}

func TestOpaqueNameLocks(t *testing.T) {
	e := newEnv(t)
	alice, bob := mkIdent(t, 73*time.Hour), mkIdent(t, time.Hour)
	s := newSession(t)
	if st, b := e.create(t, alice, s, s.createCommit(t, alice, bob)); st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	k := "deadbeefcafe0001"
	// alice takes a group-scoped lock
	st, body, _ := e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/lock", []byte(`{"k":"`+k+`","ttl":300}`))
	if st != 200 || kv(body)["fence"] != "1" {
		t.Fatalf("lock: %d %s", st, body)
	}
	// bob cannot take the same held lock
	if st, body, _ := e.signed(t, bob, "POST", "/v1/g/"+s.gid+"/lock", []byte(`{"k":"`+k+`","ttl":300}`)); st != 409 {
		t.Fatalf("contended lock accepted: %d %s", st, body)
	}
	// leader election: alice leads, bob is told otherwise
	lk := "00ff00ff00ff00ff"
	if st, body, _ := e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/lead", []byte(`{"k":"`+lk+`"}`)); st != 200 || !strings.Contains(body, "leader=self") {
		t.Fatalf("lead alice: %d %s", st, body)
	}
	if st, body, _ := e.signed(t, bob, "POST", "/v1/g/"+s.gid+"/lead", []byte(`{"k":"`+lk+`"}`)); st != 200 || !strings.Contains(body, "leader=other") {
		t.Fatalf("lead bob: %d %s", st, body)
	}
	// barrier of 2 trips when both members arrive
	bk := "aabbccddaabbccdd"
	if st, body, _ := e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/barrier", []byte(`{"k":"`+bk+`","n":2}`)); st != 200 || strings.Contains(body, "tripped") {
		t.Fatalf("barrier alice: %d %s", st, body)
	}
	if st, body, _ := e.signed(t, bob, "POST", "/v1/g/"+s.gid+"/barrier", []byte(`{"k":"`+bk+`","n":2}`)); st != 200 || !strings.Contains(body, "tripped") {
		t.Fatalf("barrier bob: %d %s", st, body)
	}
}

func TestIdleExpiryAndDeletability(t *testing.T) {
	e := newEnv(t)
	alice, bob := mkIdent(t, 73*time.Hour), mkIdent(t, time.Hour)
	s := newSession(t)
	if st, b := e.create(t, alice, s, s.createCommit(t, alice, bob)); st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	// idle expiry: a group idle > 90 d is swept by the janitor (cascade)
	s2 := newSession(t)
	if st, b := e.create(t, alice, s2, s2.createCommit(t, alice, bob)); st != 201 {
		t.Fatalf("create 2: %d %s", st, b)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE grp SET idle = now() - make_interval(days => 120) WHERE id = $1`, s2.gid); err != nil {
		t.Fatal(err)
	}
	if err := Janitor(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	if count(t, `SELECT count(*) FROM grp WHERE id = $1`, s2.gid) != 0 {
		t.Fatal("idle group not expired")
	}
	if count(t, `SELECT count(*) FROM grp WHERE id = $1`, s.gid) != 1 {
		t.Fatal("fresh group should survive")
	}
	// full deletability: the creator deletes the live group and everything cascades
	if st, body, _ := e.signed(t, alice, "DELETE", "/v1/g/"+s.gid, nil); st != 200 {
		t.Fatalf("delete: %d %s", st, body)
	}
	if count(t, `SELECT count(*) FROM grp WHERE id = $1`, s.gid) != 0 {
		t.Fatal("group not deleted")
	}
	if count(t, `SELECT count(*) FROM grp_members WHERE gid = $1`, s.gid) != 0 {
		t.Fatal("roster did not cascade")
	}
	// a non-creator cannot delete
	s3 := newSession(t)
	e.create(t, alice, s3, s3.createCommit(t, alice, bob))
	if st, body, _ := e.signed(t, bob, "DELETE", "/v1/g/"+s3.gid, nil); st != 403 {
		t.Fatalf("non-creator delete: %d %s", st, body)
	}
}

// TestSealedAppExchangeRemovedMemberCannotReadNewEpochs is the vector of the acceptance list: two
// members exchange a sealed app message through /v1/g, and a third, removed member can no longer read
// new epochs — enforced at the access layer (403) and by the key schedule (no new epoch secret).
func TestSealedAppExchangeRemovedMemberCannotReadNewEpochs(t *testing.T) {
	e := newEnv(t)
	alice, bob, carol := mkIdent(t, 73*time.Hour), mkIdent(t, time.Hour), mkIdent(t, time.Hour)
	s := newSession(t)
	if st, b := e.create(t, alice, s, s.createCommit(t, alice, bob, carol)); st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	// epoch 1: alice sends, bob and carol can both open it
	row1, _ := s.app(t, 1, "hello epoch 1")
	msgRt1 := append([]byte(nil), s.msgRt...)
	if st, b, _ := e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/m", row1); st != 200 {
		t.Fatalf("app1: %d %s", st, b)
	}
	// bob pulls and opens the epoch-1 message
	body := pullOne(t, e, bob, s.gid)
	if in, err := openRow(body, msgRt1); err != nil || string(in.Payload) != "hello epoch 1" {
		t.Fatalf("bob open epoch1: %v", err)
	}
	// remove carol: epoch advances to 2, re-keyed to alice and bob only
	rc := s.removeCommit(t, alice, 1, 3, map[int]*ident{1: alice, 2: bob})
	if st, b, _ := e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/c", rc); st != 200 {
		t.Fatalf("remove carol: %d %s", st, b)
	}
	// epoch 2: alice sends a message bob can open
	row2, _ := s.app(t, 1, "secret epoch 2")
	msgRt2 := append([]byte(nil), s.msgRt...)
	if st, b, _ := e.signed(t, alice, "POST", "/v1/g/"+s.gid+"/m", row2); st != 200 {
		t.Fatalf("app2: %d %s", st, b)
	}
	body = pullAll(t, e, bob, s.gid)
	if !opensSomewhere(body, msgRt2, "secret epoch 2") {
		t.Fatal("bob could not open the epoch-2 message")
	}
	// carol, removed, can no longer read the group at all (roster-checked)
	if st, b, _ := e.signed(t, carol, "GET", "/v1/g/"+s.gid+"/m?from=0", nil); st != 403 {
		t.Fatalf("removed carol still reads: %d %s", st, b)
	}
	// and the epoch-2 msg_root is not derivable by carol (she was not in the commit's envelopes):
	// the server even refuses her the ciphertext, so confidentiality holds on both layers.
	if count(t, `SELECT count(*) FROM grp_members WHERE gid = $1 AND id = $2`, s.gid, carol.id) != 0 {
		t.Fatal("carol should not be a member")
	}
}

func pullOne(t *testing.T, e *env, who *ident, gid string) string {
	t.Helper()
	st, body, _ := e.signed(t, who, "GET", "/v1/g/"+gid+"/m?from=0", nil)
	if st != 200 {
		t.Fatalf("pull: %d %s", st, body)
	}
	return body
}

func pullAll(t *testing.T, e *env, who *ident, gid string) string { return pullOne(t, e, who, gid) }

// openRow opens the last app row in a pull body with msgRoot.
func openRow(body string, msgRoot []byte) (*e2e.AppInner, error) {
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || f[2] != "1" {
			continue
		}
		raw, err := decodeB64(f[6])
		if err != nil {
			continue
		}
		m, err := e2e.ParseApp(raw)
		if err != nil {
			continue
		}
		if in, err := m.Open(msgRoot); err == nil {
			return in, nil
		}
	}
	return nil, fmt.Errorf("no app row opened")
}

func opensSomewhere(body string, msgRoot []byte, want string) bool {
	in, err := openRow(body, msgRoot)
	return err == nil && string(in.Payload) == want
}
