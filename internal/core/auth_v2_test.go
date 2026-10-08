package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/pow"
)

// newAuthEnv is newEnv with config tweaks and extra routes; the hourly global registration cap is
// lifted so registration-heavy tests never trip it.
func newAuthEnv(t *testing.T, mod func(*Config), routes func(*http.ServeMux, *Deps)) *tenv {
	t.Helper()
	cfg := Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	if mod != nil {
		mod(&cfg)
	}
	d, err := NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	mux := http.NewServeMux()
	Register(mux, d)
	RegisterAuthV2(mux, d)
	if routes != nil {
		routes(mux, d)
	}
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	var b [3]byte
	rand.Read(b[:])
	return &tenv{d, srv, fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])}
}

// registerFull registers and returns the whole parsed reply (id, token, recovery, …).
func (e *tenv) registerFull(t *testing.T, name string, hdr ...string) map[string]string {
	t.Helper()
	c, nonce := e.challenge(t, hdr...)
	st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": name}, hdr...)
	if st != 201 {
		t.Fatalf("register: %d %s", st, body)
	}
	return kv(body)
}

func (e *tenv) subkeyV2(t *testing.T, parentTok string, scopes []string) (id, tok string) {
	t.Helper()
	ctx := context.Background()
	parent, err := e.d.LookupToken(ctx, parentTok)
	if err != nil {
		t.Fatal(err)
	}
	if err := Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
		id, tok, err = CreateSubkeyV2(ctx, tx, parent, SubkeyOpts{Name: "s", Exp: time.Now().Add(time.Hour), Scopes: scopes})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id, tok
}

func TestAdaptivePowCurve(t *testing.T) {
	for _, tc := range []struct{ base, group, hour, per, want int }{
		{6, 0, 0, 300, 6}, {6, 3, 0, 300, 6}, {6, 4, 0, 300, 7}, {6, 8, 0, 300, 8}, {6, 0, 100, 300, 6}, {6, 0, 101, 300, 8},
		{6, 0, 201, 300, 10}, {22, 4, 0, 300, 23}, {29, 8, 201, 300, 30}, {6, 0, 101, 1 << 20, 6},
	} {
		if got := regBitsFor(tc.base, tc.group, tc.hour, tc.per); got != tc.want {
			t.Errorf("regBitsFor(%d,%d,%d,%d)=%d want %d", tc.base, tc.group, tc.hour, tc.per, got, tc.want)
		}
	}
	e := newAuthEnv(t, nil, nil)
	ctx := context.Background()
	group := "198.18.7.9"
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM reg_ips WHERE ip = $1`, group) })
	base, err := e.d.RegBits(ctx, group)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		testPool.Exec(ctx, `INSERT INTO reg_ips (ip, super) VALUES ($1, $2)`, group, IPSuper(group))
	}
	got, _ := e.d.RegBits(ctx, group)
	if got != base+1 {
		t.Fatalf("4 registrations: bits %d -> %d", base, got)
	}
	// The challenge announces the live curve and its nonce must satisfy those bits, not Cfg.PowBits.
	_, body := e.do(t, "POST", "/v1/challenge", "", nil, "CF-Connecting-IP", group)
	m := kv(body)
	if m["bits"] != strconv.Itoa(got) || m["for"] != "reg" {
		t.Fatalf("challenge: %s (want bits=%d)", body, got)
	}
	c := m["c"]
	weak := pow.Solve(c, e.d.Cfg.PowBits)
	if pow.LeadingZeros(c, weak) < got {
		if st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": weak, "name": "curve"}, "CF-Connecting-IP", group); st != 400 || body != "err pow bad proof of work" {
			t.Fatalf("weak nonce accepted: %d %s", st, body)
		}
	}
	if st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": pow.Solve(c, got), "name": "curve"}, "CF-Connecting-IP", group); st != 201 {
		t.Fatalf("strong nonce: %d %s", st, body)
	}
}

func TestChallengePurposeMismatch(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	st, body, h := e.doH(t, "POST", "/v1/challenge?for=w", "", "")
	m := kv(body)
	if st != 200 || m["bits"] != "16" || m["for"] != "w" || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("for=w: %d %s %v", st, body, h)
	}
	c := m["c"]
	st, body = e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": pow.Solve(c, 16), "name": "wrongpurpose"})
	if st != 400 || !strings.HasPrefix(body, "err pow challenge purpose w, need reg") {
		t.Fatalf("w challenge at register: %d %s", st, body)
	}
	// GET is allowed, same reply shape, never cached.
	st, body, h = e.doH(t, "GET", "/v1/challenge", "", "")
	if st != 200 || kv(body)["for"] != "reg" || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("GET challenge: %d %s %v", st, body, h)
	}
	if st, body := e.do(t, "POST", "/v1/challenge?for=x", "", nil); st != 400 || !strings.HasPrefix(body, "err bad for must be") {
		t.Fatalf("bad for: %d %s", st, body)
	}
	// A v1-style forged challenge is still refused.
	if st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": "AAAA", "nonce": "1", "name": "x"}); st != 400 || !strings.HasPrefix(body, "err pow") {
		t.Fatalf("forged: %d %s", st, body)
	}
}

func TestSuperGroupRegCaps(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	ctx := context.Background()
	var b [2]byte
	rand.Read(b[:])
	pfx := fmt.Sprintf("2001:db8:%x%x:", b[0], b[1])
	for i := 0; i < regPerSuper; i++ {
		if st, body := e.registerIP(t, fmt.Sprintf("%s%x::1", pfx, i+1), "sg"); st != 201 || kv(body)["credits"] != "100" {
			t.Fatalf("reg %d in /48: %d %s", i, st, body)
		}
	}
	if st, body := e.registerIP(t, pfx+"ffff::1", "sg"); st != 429 || body != "err quota registrations super-group" {
		t.Fatalf("21st in /48: %d %s", st, body)
	}
	var n int
	testPool.QueryRow(ctx, `SELECT n FROM reg_supers WHERE super = $1 AND day = current_date`, IPSuper(pfx+"1::1")).Scan(&n)
	if n != regPerSuper {
		t.Fatalf("reg_supers n=%d (refused registration must not count)", n)
	}
	// Another /48 is unaffected.
	if st, body := e.registerIP(t, fmt.Sprintf("2001:db8:%x%x:1::1", b[1], b[0]^0xff), "sg"); st != 201 {
		t.Fatalf("other /48: %d %s", st, body)
	}
	// Hourly: at most 10 % of REG_PER_HOUR per super-group per hour.
	var hour int
	testPool.QueryRow(ctx, `SELECT count(*) FROM reg_ips WHERE at > now() - interval '1 hour'`).Scan(&hour)
	k := hour/10 + 5
	super := "198.18.9.0/24"
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM reg_ips WHERE super = $1`, super) })
	for i := 0; i < k; i++ {
		testPool.Exec(ctx, `INSERT INTO reg_ips (ip, super) VALUES ($1, $2)`, fmt.Sprintf("synthetic-%d", i), super)
	}
	e.d.Cfg.RegPerHour = 10 * k
	if st, body := e.registerIP(t, "198.18.9.77", "sg"); st != 429 || body != "err quota registrations super-group" {
		t.Fatalf("hourly super cap: %d %s", st, body)
	}
}

const edgeSecret = "edge-s3cret-0123456789"

func asnEnv(t *testing.T, trust bool) *tenv {
	t.Helper()
	return newAuthEnv(t, func(c *Config) { c.TrustASN, c.EdgeSecret = trust, edgeSecret }, nil)
}

func setASN(t *testing.T, asn int64, class string) {
	t.Helper()
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `INSERT INTO asn_policy (asn, class, note) VALUES ($1, $2, 'test') ON CONFLICT (asn) DO UPDATE SET class = EXCLUDED.class`, asn, class); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM asn_policy WHERE asn = $1`, asn) })
}

func TestASNIgnoredWithoutEdgeSecret(t *testing.T) {
	setASN(t, 64512, "blocked")
	e := asnEnv(t, true)
	ctx := context.Background()
	for _, hdr := range [][]string{{"X-ASN", "64512"}, {"X-ASN", "64512", "X-CX-Edge", "wrong"}} {
		m := e.registerFull(t, "noedge", append([]string{"CF-Connecting-IP", e.ip}, hdr...)...)
		var asn int64
		var class string
		testPool.QueryRow(ctx, `SELECT asn, ip_class FROM identities WHERE id = $1`, m["id"]).Scan(&asn, &class)
		if asn != 0 || class != "" {
			t.Fatalf("untrusted header recorded: asn=%d class=%q", asn, class)
		}
	}
	// TRUST_ASN=0: even the right companion header changes nothing.
	e2 := asnEnv(t, false)
	m := e2.registerFull(t, "notrust", "CF-Connecting-IP", e2.ip, "X-ASN", "64512", "X-CX-Edge", edgeSecret)
	var asn int64
	testPool.QueryRow(ctx, `SELECT asn FROM identities WHERE id = $1`, m["id"]).Scan(&asn)
	if asn != 0 {
		t.Fatalf("TRUST_ASN=0 recorded asn %d", asn)
	}
}

func TestASNBlocked(t *testing.T) {
	setASN(t, 64512, "blocked")
	e := asnEnv(t, true)
	c, nonce := e.challenge(t)
	st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "blocked"}, "X-ASN", "64512", "X-CX-Edge", edgeSecret)
	if st != 429 || body != "err quota asn" {
		t.Fatalf("blocked asn: %d %s", st, body)
	}
	var n int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM identities WHERE name = 'blocked'`).Scan(&n)
	if n != 0 {
		t.Fatal("blocked registration created an identity")
	}
}

func TestAsnRecordedWhenTrusted(t *testing.T) {
	e := asnEnv(t, true)
	ctx := context.Background()
	t.Cleanup(func() {
		testPool.Exec(ctx, `DELETE FROM reg_asn WHERE asn IN (64513, 64514, 64515); DELETE FROM asn_policy WHERE asn = 64515`)
	})
	m := e.registerFull(t, "asn", "CF-Connecting-IP", e.ip, "X-ASN", "64513", "X-CX-Edge", edgeSecret)
	var asn int64
	var n int
	testPool.QueryRow(ctx, `SELECT asn FROM identities WHERE id = $1`, m["id"]).Scan(&asn)
	testPool.QueryRow(ctx, `SELECT n FROM reg_asn WHERE asn = 64513 AND day = current_date`).Scan(&n)
	if asn != 64513 || n != 1 {
		t.Fatalf("asn=%d reg_asn=%d", asn, n)
	}
	if _, body := e.do(t, "GET", "/v1/me", m["token"], nil); !strings.Contains(body, " net=asn:64513") || !strings.Contains(body, " ipclass=unknown") {
		t.Fatalf("me: %s", body)
	}
	// Hosting: ip_class recorded, 200/day per ASN, 50/day per group.
	setASN(t, 64514, "hosting")
	m = e.registerFull(t, "host", "CF-Connecting-IP", "198.18.20.1", "X-ASN", "64514", "X-CX-Edge", edgeSecret)
	if _, body := e.do(t, "GET", "/v1/me", m["token"], nil); !strings.Contains(body, " ipclass=hosting") {
		t.Fatalf("hosting me: %s", body)
	}
	testPool.Exec(ctx, `UPDATE reg_asn SET n = $1 WHERE asn = 64514 AND day = current_date`, regASNDaily)
	c, nonce := e.challenge(t, "CF-Connecting-IP", "198.18.20.2")
	if st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "host"}, "CF-Connecting-IP", "198.18.20.2", "X-ASN", "64514", "X-CX-Edge", edgeSecret); st != 429 || body != "err quota asn hosting" {
		t.Fatalf("hosting daily cap: %d %s", st, body)
	}
	group := "198.18.21.5"
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM reg_ips WHERE ip = $1`, group) })
	for i := 0; i < regHostingCap; i++ {
		testPool.Exec(ctx, `INSERT INTO reg_ips (ip, super) VALUES ($1, $2)`, group, IPSuper(group))
	}
	testPool.Exec(ctx, `UPDATE reg_asn SET n = 1 WHERE asn = 64514 AND day = current_date`)
	c, nonce = e.challenge(t, "CF-Connecting-IP", group)
	if st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "host"}, "CF-Connecting-IP", group, "X-ASN", "64514", "X-CX-Edge", edgeSecret); st != 429 || body != "err quota registrations per ip per day" {
		t.Fatalf("hosting group ceiling: %d %s", st, body)
	}
	// Auto-classification: >= 20 registrations from >= 10 distinct /48 within the ASN's first day.
	var b [2]byte
	rand.Read(b[:])
	for i := 0; i < 20; i++ {
		ip := fmt.Sprintf("2001:db8:%x%x%x::%x", b[0], b[1], i%12, i+1)
		if st, body := e.doRegisterASN(t, ip, 64515); st != 201 {
			t.Fatalf("auto reg %d: %d %s", i, st, body)
		}
	}
	var class, note string
	if err := testPool.QueryRow(ctx, `SELECT class, note FROM asn_policy WHERE asn = 64515`).Scan(&class, &note); err != nil || class != "hosting" || note != "auto" {
		t.Fatalf("auto-classification: %v %s %s", err, class, note)
	}
	var ev int
	testPool.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind = 'ops' AND ref = 'asn:64515'`).Scan(&ev)
	if ev != 1 {
		t.Fatalf("summary event rows: %d", ev)
	}
}

func (e *tenv) doRegisterASN(t *testing.T, ip string, asn int64) (int, string) {
	t.Helper()
	c, nonce := e.challenge(t, "CF-Connecting-IP", ip)
	return e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "auto"}, "CF-Connecting-IP", ip, "X-ASN", strconv.FormatInt(asn, 10), "X-CX-Edge", edgeSecret)
}

func TestCohortSet(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	ip := "2001:db8:77:88:1:2:3:4"
	m := e.registerFull(t, "cohort", "CF-Connecting-IP", ip)
	var cohort string
	var bucket int64
	if err := testPool.QueryRow(context.Background(), `SELECT cohort, floor(extract(epoch from created) / 600)::bigint FROM identities WHERE id = $1`, m["id"]).Scan(&cohort, &bucket); err != nil {
		t.Fatal(err)
	}
	if want := IPGroup(ip) + "|" + strconv.FormatInt(bucket, 10); cohort != want {
		t.Fatalf("cohort %q want %q", cohort, want)
	}
}

func TestEstablishedNeedsAge(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		id   Ident
		want bool
	}{
		{Ident{Rep: 5, Created: now}, false},
		{Ident{Rep: 5, Created: now.Add(-71 * time.Hour)}, false},
		{Ident{Rep: 5, Created: now.Add(-73 * time.Hour)}, true},
		{Ident{Rep: 4, Created: now.Add(-100 * time.Hour)}, false},
		{Ident{Rep: 0, Created: now, Seed: true}, true},
		{Ident{Rep: 5}, true}, // zero Created counts as ancient (v1 literals)
	} {
		if got := tc.id.Established(); got != tc.want {
			t.Errorf("Established(%+v)=%v want %v", tc.id, got, tc.want)
		}
	}
	// Through the DB: a fresh rep-5 root is not established; an old one is; Limit follows.
	e := newAuthEnv(t, nil, nil)
	ctx := context.Background()
	root, tok := e.register(t, "age")
	testPool.Exec(ctx, `UPDATE identities SET rep = 5 WHERE id = $1`, root)
	id, _ := e.d.LookupToken(ctx, tok)
	if id.Established() || Limit(id, 10) != 10 || id.Age() > time.Minute {
		t.Fatalf("fresh root established: %+v", id)
	}
	testPool.Exec(ctx, `UPDATE identities SET created = now() - interval '4 days' WHERE id = $1`, root)
	if id, _ = e.d.LookupToken(ctx, tok); !id.Established() || Limit(id, 10) != 50 {
		t.Fatalf("aged root not established: %+v", id)
	}
}

func TestScopesSubsetAndCheck(t *testing.T) {
	e := newAuthEnv(t, nil, func(mux *http.ServeMux, d *Deps) {
		h := func(w http.ResponseWriter, r *http.Request) {
			if _, err := d.Auth(r); err != nil {
				Fail(w, r, err)
				return
			}
			OK(w, r, "ok", nil)
		}
		mux.HandleFunc("GET /v1/zz-unregistered", h)
		mux.HandleFunc("GET /v1/zz-star", h)
		mux.HandleFunc("GET /v1/zz-kb", h)
		d.RegisterScope("GET /v1/zz-star", "*")
		d.RegisterScope("GET /v1/zz-kb", "kb:r")
	})
	ctx := context.Background()
	_, rtok := e.register(t, "scoper")
	_, stok := e.subkeyV2(t, rtok, []string{"kv:proj*", "kb:r"})
	sid, err := e.d.LookupToken(ctx, stok)
	if err != nil || strings.Join(sid.Scopes, ",") != "kb:r,kv:proj*" || sid.Class != "scoped" {
		t.Fatalf("scoped ident: %+v %v", sid, err)
	}
	try := func(parent *Ident, scopes []string) error {
		return Tx(ctx, testPool, func(tx pgx.Tx) error {
			_, _, err := CreateSubkeyV2(ctx, tx, parent, SubkeyOpts{Name: "c", Exp: time.Now().Add(time.Hour), Scopes: scopes})
			return err
		})
	}
	for _, widen := range [][]string{{"kb:w"}, {"kv:*"}, {"kv:other"}, {"kb:r", "sub"}} {
		if err := try(sid, widen); err == nil || err.Error() != "err bad scope widening" {
			t.Fatalf("widening %v: %v", widen, err)
		}
	}
	if err := try(sid, []string{"kv:projx", "kb:r"}); err != nil {
		t.Fatalf("narrowing: %v", err)
	}
	if err := try(sid, []string{"bogus"}); err == nil || err.Error() != "err bad unknown scope" {
		t.Fatalf("unknown scope: %v", err)
	}
	// nil scopes inherit the parent's set (never widen to full).
	var inheritedTok string
	if err := Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
		_, inheritedTok, err = CreateSubkeyV2(ctx, tx, sid, SubkeyOpts{Name: "c", Exp: time.Now().Add(time.Hour)})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if inh, err := e.d.LookupToken(ctx, inheritedTok); err != nil || strings.Join(inh.Scopes, ",") != "kb:r,kv:proj*" || inh.Class != "scoped" {
		t.Fatalf("inherited scopes %+v %v", inh, err)
	}
	// Route checks (3.5): registered scope must be held; unregistered routes need a full token.
	if st, body := e.do(t, "GET", "/v1/me", stok, nil); st != 403 || body != "err scope me:r" {
		t.Fatalf("scoped me: %d %s", st, body)
	}
	if st, body := e.do(t, "GET", "/v1/zz-kb", stok, nil); st != 200 {
		t.Fatalf("held scope: %d %s", st, body)
	}
	if st, body := e.do(t, "GET", "/v1/zz-unregistered", stok, nil); st != 403 || body != "err scope full" {
		t.Fatalf("unregistered route: %d %s", st, body)
	}
	if st, _ := e.do(t, "GET", "/v1/zz-star", stok, nil); st != 200 {
		t.Fatal("star route refused a scoped token")
	}
	if st, _ := e.do(t, "GET", "/v1/zz-unregistered", rtok, nil); st != 200 {
		t.Fatal("full token refused on an unregistered route")
	}
	if st, _ := e.do(t, "POST", "/v1/subkey", stok, map[string]any{}); st != 403 {
		t.Fatal("scoped token without sub minted a subkey")
	}
	// HTTP minting with scopes shows them; a scoped token holding sub can mint narrower ones.
	st, body := e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"scopes": []string{"sub", "me:r"}})
	if st != 201 || !strings.Contains(body, " scopes=me:r,sub class=scoped") {
		t.Fatalf("subkey with scopes: %d %s", st, body)
	}
	mtok := kv(body)["token"]
	if st, body := e.do(t, "GET", "/v1/me", mtok, nil); st != 200 || !strings.Contains(body, " scopes=me:r,sub class=scoped") {
		t.Fatalf("scoped me: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/subkey", mtok, map[string]any{"scopes": []string{"me:r"}}); st != 201 {
		t.Fatalf("narrow mint: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/subkey", mtok, map[string]any{"scopes": []string{"kb:w"}}); st != 400 || body != "err bad scope widening" {
		t.Fatalf("http widening: %d %s", st, body)
	}
}

func TestRotateRecoverRevokeAll(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	ctx := context.Background()
	m := e.registerFull(t, "lifecycle")
	root, tok, rec := m["id"], m["token"], m["recovery"]
	_, body := e.do(t, "POST", "/v1/subkey", tok, map[string]any{"credits": 7})
	s1 := kv(body)
	// Rotate: the new token works, the old one for 60 s, subkeys untouched.
	st, body := e.do(t, "POST", "/v1/rotate", tok, nil)
	if st != 200 || kv(body)["id"] != root || kv(body)["rotated"] != "1" {
		t.Fatalf("rotate: %d %s", st, body)
	}
	tok2 := kv(body)["token"]
	if st, _ := e.do(t, "GET", "/v1/me", tok2, nil); st != 200 {
		t.Fatal("new token refused")
	}
	if st, _ := e.do(t, "GET", "/v1/me", tok, nil); st != 200 {
		t.Fatal("old token refused inside the 60 s window")
	}
	testPool.Exec(ctx, `UPDATE identities SET rotated_at = now() - interval '61 seconds' WHERE id = $1`, root)
	if st, _ := e.do(t, "GET", "/v1/me", tok, nil); st != 401 {
		t.Fatal("old token honoured after 60 s")
	}
	if st, _ := e.do(t, "GET", "/v1/me", s1["token"], nil); st != 200 {
		t.Fatal("subkey died on rotate")
	}
	// A subkey rotates only itself.
	st, body = e.do(t, "POST", "/v1/rotate", s1["token"], nil)
	if st != 200 || kv(body)["id"] != s1["id"] {
		t.Fatalf("subkey rotate: %d %s", st, body)
	}
	s1tok := kv(body)["token"]
	if st, _ := e.do(t, "GET", "/v1/me", tok2, nil); st != 200 {
		t.Fatal("root token died on subkey rotate")
	}
	// Recovery code exists -> minting again is refused; a v1 root can mint once.
	if st, body := e.do(t, "POST", "/v1/recovery", tok2, nil); st != 409 || body != "err dup recovery already set" {
		t.Fatalf("second recovery: %d %s", st, body)
	}
	if st, _ := e.do(t, "POST", "/v1/recovery", s1tok, nil); st != 403 {
		t.Fatal("subkey minted a recovery code")
	}
	// Recover: wrong code refused, right code -> new token, subkeys revoked, credits back, audit row.
	if st, body := e.do(t, "POST", "/v1/recover", "", map[string]string{"id": root, "recovery": strings.Repeat("a", 26)}); st != 403 || body != "err auth recovery" {
		t.Fatalf("wrong code: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/recover", "", map[string]string{"id": root, "recovery": "short"}); st != 400 {
		t.Fatalf("bad shape: %d %s", st, body)
	}
	st, body = e.do(t, "POST", "/v1/recover", "", map[string]string{"id": root, "recovery": rec})
	rm := kv(body)
	if st != 200 || rm["id"] != root || rm["recovered"] != "1" || rm["revoked"] != "1" || !strings.HasPrefix(rm["token"], "cx_") || strings.Contains(body, "mk_wrapped") {
		t.Fatalf("recover: %d %s", st, body)
	}
	tok3 := rm["token"]
	if st, _ := e.do(t, "GET", "/v1/me", tok2, nil); st != 401 {
		t.Fatal("pre-recovery token alive")
	}
	if st, _ := e.do(t, "GET", "/v1/me", s1tok, nil); st != 401 {
		t.Fatal("subkey alive after recovery")
	}
	_, body = e.do(t, "GET", "/v1/me", tok3, nil)
	if kv(body)["credits"] != "100" || kv(body)["recovery"] != "set" {
		t.Fatalf("after recovery: %s", body)
	}
	var audits int
	testPool.QueryRow(ctx, `SELECT count(*) FROM audit WHERE root = $1 AND op = 'recover'`, root).Scan(&audits)
	if audits != 1 {
		t.Fatalf("audit rows: %d", audits)
	}
	// Revoke-all: every subkey below the caller dies, credits return.
	e.do(t, "POST", "/v1/subkey", tok3, map[string]any{"credits": 10})
	_, body = e.do(t, "POST", "/v1/subkey", tok3, map[string]any{"credits": 20})
	s3 := kv(body)
	_, body = e.do(t, "POST", "/v1/subkey", s3["token"], map[string]any{"credits": 5})
	s4 := kv(body)
	st, body = e.do(t, "POST", "/v1/revoke-all", tok3, nil)
	if st != 200 || body != "ok revoked=3" {
		t.Fatalf("revoke-all: %d %s", st, body)
	}
	for _, tk := range []string{s3["token"], s4["token"]} {
		if st, _ := e.do(t, "GET", "/v1/me", tk, nil); st != 401 {
			t.Fatal("subkey alive after revoke-all")
		}
	}
	if _, body = e.do(t, "GET", "/v1/me", tok3, nil); kv(body)["credits"] != "100" {
		t.Fatalf("credits after revoke-all: %s", body)
	}
	// A v1 root (no code) mints one.
	testPool.Exec(ctx, `UPDATE identities SET recovery_hash = NULL WHERE id = $1`, root)
	if _, body = e.do(t, "GET", "/v1/me", tok3, nil); kv(body)["recovery"] != "unset" {
		t.Fatalf("me without code: %s", body)
	}
	if st, body := e.do(t, "POST", "/v1/recovery", tok3, nil); st != 200 || !ValidRecovery(kv(body)["recovery"]) {
		t.Fatalf("mint recovery: %d %s", st, body)
	}
}

func TestRecoverPerSuperCaps(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	ctx := context.Background()
	m := e.registerFull(t, "recov")
	root, rec := m["id"], m["recovery"]
	attempt := func(ip, code string) (int, string) {
		return e.do(t, "POST", "/v1/recover", "", map[string]string{"id": root, "recovery": code}, "CF-Connecting-IP", ip)
	}
	for i := 0; i < recoverPerSuper; i++ {
		if st, body := attempt(fmt.Sprintf("198.51.100.%d", i+1), strings.Repeat("b", 26)); st != 403 || body != "err auth recovery" {
			t.Fatalf("fail %d: %d %s", i, st, body)
		}
	}
	// The 6th attempt from the same /24 is refused even with the right code; another /24 succeeds.
	if st, body := attempt("198.51.100.9", rec); st != 429 || body != "err quota recover attempts" {
		t.Fatalf("per-super cap: %d %s", st, body)
	}
	st, body := attempt("203.0.113.9", rec)
	if st != 200 || kv(body)["recovered"] != "1" {
		t.Fatalf("other super: %d %s", st, body)
	}
	// Global 50/day per id, whatever the networks.
	m2 := e.registerFull(t, "recov2")
	for i := 0; i < 5; i++ {
		testPool.Exec(ctx, `INSERT INTO recover_attempts (id, super, day, n) VALUES ($1, $2, current_date, 10)`, m2["id"], fmt.Sprintf("synthetic-%d", i))
	}
	if st, body := e.do(t, "POST", "/v1/recover", "", map[string]string{"id": m2["id"], "recovery": m2["recovery"]}, "CF-Connecting-IP", "192.0.2.5"); st != 429 {
		t.Fatalf("global cap: %d %s", st, body)
	}
	// Unknown ids take the same path and the same answer.
	if st, body := attempt("192.0.2.6", strings.Repeat("c", 26)); st != 403 || body != "err auth recovery" {
		t.Fatalf("unknown id: %d %s", st, body)
	}
}

func TestEraseGraceUndo(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	ctx := context.Background()
	root, tok := e.register(t, "eraser")
	_, body := e.do(t, "POST", "/v1/subkey", tok, map[string]any{"credits": 1})
	sub := kv(body)
	if st, body := e.do(t, "DELETE", "/v1/me", tok, map[string]string{"confirm": "a1111111"}); st != 400 {
		t.Fatalf("bad confirm: %d %s", st, body)
	}
	if st, _ := e.do(t, "DELETE", "/v1/me", sub["token"], map[string]string{"confirm": root}); st != 403 {
		t.Fatal("subkey scheduled an erasure")
	}
	st, body := e.do(t, "DELETE", "/v1/me", tok, map[string]string{"confirm": root})
	if st != 200 || !strings.HasPrefix(body, "ok erasing=") {
		t.Fatalf("erase: %d %s", st, body)
	}
	at, err := time.Parse(time.RFC3339, kv(body)["erasing"])
	if err != nil || time.Until(at) < 23*time.Hour || time.Until(at) > 25*time.Hour {
		t.Fatalf("grace: %v %v", at, err)
	}
	if _, body = e.do(t, "GET", "/v1/me", tok, nil); kv(body)["erasing"] != Date(at) {
		t.Fatalf("me during grace: %s", body)
	}
	// The janitor leaves it alone during the grace period.
	e.d.Janitor.RunOnce(ctx)
	if st, _ := e.do(t, "GET", "/v1/me", tok, nil); st != 200 {
		t.Fatal("purged during grace")
	}
	if st, body := e.do(t, "POST", "/v1/me/undo", tok, nil); st != 200 || body != "ok undone=1" {
		t.Fatalf("undo: %d %s", st, body)
	}
	if _, body = e.do(t, "GET", "/v1/me", tok, nil); strings.Contains(body, "erasing=") {
		t.Fatalf("me after undo: %s", body)
	}
	if st, body := e.do(t, "POST", "/v1/me/undo", tok, nil); st != 200 || body != "ok undone=0" {
		t.Fatalf("second undo: %d %s", st, body)
	}
	// Schedule again, let the grace elapse: the janitor purges the tree.
	e.do(t, "DELETE", "/v1/me", tok, map[string]string{"confirm": root})
	testPool.Exec(ctx, `UPDATE identities SET erasing_at = now() - interval '1 second' WHERE id = $1`, root)
	e.d.Janitor.RunOnce(ctx)
	for _, tk := range []string{tok, sub["token"]} {
		if st, _ := e.do(t, "GET", "/v1/me", tk, nil); st != 401 {
			t.Fatal("token alive after the erasure ran")
		}
	}
	var revoked bool
	testPool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM identities WHERE id = $1`, root).Scan(&revoked)
	if !revoked {
		t.Fatal("root not revoked")
	}
}

func TestXPoWFnSingleUse(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	ctx := context.Background()
	exp := time.Now().Add(5 * time.Minute)
	mk := func(bits int, p pow.Purpose) (string, string) {
		c := pow.New(e.d.Cfg.ServerSecret, exp, bits, p)
		return c, pow.Solve(c, bits)
	}
	req := func(hdr string) *http.Request {
		r := httptest.NewRequest("POST", "/w/kb", nil)
		r.Header.Set("CF-Connecting-IP", "203.0.113.5")
		if hdr != "" {
			r.Header.Set("X-PoW", hdr)
		}
		return r
	}
	c, n := mk(8, pow.PurposeWrite)
	grp, super, err := e.d.XPoW(ctx, req(c+":"+n))
	if err != nil || grp != "203.0.113.5" || super != "203.0.113.0/24" {
		t.Fatalf("xpow: %q %q %v", grp, super, err)
	}
	if _, _, err := e.d.XPoW(ctx, req(c+":"+n)); err == nil || err.Error() != "err pow challenge already used" {
		t.Fatalf("second use: %v", err)
	}
	c, n = mk(8, pow.PurposeWrite)
	if _, _, err := e.d.XPoW(ctx, req(c+":1")); err != ErrPow && (err == nil || err.Error() != ErrPow.Error()) {
		t.Fatalf("weak nonce: %v", err)
	}
	// A refused nonce did not burn the challenge.
	if _, _, err := e.d.XPoW(ctx, req(c+":"+n)); err != nil {
		t.Fatalf("after weak attempt: %v", err)
	}
	c, n = mk(8, pow.PurposeReg)
	if _, _, err := e.d.XPoW(ctx, req(c+":"+n)); err == nil || err.Error() != "err pow challenge purpose reg, need w" {
		t.Fatalf("reg challenge in X-PoW: %v", err)
	}
	if _, _, err := e.d.XPoW(ctx, req("")); err == nil || err.Error() != "err pow X-PoW required" {
		t.Fatalf("missing: %v", err)
	}
	if _, _, err := e.d.XPoW(ctx, req("nocolon")); err == nil || !strings.HasPrefix(err.Error(), "err pow") {
		t.Fatalf("malformed: %v", err)
	}
	// Network keys stashed by the Handler win over the request address.
	c, n = mk(8, pow.PurposeWrite)
	grp, super, err = e.d.XPoW(WithClient(ctx, "198.51.100.7", "198.51.100.7", "198.51.100.0/24"), req(c+":"+n))
	if err != nil || grp != "198.51.100.7" || super != "198.51.100.0/24" {
		t.Fatalf("ctx keys: %q %q %v", grp, super, err)
	}
}

func TestLeakedTokenRotateRevoke(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	ctx := context.Background()
	var mails []string
	old := SysMailFn
	SysMailFn = func(_ context.Context, _ Q, to, subject, text string) error {
		mails = append(mails, to+" "+subject)
		return nil
	}
	t.Cleanup(func() { SysMailFn = old })
	mr := e.registerFull(t, "leaker")
	root, rtok := mr["id"], mr["token"]
	_, body := e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"credits": 9})
	sub := kv(body)
	other := e.registerFull(t, "victim")
	me, _ := e.d.LookupToken(ctx, rtok)
	callerCtx := context.WithValue(ctx, identKey, &authResult{id: me})
	// Own token in content: rotated in the caller's tx, new token returned once.
	var action string
	if err := Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
		action, err = LeakedToken(callerCtx, tx, rtok)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	newTok, ok := strings.CutPrefix(action, "rotated token=")
	if !ok || len(newTok) != 46 {
		t.Fatalf("own token action %q", action)
	}
	if st, _ := e.do(t, "GET", "/v1/me", newTok, nil); st != 200 {
		t.Fatal("rotated token refused")
	}
	if len(mails) != 0 {
		t.Fatal("own rotation mailed")
	}
	// Own subkey's token: that subkey is revoked, credits come back, the owner is told.
	if err := Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
		action, err = LeakedToken(callerCtx, tx, sub["token"])
		return err
	}); err != nil || action != "revoked" {
		t.Fatalf("subkey leak: %q %v", action, err)
	}
	if st, _ := e.do(t, "GET", "/v1/me", sub["token"], nil); st != 401 {
		t.Fatal("leaked subkey alive")
	}
	if _, body = e.do(t, "GET", "/v1/me", newTok, nil); kv(body)["credits"] != "100" {
		t.Fatalf("credits after subkey revoke: %s", body)
	}
	if len(mails) != 1 || mails[0] != root+" token revoked" {
		t.Fatalf("mails %v", mails)
	}
	// Another root's token: locked out (tree and credits kept), owner recovers with the code.
	if err := Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
		action, err = LeakedToken(callerCtx, tx, other["token"])
		return err
	}); err != nil || action != "revoked" {
		t.Fatalf("other leak: %q %v", action, err)
	}
	if st, _ := e.do(t, "GET", "/v1/me", other["token"], nil); st != 401 {
		t.Fatal("leaked root token alive")
	}
	if len(mails) != 2 || mails[1] != other["id"]+" token revoked" {
		t.Fatalf("mails %v", mails)
	}
	st, body := e.do(t, "POST", "/v1/recover", "", map[string]string{"id": other["id"], "recovery": other["recovery"]})
	if st != 200 || kv(body)["credits"] == "0" {
		t.Fatalf("recover after leak: %d %s", st, body)
	}
	if _, body = e.do(t, "GET", "/v1/me", kv(body)["token"], nil); kv(body)["credits"] != "100" {
		t.Fatalf("victim credits: %s", body)
	}
	// Unknown or malformed tokens: nothing happens.
	for _, tk := range []string{"cx_" + strings.Repeat("A", 43), "nope", ""} {
		if a, err := LeakedToken(callerCtx, testPool, tk); a != "" || err != nil {
			t.Fatalf("%q: %q %v", tk, a, err)
		}
	}
	var audits int
	testPool.QueryRow(ctx, `SELECT count(*) FROM audit WHERE op IN ('leak-rotate', 'leak-revoke') AND root IN ($1, $2)`, root, other["id"]).Scan(&audits)
	if audits != 3 {
		t.Fatalf("audit rows: %d", audits)
	}
}

func TestReservedRegistrationName(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	for _, name := range []string{"admin", "Admin", "cx-bot", "claude", "sys_tem", "a.d.m.i.n", "tpl-x"} {
		c, nonce := e.challenge(t)
		if st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": name}); st != 400 || body != "err bad name reserved" {
			t.Fatalf("%q: %d %s", name, st, body)
		}
	}
	e.register(t, "alice-7")
	// The reserved check precedes the PoW: no challenge is burnt by a refused name.
	c, nonce := e.challenge(t)
	e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "root"})
	if st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "rooter"}); st != 201 {
		t.Fatalf("challenge burnt by a reserved name: %d %s", st, body)
	}
	if _, _, _, err := RegisterWithChallenge(context.Background(), e.d, e.ip, "x", "y", "mod"); err == nil || err.Error() != "err bad name reserved" {
		t.Fatalf("RegisterWithChallenge reserved: %v", err)
	}
}

func TestValidIDPrefixes(t *testing.T) {
	for id, want := range map[string]bool{"a234567": true, "kabcdef": true, "zzzzzzz": true, "q2b3c4d": true, "asystem": true,
		"Aabcdef": false, "1abcdef": false, "abcdef": false, "abcdefgh": false, "aabcde1": false, "aabcde8": false, "a-bcdef": false} {
		if got := ValidID(id); got != want {
			t.Errorf("ValidID(%q)=%v want %v", id, got, want)
		}
	}
	if !ValidIDPrefix("kabcdef", 'k') || ValidIDPrefix("kabcdef", 'a') || ValidIDPrefix("", 'a') || ValidIDPrefix("K", 'k') {
		t.Fatal("ValidIDPrefix")
	}
	if !ValidIDPrefix(NewID('q'), 'q') || !ValidIDPrefix(SystemID, 'a') {
		t.Fatal("NewID / SystemID")
	}
	code, h := NewRecoveryCode()
	if !ValidRecovery(code) || len(h) != 32 || ValidRecovery(code[:25]) || ValidRecovery(strings.ToUpper(code)) {
		t.Fatal("recovery code shape")
	}
}

func TestChallengeIdAndBundleSeams(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	ctx := context.Background()
	derive := func(c string) string {
		h := sha256.Sum256([]byte("regid" + c))
		out := []byte{'a'}
		for _, b := range h[:6] {
			out = append(out, b32[b&31])
		}
		return string(out)
	}
	var gotID string
	var gotBundle json.RawMessage
	var bundleErr error
	ChallengeIDFn = func(_ context.Context, c string) string { return derive(c) }
	RegisterBundleFn = func(_ context.Context, _ Q, id string, bundle json.RawMessage) error {
		gotID, gotBundle = id, bundle
		return bundleErr
	}
	t.Cleanup(func() { ChallengeIDFn, RegisterBundleFn = nil, nil })
	_, body := e.do(t, "POST", "/v1/challenge", "", nil)
	m := kv(body)
	c := m["c"]
	if m["id"] != derive(c) {
		t.Fatalf("challenge id: %s", body)
	}
	bits, _ := strconv.Atoi(m["bits"])
	st, body := e.do(t, "POST", "/v1/register", "", map[string]any{"c": c, "nonce": pow.Solve(c, bits), "name": "sealed", "bundle": "QUJD"})
	if st != 201 || kv(body)["id"] != derive(c) {
		t.Fatalf("register with derived id: %d %s", st, body)
	}
	if gotID != derive(c) || string(gotBundle) != `"QUJD"` {
		t.Fatalf("bundle seam got %q %s", gotID, gotBundle)
	}
	// A bundle the keys package refuses aborts the whole registration (same tx).
	bundleErr = E(400, "bundle", "bad signature")
	_, body = e.do(t, "POST", "/v1/challenge", "", nil)
	m = kv(body)
	c = m["c"]
	bits, _ = strconv.Atoi(m["bits"])
	if st, body := e.do(t, "POST", "/v1/register", "", map[string]any{"c": c, "nonce": pow.Solve(c, bits), "name": "sealed2", "bundle": "QUJD"}); st != 400 || body != "err bundle bad signature" {
		t.Fatalf("refused bundle: %d %s", st, body)
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM identities WHERE id = $1 OR name = 'sealed2'`, derive(c)).Scan(&n)
	if n != 0 {
		t.Fatal("identity created despite the refused bundle")
	}
	bundleErr = nil
	// Without a bundle the seam is not called; a colliding derived id answers err retry.
	gotID = ""
	taken, _ := e.register(t, "taken")
	ChallengeIDFn = func(context.Context, string) string { return taken }
	_, body = e.do(t, "POST", "/v1/challenge", "", nil)
	m = kv(body)
	c = m["c"]
	bits, _ = strconv.Atoi(m["bits"])
	if st, body := e.do(t, "POST", "/v1/register", "", map[string]any{"c": c, "nonce": pow.Solve(c, bits), "name": "collide"}); st != 409 || !strings.HasPrefix(body, "err retry") {
		t.Fatalf("collision: %d %s", st, body)
	}
	if gotID != "" {
		t.Fatal("bundle seam called without a bundle")
	}
}

func TestAnonBitsFnConsulted(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	AnonBitsFn = nil
	if _, body := e.do(t, "POST", "/v1/challenge?for=w", "", nil); kv(body)["bits"] != "16" {
		t.Fatalf("default w bits: %s", body)
	}
	var seen string
	AnonBitsFn = func(_ context.Context, super string) int { seen = super; return 9 }
	t.Cleanup(func() { AnonBitsFn = nil })
	_, body := e.do(t, "POST", "/v1/challenge?for=w", "", nil, "CF-Connecting-IP", "203.0.113.44")
	if kv(body)["bits"] != "9" || seen != "203.0.113.0/24" {
		t.Fatalf("AnonBitsFn: %s seen=%q", body, seen)
	}
	c := kv(body)["c"]
	if info, err := pow.VerifyV2(e.d.Cfg.ServerSecret, c, time.Now()); err != nil || info.Bits != 9 || info.Purpose != pow.PurposeWrite {
		t.Fatalf("bits not authenticated in the challenge: %+v %v", info, err)
	}
	// for=reg ignores it.
	if _, body := e.do(t, "POST", "/v1/challenge", "", nil); kv(body)["bits"] == "9" {
		t.Fatalf("reg bits took the anon curve: %s", body)
	}
}

func TestUrlClassReadScopesAndCapabilityURL(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	_, rtok := e.register(t, "urlowner")
	st, body := e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"class": "url"})
	if st != 201 {
		t.Fatalf("url subkey: %d %s", st, body)
	}
	lines := strings.Split(body, "\n")
	m := kv(lines[0])
	if m["credits"] != "0" || m["scopes"] != "cp:r,ev:r,kv:r,mb:env,me:r" || m["class"] != "url" || len(lines) != 2 || lines[1] != "url: https://agents.example/v1/me/resume?t="+m["token"] {
		t.Fatalf("url reply: %s", body)
	}
	exp, _ := time.Parse("2006-01-02", m["exp"])
	if d := time.Until(exp); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Fatalf("url ttl: %s", m["exp"])
	}
	utok := m["token"]
	st, body = e.do(t, "GET", "/v1/me", utok, nil)
	if st != 200 || !strings.Contains(body, " scopes=cp:r,ev:r,kv:r,mb:env,me:r class=url") {
		t.Fatalf("url me: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/subkey", utok, map[string]any{}); st != 403 || body != "err scope sub" {
		t.Fatalf("url minting: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"class": "url", "credits": 5}); st != 400 || body != "err bad url class carries no credits" {
		t.Fatalf("url credits: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"class": "url", "ttl_h": 2161}); st != 400 || body != "err bad ttl_h must be 1..2160" {
		t.Fatalf("url ttl cap: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"ttl_h": 721}); st != 400 || body != "err bad ttl_h must be 1..720" {
		t.Fatalf("v1 ttl cap: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"class": "ui", "scopes": []string{"kb:r"}}); st != 201 || !strings.Contains(body, "class=ui") {
		t.Fatalf("ui class: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"class": "king"}); st != 400 {
		t.Fatalf("bad class: %d %s", st, body)
	}
	// Explicit url scopes stay within the parent's set.
	st, body = e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"class": "url", "scopes": []string{"kb:r", "me:r"}})
	if st != 201 || !strings.Contains(body, " scopes=kb:r,me:r class=url") {
		t.Fatalf("url explicit scopes: %d %s", st, body)
	}
}

func TestFamilyChangeOncePer30d(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	ctx := context.Background()
	var logged []string
	old := RepLogger
	RepLogger = func(_ context.Context, _ Q, root string, delta int, kind, ref string) error {
		logged = append(logged, fmt.Sprintf("%s %d %s %s", root, delta, kind, ref))
		return nil
	}
	t.Cleanup(func() { RepLogger = old })
	root, tok := e.register(t, "fam")
	st, body := e.do(t, "PUT", "/v1/me", tok, map[string]any{"family": "gpt", "model": "gpt-4o", "cutoff": "2024-10"})
	if st != 200 || body != "ok family=gpt model=gpt-4o cutoff=2024-10 public_stats=0" {
		t.Fatalf("put me: %d %s", st, body)
	}
	if _, body = e.do(t, "GET", "/v1/me", tok, nil); !strings.Contains(body, " family=gpt model=gpt-4o cutoff=2024-10") {
		t.Fatalf("me: %s", body)
	}
	if st, body := e.do(t, "PUT", "/v1/me", tok, map[string]any{"family": "claude"}); st != 429 || body != "err quota family change once per 30 d" {
		t.Fatalf("second change: %d %s", st, body)
	}
	if st, _ := e.do(t, "PUT", "/v1/me", tok, map[string]any{"family": "gpt", "public_stats": true}); st != 200 {
		t.Fatal("same family refused")
	}
	testPool.Exec(ctx, `UPDATE identities SET family_at = now() - interval '31 days' WHERE id = $1`, root)
	if st, body := e.do(t, "PUT", "/v1/me", tok, map[string]any{"family": "claude"}); st != 200 || !strings.HasPrefix(body, "ok family=claude model=gpt-4o") || !strings.HasSuffix(body, "public_stats=1") {
		t.Fatalf("after 30 d: %d %s", st, body)
	}
	if len(logged) != 2 || logged[0] != root+" 0 family gpt" || logged[1] != root+" 0 family claude" {
		t.Fatalf("rep_log: %v", logged)
	}
	for _, bad := range []map[string]any{{"family": "skynet"}, {"cutoff": "2024-13"}, {"model": "has space"}, {"model": strings.Repeat("x", 41)}} {
		if st, _ := e.do(t, "PUT", "/v1/me", tok, bad); st != 400 {
			t.Fatalf("%v accepted", bad)
		}
	}
	// Profile edits need a full token; a scoped one holding sub is refused.
	_, body = e.do(t, "POST", "/v1/subkey", tok, map[string]any{"scopes": []string{"sub"}})
	if st, body := e.do(t, "PUT", "/v1/me", kv(body)["token"], map[string]any{"model": "x"}); st != 403 || body != "err auth full token required" {
		t.Fatalf("scoped put me: %d %s", st, body)
	}
}

func TestPubRegistration(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	ctx := context.Background()
	root, tok := e.register(t, "donor")
	var k1, k2 [32]byte
	rand.Read(k1[:])
	rand.Read(k2[:])
	st, body := e.do(t, "PUT", "/v1/me", tok, map[string]any{"pub": strings.ToUpper(hex.EncodeToString(k1[:]))})
	if st != 200 || !strings.HasSuffix(body, " pub="+hex.EncodeToString(k1[:])) {
		t.Fatalf("set pub: %d %s", st, body)
	}
	var pub, prev []byte
	testPool.QueryRow(ctx, `SELECT pub, pub_prev FROM identities WHERE id = $1`, root).Scan(&pub, &prev)
	if !bytesEqual(pub, k1[:]) || prev != nil {
		t.Fatalf("stored pub %x prev %x", pub, prev)
	}
	if st, body := e.do(t, "PUT", "/v1/me", tok, map[string]any{"pub": hex.EncodeToString(k2[:])}); st != 429 || body != "err quota pub rotation once per 30 d" {
		t.Fatalf("early rotation: %d %s", st, body)
	}
	if st, _ := e.do(t, "PUT", "/v1/me", tok, map[string]any{"pub": hex.EncodeToString(k1[:])}); st != 200 {
		t.Fatal("re-sending the same pub refused")
	}
	testPool.Exec(ctx, `UPDATE identities SET pub_at = now() - interval '31 days' WHERE id = $1`, root)
	if st, _ := e.do(t, "PUT", "/v1/me", tok, map[string]any{"pub": hex.EncodeToString(k2[:])}); st != 200 {
		t.Fatal("rotation after 30 d refused")
	}
	testPool.QueryRow(ctx, `SELECT pub, pub_prev FROM identities WHERE id = $1`, root).Scan(&pub, &prev)
	if !bytesEqual(pub, k2[:]) || !bytesEqual(prev, k1[:]) {
		t.Fatalf("after rotation pub %x prev %x", pub, prev)
	}
	for _, bad := range []string{"abc", strings.Repeat("g", 64), strings.Repeat("a", 63)} {
		if st, _ := e.do(t, "PUT", "/v1/me", tok, map[string]any{"pub": bad}); st != 400 {
			t.Fatalf("%q accepted", bad)
		}
	}
	// A subkey of class full registers for its root (cxw runs under subkeys).
	_, body = e.do(t, "POST", "/v1/subkey", tok, map[string]any{})
	testPool.Exec(ctx, `UPDATE identities SET pub_at = now() - interval '31 days' WHERE id = $1`, root)
	if st, _ := e.do(t, "PUT", "/v1/me", kv(body)["token"], map[string]any{"pub": hex.EncodeToString(k1[:])}); st != 200 {
		t.Fatal("subkey pub registration refused")
	}
	testPool.QueryRow(ctx, `SELECT pub FROM identities WHERE id = $1`, root).Scan(&pub)
	if !bytesEqual(pub, k1[:]) {
		t.Fatal("subkey registration did not land on the root")
	}
}

func TestMkWrappedRoundTrip(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	m := e.registerFull(t, "sealer")
	tok := m["token"]
	if st, body := e.do(t, "GET", "/v1/me/mk", tok, nil); st != 404 || body != "err notfound mk_wrapped unset" {
		t.Fatalf("mk before: %d %s", st, body)
	}
	if _, body := e.do(t, "GET", "/v1/me", tok, nil); !strings.Contains(body, " seal=unset") {
		t.Fatalf("me before: %s", body)
	}
	wrapped := make([]byte, 60)
	rand.Read(wrapped)
	if st, body := e.do(t, "PUT", "/v1/me/mk", tok, map[string]string{"wrapped": base64.StdEncoding.EncodeToString(wrapped)}); st != 200 || body != "ok mk_wrapped=1" {
		t.Fatalf("put mk: %d %s", st, body)
	}
	st, body, h := e.doH(t, "GET", "/v1/me/mk", tok, "")
	got, err := base64.RawURLEncoding.DecodeString(kv(body)["mk_wrapped"])
	if st != 200 || err != nil || !bytesEqual(got, wrapped) || !strings.Contains(h.Get("Cache-Control"), "no-store") {
		t.Fatalf("get mk: %d %s %v", st, body, err)
	}
	if _, body := e.do(t, "GET", "/v1/me", tok, nil); strings.Contains(body, "seal=unset") {
		t.Fatalf("me after: %s", body)
	}
	// Rotation never touches it; recovery hands it back.
	_, body = e.do(t, "POST", "/v1/rotate", tok, nil)
	tok = kv(body)["token"]
	st, body = e.do(t, "POST", "/v1/recover", "", map[string]string{"id": m["id"], "recovery": m["recovery"]})
	if got, err := base64.RawURLEncoding.DecodeString(kv(body)["mk_wrapped"]); st != 200 || err != nil || !bytesEqual(got, wrapped) {
		t.Fatalf("recover mk: %d %s", st, body)
	}
	for _, bad := range []string{"", "!!!", base64.StdEncoding.EncodeToString(make([]byte, 10)), base64.StdEncoding.EncodeToString(make([]byte, 600))} {
		if st, _ := e.do(t, "PUT", "/v1/me/mk", kv(body)["token"], map[string]string{"wrapped": bad}); st != 400 {
			t.Fatalf("%q accepted", bad)
		}
	}
	_, body = e.do(t, "POST", "/v1/subkey", kv(body)["token"], map[string]any{"scopes": []string{"sub", "me:r"}})
	if st, _ := e.do(t, "GET", "/v1/me/mk", kv(body)["token"], nil); st != 403 {
		t.Fatal("scoped token read the wrapped key")
	}
}

func TestAuthOrPoWHeaders(t *testing.T) {
	e := newAuthEnv(t, nil, func(mux *http.ServeMux, d *Deps) {
		mux.HandleFunc("POST /w/zz", func(w http.ResponseWriter, r *http.Request) {
			id, grp, _, err := d.AuthOrPoW(w, r)
			if err != nil {
				Fail(w, r, err)
				return
			}
			if id != nil {
				OK(w, r, "ok id="+id.ID, nil)
				return
			}
			OK(w, r, "ok anon grp="+grp, nil)
		})
	})
	old := WWWAuthenticate
	WWWAuthenticate = `Bearer resource_metadata="https://agents.example/.well-known/oauth-protected-resource"`
	t.Cleanup(func() { WWWAuthenticate = old })
	st, body, h := e.doH(t, "POST", "/w/zz", "", "")
	vals := h.Values("WWW-Authenticate")
	if st != 401 || body != "err auth token required" || len(vals) != 2 || !strings.HasPrefix(vals[0], "Bearer ") || !strings.HasPrefix(vals[1], `PoW realm="w", c="`) {
		t.Fatalf("anon: %d %s %v", st, body, vals)
	}
	var c string
	var bits int
	var exp int64
	if _, err := fmt.Sscanf(vals[1], `PoW realm="w", c="%40s", bits=%d, exp=%d`, &c, &bits, &exp); err != nil || bits != 16 || exp < time.Now().Unix() {
		t.Fatalf("PoW header %q: %v", vals[1], err)
	}
	if st, body, _ := e.doH(t, "POST", "/w/zz", "", "", "X-PoW", c+":"+pow.Solve(c, bits)); st != 200 || body != "ok anon grp="+e.ip {
		t.Fatalf("with pow: %d %s", st, body)
	}
	id, tok := e.register(t, "powless")
	if st, body, h := e.doH(t, "POST", "/w/zz", tok, ""); st != 200 || body != "ok id="+id || len(h.Values("WWW-Authenticate")) != 0 {
		t.Fatalf("with token: %d %s", st, body)
	}
}

func TestMeV2FieldsAndExport(t *testing.T) {
	e := newAuthEnv(t, nil, nil)
	ctx := context.Background()
	e.d.OnExport("zz", func(_ context.Context, root string, w io.Writer) error {
		_, err := fmt.Fprintf(w, "{\"kind\":\"zz\",\"root\":%q}\n", root)
		return err
	})
	e.d.MeExtra(func(context.Context, *Ident) []string { return []string{"today: kb 0/30"} })
	root, tok := e.register(t, "meexp")
	st, body := e.do(t, "GET", "/v1/me", tok, nil)
	head := strings.Split(body, "\n")
	if st != 200 || len(head) != 2 || head[1] != "today: kb 0/30" {
		t.Fatalf("me: %d %s", st, body)
	}
	m := kv(head[0])
	if m["lvl"] != "L0" || m["ipclass"] != "unknown" || m["recovery"] != "set" || m["seal"] != "unset" || m["exp"] != "never" || strings.Contains(head[0], "scopes=") {
		t.Fatalf("me head: %s", head[0])
	}
	var j map[string]any
	_, body = e.do(t, "GET", "/v1/me?f=json", tok, nil)
	if err := json.Unmarshal([]byte(body), &j); err != nil || j["class"] != "full" || j["recovery"] != true || j["lvl"] != float64(0) || j["created"] == nil {
		t.Fatalf("me json: %s", body)
	}
	_, body = e.do(t, "POST", "/v1/subkey", tok, map[string]any{"credits": 3})
	sub := kv(body)
	if _, body = e.do(t, "GET", "/v1/me", sub["token"], nil); strings.Contains(body, "recovery=") {
		t.Fatalf("subkey me shows recovery: %s", body)
	}
	st, body, h := e.doH(t, "GET", "/v1/me/export", tok, "")
	lines := strings.Split(body, "\n")
	if st != 200 || h.Get("Content-Type") != "application/x-ndjson" || len(lines) != 3 {
		t.Fatalf("export: %d %s %v", st, body, h)
	}
	for i, want := range []string{`"kind":"identity"`, `"kind":"subkey"`, `"kind":"zz"`} {
		var row map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &row); err != nil || !strings.Contains(lines[i], want) {
			t.Fatalf("export line %d: %s", i, lines[i])
		}
	}
	if !strings.Contains(lines[0], `"id":"`+root+`"`) || !strings.Contains(lines[1], `"id":"`+sub["id"]+`"`) || !strings.Contains(lines[2], root) {
		t.Fatalf("export rows: %s", body)
	}
	if st, _ := e.do(t, "GET", "/v1/me/export", sub["token"], nil); st != 403 {
		t.Fatal("subkey exported")
	}
	testPool.Exec(ctx, `UPDATE counters SET n = $2 WHERE scope = $1 AND kind = 'export' AND day = current_date`, root, exportPerDay)
	if st, body := e.do(t, "GET", "/v1/me/export", tok, nil); st != 429 || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("export quota: %d %s", st, body)
	}
}
