package export

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/sign"
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
	} else if pool, done := testdb.Open("export", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping export DB tests")
		os.Exit(0)
	}
	// This package's own database: start its tables clean (a reused database keeps old rows).
	for _, sql := range []string{
		`TRUNCATE kb, kb_tombstones, tasks, claims, digests, egress_outbox CASCADE`,
		`DELETE FROM flags WHERE k LIKE 'export:%'`,
	} {
		if _, err := testPool.Exec(ctx, sql); err != nil {
			panic(err)
		}
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	s   *Service
	srv *httptest.Server
	dir string
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	dir := t.TempDir()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: dir, ExportDir: filepath.Join(dir, "export"),
		TrustCF: true, PublicURL: "https://agents.example", LicenseContent: "CC0-1.0", SignKID: 1, RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	if _, err := sign.Init(cfg); err != nil {
		t.Fatal(err)
	}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	return &tenv{d: d, s: cur.Load(), srv: srv, dir: cfg.ExportDir}
}

// --- fixtures ----------------------------------------------------------------------------------

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func (e *tenv) identity(t *testing.T, seed bool) string {
	t.Helper()
	id := core.NewID('a')
	_, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, root, token_hash, rep, created, seed, verified_noncompute)
		VALUES ($1, $1, $1, $2, 10, now() - interval '5 days', $3, 1)`, id, randBytes(32), seed)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type kbIn struct {
	root, title, symptom, fix, versions, space, superseded string
	tags                                                   []string
	hidden, quarantine, expired, seed                      bool
	okW                                                    float32
}

func (e *tenv) kb(t *testing.T, in kbIn) string {
	t.Helper()
	id := core.NewID('k')
	exp := "now() + interval '100 days'"
	if in.expired {
		exp = "now() - interval '1 hour'"
	}
	if in.title == "" {
		in.title = "ECONNRESET during npm ci " + id
	}
	if in.tags == nil {
		in.tags = []string{}
	}
	_, err := testPool.Exec(context.Background(), `INSERT INTO kb (id, kind, title, symptom, cause, fix, versions, tags, author, author_root, ok_w, created, expires_at,
		hidden, quarantine, seed, space, superseded_by)
		VALUES ($1, 'fix', $2, $3, 'cause', $4, $5, $6, $7, $7, $8, now() - interval '2 hours', `+exp+`, $9, $10, $11, $12, $13)`,
		id, in.title, in.symptom, in.fix, in.versions, in.tags, in.root, in.okW, in.hidden, in.quarantine, in.seed, in.space, in.superseded)
	if err != nil {
		t.Fatal(err)
	}
	for _, lv := range kb.ParseVersions(in.versions) {
		if _, err := testPool.Exec(context.Background(), `INSERT INTO kb_versions (kb_id, lib, ver) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, id, lv.Lib, lv.Ver); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func (e *tenv) task(t *testing.T, root, title, body, state, space string, quarantine bool) int64 {
	t.Helper()
	var n int64
	err := testPool.QueryRow(context.Background(), `INSERT INTO tasks (n, id, root, title, body, tags, state, space, quarantine)
		VALUES (nextval('task_n_seq'), $1, $1, $2, $3, '{go}', $4, $5, $6) RETURNING n`, root, title, body, state, space, quarantine).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *tenv) claim(t *testing.T, root, status string, hidden bool) string {
	t.Helper()
	id := core.NewID('v')
	_, err := testPool.Exec(context.Background(), `INSERT INTO claims (id, lib, kind, v_from, v_to, title, detail, author, author_root, status, hidden, expires_at, created)
		VALUES ($1, 'npm:react', 'breaking', '18', '19', 'defaultProps removed ' || $1, 'detail', $2, $2, $3, $4, now() + interval '100 days', now() - interval '2 hours')`,
		id, root, status, hidden)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *tenv) digest(t *testing.T, root, status string, hidden bool) string {
	t.Helper()
	id := core.NewID('d')
	_, err := testPool.Exec(context.Background(), `INSERT INTO digests (id, lib, v_from, v_to, topic, body, hash, author, author_root, status, hidden, expires_at, created)
		VALUES ($1, 'pypi:requests', '2.31', '2.32', 'api', 'body of ' || $1, $2, $3, $3, $4, $5, now() + interval '100 days', now() - interval '2 hours')`,
		id, randBytes(32), root, status, hidden)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// --- helpers -----------------------------------------------------------------------------------

func today() string { return time.Now().UTC().Format(dateFmt) }

// gzRows reads every JSON object of a gzip JSONL file.
func gzRows(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var out []map[string]any
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("%s: bad line %q: %v", path, sc.Bytes(), err)
		}
		out = append(out, m)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func idsOf(rows []map[string]any) map[string]map[string]any {
	m := map[string]map[string]any{}
	for _, r := range rows {
		m[fmt.Sprint(r["id"])] = r
	}
	return m
}

func fileSHA(t *testing.T, path string) (string, int64) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), int64(len(b))
}

func readManifest(t *testing.T, dir string) *Manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

// checkIntegrity asserts the manifest, SHA256SUMS and SIGNATURES describe the files on disk and
// verify under the server key.
func checkIntegrity(t *testing.T, dir string) *Manifest {
	t.Helper()
	m := readManifest(t, dir)
	for _, f := range m.Files {
		sum, size := fileSHA(t, filepath.Join(dir, f.Name))
		if sum != f.SHA256 || size != f.Size {
			t.Fatalf("manifest %s: sha %s size %d, disk sha %s size %d", f.Name, f.SHA256, f.Size, sum, size)
		}
		if int64(len(gzRows(t, filepath.Join(dir, f.Name)))) != f.Rows {
			t.Fatalf("manifest %s: rows %d do not match the file", f.Name, f.Rows)
		}
	}
	sig := m.Sig
	if sig == "" || m.KID != 1 {
		t.Fatalf("manifest sig/kid: %q %d", sig, m.KID)
	}
	m.Sig = ""
	if _, ok := sign.Verify("manifest1", string(compactJSON(m)), sig); !ok {
		t.Fatal("manifest sig does not verify over the manifest without sig")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "manifest.json.sig")); strings.TrimSpace(string(b)) != "sig="+sig {
		t.Fatalf("manifest.json.sig: %q", b)
	}
	m.Sig = sig
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		hexSum, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("SHA256SUMS line %q", line)
		}
		got, _ := fileSHA(t, filepath.Join(dir, name))
		if got != hexSum {
			t.Fatalf("SHA256SUMS %s: %s, disk %s", name, hexSum, got)
		}
		seen[name] = hexSum
	}
	for _, want := range append([]string{"manifest.json", "tombstones.jsonl", "croissant.json", "README.md"}, shardNames(m)...) {
		if seen[want] == "" {
			t.Fatalf("SHA256SUMS lacks %s", want)
		}
	}
	ssig, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	if _, ok := sign.Verify("manifest1", string(sums), strings.TrimSpace(string(ssig))); !ok {
		t.Fatal("SHA256SUMS.sig does not verify")
	}
	sigs, _ := os.ReadFile(filepath.Join(dir, "SIGNATURES"))
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(sigs)), "\n") {
		msg, s, ok := strings.Cut(line, " sig=")
		name, sha, _ := strings.Cut(msg, " sha256=")
		if !ok || seen[name] != sha {
			t.Fatalf("SIGNATURES line %q", line)
		}
		if _, ok := sign.Verify("export1", msg, s); !ok {
			t.Fatalf("SIGNATURES %s does not verify", name)
		}
		n++
	}
	if n != len(seen) {
		t.Fatalf("SIGNATURES has %d lines, SHA256SUMS %d", n, len(seen))
	}
	return m
}

func shardNames(m *Manifest) []string {
	var out []string
	for _, f := range m.Files {
		out = append(out, f.Name)
	}
	return out
}

func queryInt(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// egressPayloads returns the payloads of the outbox rows of one kind, oldest first.
func egressPayloads(t *testing.T, kind string) []string {
	t.Helper()
	rows, err := testPool.Query(context.Background(), `SELECT payload::text FROM egress_outbox WHERE kind = $1 ORDER BY id`, kind)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

var ipSeq int64

// nextIP gives every request its own anonymous group so the limiter never shapes a test.
func nextIP() string {
	ipSeq++
	return fmt.Sprintf("10.%d.%d.%d", 50+ipSeq/65536%200, ipSeq/256%256, 1+ipSeq%250)
}

func (e *tenv) get(t *testing.T, path string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	req.Header.Set("CF-Connecting-IP", nextIP())
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), res.Header
}

// writeFakeShard writes a small gzip JSONL shard with the given ids.
func writeFakeShard(t *testing.T, path string, ids ...string) {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	for _, id := range ids {
		fmt.Fprintf(gz, `{"id":%q,"title":"x"}`+"\n", id)
	}
	gz.Close()
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- tests -------------------------------------------------------------------------------------

func TestDailyExportFilesAndManifest(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, seedRoot := e.identity(t, false), e.identity(t, true)
	k1 := e.kb(t, kbIn{root: root, symptom: "read ECONNRESET", fix: "retry with keepalive", versions: "node@22.9, npm@10.8", tags: []string{"npm", "proxy"}, okW: 2})
	k2 := e.kb(t, kbIn{root: seedRoot, seed: true, fix: "seed fix"})
	n := e.task(t, root, "Investigate flaky CI", "body", "open", "", false)
	v := e.claim(t, root, "unverified", false)
	dg := e.digest(t, root, "live", false)

	if err := e.s.Regen(ctx); err != nil {
		t.Fatal(err)
	}
	m := checkIntegrity(t, e.dir)
	if m.Date != today() || m.License != "CC0-1.0" || m.Retention != Retention || m.Latest != "kb-"+today()+".jsonl.gz" || m.Generated == "" {
		t.Fatalf("manifest head: %+v", m)
	}
	names := shardNames(m)
	for _, kind := range shardKinds {
		want := kind + "-" + today() + ".jsonl.gz"
		found := false
		for _, n := range names {
			found = found || n == want
		}
		if !found {
			t.Fatalf("manifest lacks %s: %v", want, names)
		}
	}
	rows := idsOf(gzRows(t, filepath.Join(e.dir, "kb-"+today()+".jsonl.gz")))
	r1, r2 := rows[k1], rows[k2]
	if r1 == nil || r2 == nil {
		t.Fatalf("kb shard lacks %s/%s: %v", k1, k2, names)
	}
	if r1["author"] != root || r2["author"] != "seed" || r1["license"] != "CC0-1.0" || r1["url"] != "https://agents.example/k/"+k1 ||
		r1["kind"] != "fix" || r1["fix"] != "retry with keepalive" || r1["rev"].(float64) != 1 || len(r1["md_sha256"].(string)) != 64 {
		t.Fatalf("kb row: %v", r1)
	}
	if libs := r1["libs"].([]any); len(libs) != 2 || r1["tags"].([]any)[0] != "npm" || r1["ok_w"].(float64) != 2 {
		t.Fatalf("kb row libs/tags: %v", r1)
	}
	for _, key := range []string{"id", "kind", "title", "symptom", "cause", "fix", "versions", "libs", "tags", "ok_w", "bad_w", "created", "confirmed_at", "url", "author", "license", "rev", "md_sha256"} {
		if _, ok := r1[key]; !ok {
			t.Fatalf("kb row lacks %s", key)
		}
	}
	full, err := kb.GetV2(ctx, testPool, k1, kb.GetOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256([]byte(full.Markdown())); hex.EncodeToString(sum[:]) != r1["md_sha256"] {
		t.Fatal("md_sha256 is not the sha256 of the Markdown rendition")
	}
	tasks := idsOf(gzRows(t, filepath.Join(e.dir, "tasks-"+today()+".jsonl.gz")))
	if tr := tasks[strconv.FormatInt(n, 10)]; tr == nil || tr["title"] != "Investigate flaky CI" || tr["url"] != "https://agents.example/t/"+strconv.FormatInt(n, 10) || tr["author"] != root || tr["state"] != "open" {
		t.Fatalf("task row: %v", tr)
	}
	claims := idsOf(gzRows(t, filepath.Join(e.dir, "claims-"+today()+".jsonl.gz")))
	if cr := claims[v]; cr == nil || cr["lib"] != "npm:react" || cr["status"] != "unverified" || cr["author"] != root {
		t.Fatalf("claim row: %v", cr)
	}
	digests := idsOf(gzRows(t, filepath.Join(e.dir, "digests-"+today()+".jsonl.gz")))
	if dr := digests[dg]; dr == nil || dr["topic"] != "api" || dr["body"] != "body of "+dg {
		t.Fatalf("digest row: %v", dr)
	}
	for _, aux := range []string{"croissant.json", "README.md", "tombstones.jsonl", "SIGNATURES"} {
		if _, err := os.Stat(filepath.Join(e.dir, aux)); err != nil {
			t.Fatalf("%s: %v", aux, err)
		}
	}
	readme, _ := os.ReadFile(filepath.Join(e.dir, "README.md"))
	if !strings.Contains(string(readme), "openssl pkeyutl -verify") || !strings.Contains(string(readme), "-rawin") || !strings.Contains(string(readme), "license: cc0-1.0") {
		t.Fatal("README lacks the verification recipe or the card front matter")
	}
	var used string
	if err := testPool.QueryRow(ctx, `SELECT s FROM flags WHERE k = 'export:bytes'`).Scan(&used); err != nil || used == "" || used == "0" {
		t.Fatalf("export:bytes flag: %q %v", used, err)
	}
	if entries, _ := os.ReadDir(e.dir); len(entries) == 0 {
		t.Fatal("empty dir")
	} else {
		for _, en := range entries {
			if strings.HasSuffix(en.Name(), ".tmp") {
				t.Fatalf("temp file left behind: %s", en.Name())
			}
		}
	}
}

func TestTickDailyFlag(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := e.identity(t, false)
	e.kb(t, kbIn{root: root})
	clock := time.Date(2026, 10, 7, 1, 30, 0, 0, time.UTC)
	e.s.now = func() time.Time { return clock }
	// Nothing exported yet: the first tick runs whatever the hour is.
	if err := e.s.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.d.Flag("export:2026-10-07") || readManifest(t, e.dir).Date != "2026-10-07" {
		t.Fatal("first tick did not export or flag the day")
	}
	gen := readManifest(t, e.dir).Generated
	clock = clock.Add(time.Hour)
	if err := e.s.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if readManifest(t, e.dir).Generated != gen {
		t.Fatal("second tick of the day re-exported")
	}
	clock = time.Date(2026, 10, 8, 2, 0, 0, 0, time.UTC) // next day, before 03:00: wait
	if err := e.s.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if e.d.Flag("export:2026-10-08") {
		t.Fatal("exported before 03:00")
	}
	clock = time.Date(2026, 10, 8, 3, 0, 30, 0, time.UTC)
	if err := e.s.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.d.Flag("export:2026-10-08") || readManifest(t, e.dir).Date != "2026-10-08" {
		t.Fatal("03:00 tick did not export")
	}
	// Old day flags are pruned beyond 10 days.
	e.d.SetFlag(ctx, "export:2026-09-01", true, "")
	clock = time.Date(2026, 10, 9, 3, 1, 0, 0, time.UTC)
	if err := e.s.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if queryInt(t, `SELECT count(*) FROM flags WHERE k = 'export:2026-09-01'`) != 0 || queryInt(t, `SELECT count(*) FROM flags WHERE k = 'export:2026-10-08'`) != 1 {
		t.Fatal("flag pruning")
	}
}

func TestOnlyVisibleRowsAndMaskRerun(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := e.identity(t, false)
	kv := e.kb(t, kbIn{root: root, symptom: "mail me at bob@corp-example.org from 51.15.22.3 when read ECONNRESET shows up", space: "team-a"})
	kh := e.kb(t, kbIn{root: root, hidden: true})
	kq := e.kb(t, kbIn{root: root, quarantine: true})
	ke := e.kb(t, kbIn{root: root, expired: true})
	ks := e.kb(t, kbIn{root: root, superseded: kv})
	tv := e.task(t, root, "visible task", "body", "open", "team-a", false)
	th := e.task(t, root, "hidden task", "body", "hidden", "", false)
	tq := e.task(t, root, "quarantined task", "body", "open", "", true)
	cv := e.claim(t, root, "verified", false)
	cr := e.claim(t, root, "retracted", false)
	ch := e.claim(t, root, "unverified", true)
	cd := e.claim(t, root, "disputed", false)
	cq := e.claim(t, root, "quarantine", false)
	dv := e.digest(t, root, "live", false)
	dh := e.digest(t, root, "live", true)
	dq := e.digest(t, root, "quarantine", false)

	if err := e.s.Regen(ctx); err != nil {
		t.Fatal(err)
	}
	kbRows := idsOf(gzRows(t, filepath.Join(e.dir, "kb-"+today()+".jsonl.gz")))
	if kbRows[kv] == nil {
		t.Fatal("visible entry missing")
	}
	for _, id := range []string{kh, kq, ke, ks} {
		if kbRows[id] != nil {
			t.Fatalf("non-visible entry %s exported", id)
		}
	}
	if sym := kbRows[kv]["symptom"].(string); strings.Contains(sym, "bob@corp-example.org") || strings.Contains(sym, "51.15.22.3") || !strings.Contains(sym, "<email>") || !strings.Contains(sym, "<ip>") {
		t.Fatalf("symptom not re-masked: %q", sym)
	}
	tasks := idsOf(gzRows(t, filepath.Join(e.dir, "tasks-"+today()+".jsonl.gz")))
	if tasks[strconv.FormatInt(tv, 10)] == nil || tasks[strconv.FormatInt(th, 10)] != nil || tasks[strconv.FormatInt(tq, 10)] != nil {
		t.Fatal("task visibility")
	}
	claims := idsOf(gzRows(t, filepath.Join(e.dir, "claims-"+today()+".jsonl.gz")))
	if claims[cv] == nil || claims[cr] != nil || claims[ch] != nil || claims[cd] != nil || claims[cq] != nil {
		t.Fatal("claim visibility")
	}
	digests := idsOf(gzRows(t, filepath.Join(e.dir, "digests-"+today()+".jsonl.gz")))
	if digests[dv] == nil || digests[dh] != nil || digests[dq] != nil {
		t.Fatal("digest visibility")
	}

	// Row: the same predicate, one object at a time (27.7 sync).
	if row, ok, err := Row(ctx, testPool, "kb", kv); err != nil || !ok || row["id"] != kv || strings.Contains(row["symptom"].(string), "bob@") {
		t.Fatalf("Row kb: %v %v %v", row, ok, err)
	}
	for _, c := range []struct{ kind, id string }{{"kb", kh}, {"kb", kq}, {"kb", ke}, {"kb", ks}, {"task", strconv.FormatInt(th, 10)}, {"task", strconv.FormatInt(tq, 10)},
		{"claim", cr}, {"claim", ch}, {"digest", dh}, {"digest", dq}, {"kb", "kzzzzzz"}, {"task", "0"}, {"task", "abc"}, {"claim", "bad id"}} {
		if row, ok, err := Row(ctx, testPool, c.kind, c.id); err != nil || ok || row != nil {
			t.Fatalf("Row %s %s: %v %v %v", c.kind, c.id, row, ok, err)
		}
	}
	if _, ok, _ := Row(ctx, testPool, "task", strconv.FormatInt(tv, 10)); !ok {
		t.Fatal("Row task visible")
	}
	if _, ok, _ := Row(ctx, testPool, "claim", cv); !ok {
		t.Fatal("Row claim visible")
	}
	if _, ok, _ := Row(ctx, testPool, "digest", dv); !ok {
		t.Fatal("Row digest visible")
	}
	if _, _, err := Row(ctx, testPool, "svc", "x"); err == nil {
		t.Fatal("Row unknown kind must error")
	}

	// SpaceJSONL: space-filtered, hidden/quarantined excluded, src selects the kinds.
	var buf bytes.Buffer
	if err := SpaceJSONL(ctx, testPool, "team-a", "", &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, kv) || !strings.Contains(out, `"n":`+strconv.FormatInt(tv, 10)+",") || strings.Contains(out, kh) || strings.Contains(out, kq) {
		t.Fatalf("SpaceJSONL: %s", out)
	}
	buf.Reset()
	if err := SpaceJSONL(ctx, testPool, "team-a", "kb", &buf); err != nil || !strings.Contains(buf.String(), kv) || strings.Contains(buf.String(), `"n":`) {
		t.Fatalf("SpaceJSONL kb: %v %s", err, buf.String())
	}
	buf.Reset()
	if err := SpaceJSONL(ctx, testPool, "team-a", "t", &buf); err != nil || strings.Contains(buf.String(), kv) || !strings.Contains(buf.String(), `"n":`) {
		t.Fatalf("SpaceJSONL t: %v %s", err, buf.String())
	}
	if SpaceJSONL(ctx, testPool, "Bad Slug", "", &buf) == nil || SpaceJSONL(ctx, testPool, "team-a", "mail", &buf) == nil {
		t.Fatal("SpaceJSONL must refuse a bad slug or src")
	}
}

func TestTombstones(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	recent, old := core.NewID('k'), core.NewID('k')
	for _, r := range []struct {
		id, reason, at string
	}{{recent, "retract", "1 day"}, {old, "expire", "100 days"}} {
		if _, err := testPool.Exec(ctx, `INSERT INTO kb_tombstones (id, title, reason, at) VALUES ($1, 'secret title', $2, now() - interval '`+r.at+`')`, r.id, r.reason); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.s.Regen(ctx); err != nil {
		t.Fatal(err)
	}
	lines := readTombstones(filepath.Join(e.dir, "tombstones.jsonl"))
	byID := map[string]tombstone{}
	for _, l := range lines {
		byID[l.ID] = l
	}
	if tb := byID[recent]; tb.Kind != "kb" || tb.Reason != "retract" || tb.RemovedAt.IsZero() {
		t.Fatalf("recent tombstone: %+v", tb)
	}
	if _, ok := byID[old]; ok {
		t.Fatal("tombstone older than 90 d exported")
	}
	raw, _ := os.ReadFile(filepath.Join(e.dir, "tombstones.jsonl"))
	if strings.Contains(string(raw), "secret title") || strings.Contains(string(raw), `"title"`) {
		t.Fatal("tombstones carry content")
	}
	// Remove appends a tombstone for kinds without a table; the daily regeneration keeps it.
	cid := core.NewID('v')
	Remove(ctx, "claim", cid)
	if tb := readTombstoneByID(t, e.dir, cid); tb.Kind != "claim" || tb.Reason != "removed" {
		t.Fatalf("appended tombstone: %+v", tb)
	}
	if err := e.s.Regen(ctx); err != nil {
		t.Fatal(err)
	}
	if tb := readTombstoneByID(t, e.dir, cid); tb.Kind != "claim" {
		t.Fatal("appended tombstone lost on regeneration")
	}
	dup := 0
	for _, l := range readTombstones(filepath.Join(e.dir, "tombstones.jsonl")) {
		if l.ID == recent {
			dup++
		}
	}
	if dup != 1 {
		t.Fatalf("tombstone %s listed %d times", recent, dup)
	}
	// A kb removal appended before its table row is visible gets the table's reason on the next run.
	kid := core.NewID('k')
	Remove(ctx, "kb", kid)
	if _, err := testPool.Exec(ctx, `INSERT INTO kb_tombstones (id, title, reason) VALUES ($1, '', 'purge')`, kid); err != nil {
		t.Fatal(err)
	}
	if err := e.s.Regen(ctx); err != nil {
		t.Fatal(err)
	}
	if tb := readTombstoneByID(t, e.dir, kid); tb.Reason != "purge" {
		t.Fatalf("table reason did not win: %+v", tb)
	}
	// Unsafe lines in the file never survive a rewrite.
	f, _ := os.OpenFile(filepath.Join(e.dir, "tombstones.jsonl"), os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(`{"id":"../../etc","kind":"kb","removed_at":"2026-10-01T00:00:00Z","reason":"x"}` + "\nnot json\n")
	f.Close()
	if err := e.s.Regen(ctx); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(e.dir, "tombstones.jsonl"))
	if strings.Contains(string(raw), "etc") || strings.Contains(string(raw), "not json") {
		t.Fatal("unsafe tombstone lines kept")
	}
}

func readTombstoneByID(t *testing.T, dir, id string) tombstone {
	t.Helper()
	for _, l := range readTombstones(filepath.Join(dir, "tombstones.jsonl")) {
		if l.ID == id {
			return l
		}
	}
	t.Fatalf("tombstone %s missing", id)
	return tombstone{}
}

func TestRetentionLatestPlusSeven(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	clock := time.Date(2026, 10, 7, 4, 0, 0, 0, time.UTC)
	e.s.now = func() time.Time { return clock }
	if err := os.MkdirAll(e.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var dates []string
	for i := 1; i <= 17; i++ {
		d := clock.AddDate(0, 0, -i).Format(dateFmt)
		dates = append(dates, d)
		for _, kind := range []string{"kb", "tasks"} {
			writeFakeShard(t, filepath.Join(e.dir, kind+"-"+d+".jsonl.gz"), "k"+strconv.Itoa(i))
		}
	}
	writeFakeShard(t, filepath.Join(e.dir, "delta-"+dates[11]+".jsonl.gz"), "x")
	writeFakeShard(t, filepath.Join(e.dir, "delta-"+dates[2]+".jsonl.gz"), "y")
	stale := filepath.Join(e.dir, ".kb-old.jsonl.gz.1.tmp")
	os.WriteFile(stale, []byte("x"), 0o644)
	os.Chtimes(stale, time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour))

	if err := e.s.Regen(ctx); err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	entries, _ := os.ReadDir(e.dir)
	for _, en := range entries {
		if m := FileRe.FindStringSubmatch(en.Name()); m != nil {
			kept[m[2]] = true
		}
		if strings.HasSuffix(en.Name(), ".tmp") {
			t.Fatalf("stale temp file kept: %s", en.Name())
		}
	}
	if len(kept) != keepDailies+1 || !kept["2026-10-07"] {
		t.Fatalf("kept dates: %v", kept)
	}
	for i, d := range dates {
		if kept[d] != (i < keepDailies) {
			t.Fatalf("date %s kept=%v (i=%d)", d, kept[d], i)
		}
	}
	if _, err := os.Stat(filepath.Join(e.dir, "delta-"+dates[2]+".jsonl.gz")); err != nil {
		t.Fatal("recent delta shard dropped")
	}
	m := checkIntegrity(t, e.dir)
	for _, f := range m.Files {
		if !kept[FileRe.FindStringSubmatch(f.Name)[2]] {
			t.Fatalf("manifest lists a dropped file %s", f.Name)
		}
	}
	if len(m.Files) != 4+2*keepDailies+1 {
		t.Fatalf("manifest files: %d", len(m.Files))
	}
	// The byte cap drops the oldest dates first and never the latest.
	old := MaxBytes
	t.Cleanup(func() { MaxBytes = old })
	MaxBytes = 1
	if err := e.s.retain(); err != nil {
		t.Fatal(err)
	}
	entries, _ = os.ReadDir(e.dir)
	for _, en := range entries {
		if m := FileRe.FindStringSubmatch(en.Name()); m != nil && m[2] != "2026-10-07" {
			t.Fatalf("cap kept %s", en.Name())
		}
	}
	for _, kind := range shardKinds {
		if _, err := os.Stat(filepath.Join(e.dir, kind+"-2026-10-07.jsonl.gz")); err != nil {
			t.Fatalf("latest %s dropped by the cap", kind)
		}
	}
}

func TestRemoveRewritesEveryRetainedFileAndEnqueuesPurge(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := e.identity(t, false)
	k1 := e.kb(t, kbIn{root: root, fix: "fix one"})
	k2 := e.kb(t, kbIn{root: root, fix: "fix two"})
	if err := e.s.Regen(ctx); err != nil {
		t.Fatal(err)
	}
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format(dateFmt)
	cur := filepath.Join(e.dir, "kb-"+today()+".jsonl.gz")
	src, _ := os.ReadFile(cur)
	if err := os.WriteFile(filepath.Join(e.dir, "kb-"+yesterday+".jsonl.gz"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	writeFakeShard(t, filepath.Join(e.dir, "delta-"+today()+".jsonl.gz"), k1, k2)
	writeFakeShard(t, filepath.Join(e.dir, "tasks-"+yesterday+".jsonl.gz"), "77")
	before := len(egressPayloads(t, "hf"))

	Remove(ctx, "kb", k1)

	entries, _ := os.ReadDir(e.dir)
	var shards []string
	for _, en := range entries {
		if !FileRe.MatchString(en.Name()) {
			continue
		}
		shards = append(shards, en.Name())
		rows := idsOf(gzRows(t, filepath.Join(e.dir, en.Name())))
		if rows[k1] != nil {
			t.Fatalf("%s still contains %s", en.Name(), k1)
		}
		if strings.HasPrefix(en.Name(), "kb-") || strings.HasPrefix(en.Name(), "delta-") {
			if rows[k2] == nil {
				t.Fatalf("%s lost %s", en.Name(), k2)
			}
		}
	}
	if len(shards) != 7 {
		t.Fatalf("shards: %v", shards)
	}
	if zgrep, err := exec.LookPath("zgrep"); err == nil {
		args := append([]string{"-l", k1}, func() []string {
			var ps []string
			for _, s := range shards {
				ps = append(ps, filepath.Join(e.dir, s))
			}
			return ps
		}()...)
		out, err := exec.Command(zgrep, args...).CombinedOutput()
		if err == nil || len(bytes.TrimSpace(out)) > 0 {
			t.Fatalf("zgrep still finds %s: %s", k1, out)
		}
	}
	m := checkIntegrity(t, e.dir)
	if m.Date != today() || len(m.Files) != 7 {
		t.Fatalf("manifest after remove: %+v", m)
	}
	for _, f := range m.Files {
		if strings.HasPrefix(f.Name, "kb-") && f.Rows != int64(len(gzRows(t, filepath.Join(e.dir, f.Name)))) {
			t.Fatalf("rows of %s not refreshed", f.Name)
		}
	}
	if tb := readTombstoneByID(t, e.dir, k1); tb.Kind != "kb" {
		t.Fatalf("tombstone: %+v", tb)
	}
	purges := egressPayloads(t, "cf_purge")
	if len(purges) == 0 {
		t.Fatal("no cf_purge row")
	}
	last := purges[len(purges)-1]
	for _, u := range []string{"https://agents.example/export/kb-" + today() + ".jsonl.gz", "https://agents.example/export/kb-" + yesterday + ".jsonl.gz",
		"https://agents.example/export/delta-" + today() + ".jsonl.gz", "https://agents.example/export/manifest.json", "https://agents.example/export/tombstones.jsonl",
		"https://agents.example/export/SHA256SUMS", "https://agents.example/export/"} {
		if !strings.Contains(last, u) {
			t.Fatalf("cf_purge lacks %s: %s", u, last)
		}
	}
	if strings.Contains(last, "tasks-"+yesterday) {
		t.Fatal("cf_purge lists an untouched shard")
	}
	mirrors := egressPayloads(t, "mirror_rewrite")
	if len(mirrors) == 0 || !strings.Contains(mirrors[len(mirrors)-1], `"id": "`+k1+`"`) && !strings.Contains(mirrors[len(mirrors)-1], `"id":"`+k1+`"`) {
		t.Fatalf("mirror_rewrite: %v", mirrors)
	}
	hf := egressPayloads(t, "hf")[before:]
	want := map[string]bool{"kb-" + today() + ".jsonl.gz": true, "kb-" + yesterday + ".jsonl.gz": true}
	for _, p := range hf {
		var pl struct{ File string }
		json.Unmarshal([]byte(p), &pl)
		if !want[pl.File] {
			t.Fatalf("unexpected hf row %s", p)
		}
		delete(want, pl.File)
	}
	if len(want) != 0 {
		t.Fatalf("hf rows missing for %v", want)
	}

	// An id in no file: tombstone + aux only; an invalid id: nothing at all.
	n1, n2 := len(egressPayloads(t, "cf_purge")), len(egressPayloads(t, "hf"))
	Remove(ctx, "digest", core.NewID('d'))
	if len(egressPayloads(t, "cf_purge")) != n1+1 || len(egressPayloads(t, "hf")) != n2 {
		t.Fatal("removal of an unexported id must purge the aux files only")
	}
	checkIntegrity(t, e.dir)
	Remove(ctx, "kb", "../../etc/passwd")
	Remove(ctx, "svc", k2)
	if len(egressPayloads(t, "cf_purge")) != n1+1 {
		t.Fatal("invalid removal enqueued work")
	}
	// The seam installed by Register reaches the same path.
	core.ExportRemove(ctx, "kb", k2)
	if rows := idsOf(gzRows(t, cur)); rows[k2] != nil {
		t.Fatal("core.ExportRemove did not rewrite")
	}
}

func TestRoutesAllowlistAndLatestRedirect(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if st, body, _ := e.get(t, "/export/"); st != 200 || !strings.Contains(body, "export none yet") || !strings.Contains(body, `"Dataset"`) {
		t.Fatalf("empty page: %d %s", st, body)
	}
	if st, _, _ := e.get(t, "/export/latest.jsonl.gz"); st != 404 {
		t.Fatalf("latest before export: %d", st)
	}
	root := e.identity(t, false)
	k1 := e.kb(t, kbIn{root: root})
	if err := e.s.Regen(ctx); err != nil {
		t.Fatal(err)
	}
	shard := "kb-" + today() + ".jsonl.gz"

	st, body, h := e.get(t, "/export/")
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/html") || !strings.Contains(body, `"@type":"Dataset"`) || !strings.Contains(body, shard) ||
		!strings.Contains(body, "export "+today()) || !strings.Contains(h.Get("Cache-Control"), "max-age=3600") {
		t.Fatalf("page: %d %s %v", st, body, h)
	}
	if strings.Contains(body, "noindex") {
		t.Fatal("dataset page must be indexable")
	}
	if st, _, h := e.get(t, "/export/", "Accept", "text/markdown"); st != 303 || h.Get("Location") != "/export/index.md" {
		t.Fatalf("twin redirect: %d %v", st, h)
	}
	if st, body, h := e.get(t, "/export/index.md"); st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/markdown") || !strings.HasPrefix(body, "# Open data") || !strings.Contains(body, shard) {
		t.Fatalf("index.md: %d %s", st, body)
	}
	if st, body, _ := e.get(t, "/export/index.txt"); st != 200 || !strings.HasPrefix(body, "export "+today()) {
		t.Fatalf("index.txt: %d %s", st, body)
	}
	if st, body, _ := e.get(t, "/export/index.json"); st != 200 || !json.Valid([]byte(body)) {
		t.Fatalf("index.json: %d %s", st, body)
	}
	for name, ct := range auxTypes {
		st, body, h := e.get(t, "/export/"+name)
		if st != 200 || h.Get("Content-Type") != ct || len(body) == 0 || h.Get("ETag") == "" || !strings.Contains(h.Get("Cache-Control"), "public") {
			t.Fatalf("%s: %d %q %v", name, st, h.Get("Content-Type"), h)
		}
	}
	if st, body, _ := e.get(t, "/export/manifest.json"); st != 200 || !strings.Contains(body, `"sig"`) {
		t.Fatalf("manifest: %d %s", st, body)
	}
	st, _, h = e.get(t, "/export/latest.jsonl.gz")
	if st != 302 || h.Get("Location") != "/export/"+shard {
		t.Fatalf("latest: %d %v", st, h)
	}
	st, body, h = e.get(t, "/export/"+shard)
	if st != 200 || h.Get("Content-Type") != "application/gzip" || !strings.Contains(h.Get("Cache-Control"), "public, max-age=3600") || h.Get("ETag") == "" ||
		!strings.Contains(h.Get("X-Next"), "GET /export/manifest.json") || !strings.Contains(strings.Join(h.Values("Link"), ","), "describedby") {
		t.Fatalf("shard: %d %v", st, h)
	}
	gz, err := gzip.NewReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := io.ReadAll(gz); !strings.Contains(string(raw), k1) {
		t.Fatal("shard body")
	}
	if st, _, _ := e.get(t, "/export/"+shard, "If-None-Match", h.Get("ETag")); st != 304 {
		t.Fatalf("conditional shard: %d", st)
	}
	req, _ := http.NewRequest(http.MethodHead, e.srv.URL+"/export/"+shard, nil)
	req.Header.Set("CF-Connecting-IP", nextIP())
	if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/gzip" {
		t.Fatalf("HEAD shard: %v", err)
	}
	if st, _, h := e.get(t, "/export/"+shard, "Authorization", "Bearer cx_"+strings.Repeat("a", 43)); st != 200 || !strings.Contains(h.Get("Cache-Control"), "private") {
		t.Fatalf("token download must be private: %d %v", st, h)
	}
	os.WriteFile(filepath.Join(e.dir, "evil.jsonl.gz"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(e.dir, "notes.txt"), []byte("x"), 0o644)
	for _, p := range []string{"/export/evil.jsonl.gz", "/export/" + shard + ".tmp", "/export/kb-2026-1-1.jsonl.gz", "/export/." + shard + ".1.tmp",
		"/export/manifest.json.bak", "/export/notes.txt", "/export/KB-" + today() + ".jsonl.gz", "/export/kb-" + today() + ".jsonl", "/export/a/b"} {
		if st, body, _ := e.get(t, p); st != 404 {
			t.Fatalf("%s: %d %s", p, st, body)
		}
	}
	if st, body, _ := e.get(t, "/export/..%2Fmanifest.json"); st == 200 && strings.Contains(body, `"files"`) {
		t.Fatal("traversal served the manifest")
	}
	if st, _, h := e.get(t, "/data/"); st != 301 || h.Get("Location") != "/export/" {
		t.Fatalf("/data/: %d %v", st, h)
	}
	if st, _, h := e.get(t, "/data/manifest.json"); st != 301 || h.Get("Location") != "/export/manifest.json" {
		t.Fatalf("/data/manifest.json: %d %v", st, h)
	}
	if st, _, h := e.get(t, "/data/evil"); st != 301 || h.Get("Location") != "/export/" {
		t.Fatalf("/data/evil: %d %v", st, h)
	}
	// The op renders the same page, tail-free.
	out, err := Ops(e.d)["dump"](ctx, nil, nil)
	if err != nil || !strings.HasPrefix(out, "export "+today()) || strings.Contains(out, "next:") || !strings.Contains(out, shard) {
		t.Fatalf("dump op: %v %q", err, out)
	}
	if _, ok := OpMeta["dump"]; !ok || Help == "" {
		t.Fatal("op meta")
	}
	// Every registered route carries a scope and appears in the OpenAPI fragment.
	var frag struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(openAPI, &frag); err != nil {
		t.Fatal(err)
	}
	for _, pat := range []string{"GET /export/{$}", "GET /export/latest.jsonl.gz", "GET /export/{file}", "GET /data/", "GET /export/manifest.json", "GET /export/SIGNATURES", "GET /export/README.md"} {
		if sc, ok := e.d.ScopeOf(pat); !ok || sc != "kb:r" {
			t.Fatalf("scope of %s: %q %v", pat, sc, ok)
		}
		p := strings.TrimPrefix(pat, "GET ")
		p = strings.TrimSuffix(p, "{$}")
		if _, ok := frag.Paths[p]; !ok {
			t.Fatalf("openapi lacks %s", p)
		}
	}
	if e.d.CostOf("GET /export/{file}") != 3 {
		t.Fatal("shard cost")
	}
	if urls, err := e.s.sitemap(ctx); err != nil || len(urls) != 1 || urls[0].Loc != "https://agents.example/export/" || urls[0].LastMod.IsZero() {
		t.Fatalf("sitemap: %v %v", urls, err)
	}
}

func TestCroissantValidJSON(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := e.identity(t, false)
	e.kb(t, kbIn{root: root})
	e.task(t, root, "a task", "body", "open", "", false)
	if err := e.s.Regen(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(e.dir, "croissant.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatal("croissant.json is not valid JSON")
	}
	var c struct {
		Context    map[string]any   `json:"@context"`
		Type       string           `json:"@type"`
		ConformsTo string           `json:"conformsTo"`
		Name       string           `json:"name"`
		License    string           `json:"license"`
		URL        string           `json:"url"`
		Dist       []map[string]any `json:"distribution"`
		RecordSets []struct {
			ID     string           `json:"@id"`
			Fields []map[string]any `json:"field"`
			Key    map[string]any   `json:"key"`
		} `json:"recordSet"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Type != "sc:Dataset" || c.ConformsTo != "http://mlcommons.org/croissant/1.0" || c.Context["cr"] != "http://mlcommons.org/croissant/" ||
		c.Name == "" || c.License != core.LicenseURL("CC0-1.0") || c.URL != "https://agents.example/export/" {
		t.Fatalf("croissant head: %+v", c)
	}
	m := readManifest(t, e.dir)
	ids := map[string]bool{}
	for _, d := range c.Dist {
		ids[d["@id"].(string)] = true
	}
	for _, f := range m.Files {
		found := false
		for _, d := range c.Dist {
			if d["@id"] == f.Name {
				found = true
				if d["sha256"] != f.SHA256 || d["@type"] != "cr:FileObject" || d["contentUrl"] != "https://agents.example/export/"+f.Name || d["encodingFormat"] != "application/gzip" {
					t.Fatalf("distribution %s: %v", f.Name, d)
				}
			}
		}
		if !found || !ids[strings.TrimSuffix(f.Name, ".gz")] {
			t.Fatalf("croissant lacks %s or its jsonl", f.Name)
		}
	}
	sets := map[string]bool{}
	fieldIDs := map[string]bool{}
	for _, rs := range c.RecordSets {
		sets[rs.ID] = true
		if len(rs.Fields) == 0 || rs.Key["@id"] != rs.ID+"/id" {
			t.Fatalf("recordSet %s: %+v", rs.ID, rs)
		}
		for _, f := range rs.Fields {
			id := f["@id"].(string)
			if fieldIDs[id] {
				t.Fatalf("duplicate field %s", id)
			}
			fieldIDs[id] = true
			src := f["source"].(map[string]any)["fileObject"].(map[string]any)["@id"].(string)
			if !ids[src] {
				t.Fatalf("field %s sources unknown file %s", id, src)
			}
		}
	}
	for _, k := range append(append([]string(nil), shardKinds...), "tombstones") {
		if !sets[k] {
			t.Fatalf("recordSet %s missing", k)
		}
	}
	if !fieldIDs["kb/md_sha256"] || !fieldIDs["kb/rev"] || !fieldIDs["tasks/n"] || !fieldIDs["tombstones/reason"] {
		t.Fatal("expected fields missing")
	}
	// Served with the JSON-LD content type and byte-identical to the file.
	if st, body, h := e.get(t, "/export/croissant.json"); st != 200 || h.Get("Content-Type") != "application/ld+json" || body != string(raw) {
		t.Fatalf("croissant route: %d %s", st, h.Get("Content-Type"))
	}
}

func TestHFEnqueue(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := e.identity(t, false)
	k1 := e.kb(t, kbIn{root: root})
	before := len(egressPayloads(t, "hf"))
	if err := e.s.Regen(ctx); err != nil {
		t.Fatal(err)
	}
	got := egressPayloads(t, "hf")[before:]
	if len(got) != 4 {
		t.Fatalf("hf rows after export: %v", got)
	}
	want := map[string]bool{}
	for _, kind := range shardKinds {
		want[kind+"-"+today()+".jsonl.gz"] = true
	}
	for _, p := range got {
		var pl map[string]any
		if err := json.Unmarshal([]byte(p), &pl); err != nil || len(pl) != 1 || !want[fmt.Sprint(pl["file"])] {
			t.Fatalf("hf payload %s", p)
		}
		delete(want, fmt.Sprint(pl["file"]))
	}
	if len(want) != 0 {
		t.Fatalf("hf rows missing: %v", want)
	}
	n := len(egressPayloads(t, "hf"))
	Remove(ctx, "kb", k1)
	got = egressPayloads(t, "hf")[n:]
	if len(got) != 1 || !strings.Contains(got[0], "kb-"+today()+".jsonl.gz") {
		t.Fatalf("hf rows after removal: %v", got)
	}
}
