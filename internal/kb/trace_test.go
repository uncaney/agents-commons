package kb

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// newTraceEnv is newEnv with RegisterTrace mounted (POST /e, /q, /v1/q, GET /ci and the dry routes).
func newTraceEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, PowBitsW: 4, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	RegisterAnon(mux, d)
	RegisterTrace(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	e := &tenv{d: d, srv: srv, ip: nextIP(), cfg: cfg}
	t.Cleanup(func() {
		ctx := context.Background()
		testPool.Exec(ctx, `DELETE FROM kb_votes WHERE root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `DELETE FROM kb WHERE author_root = ANY($1)`, e.roots)
	})
	return e
}

// uniqName is a registration-safe unique name ([a-zA-Z0-9._-]{1,32}).
func uniqName() string { return strings.ReplaceAll(uniq("u"), " ", "") }

// seedFix posts a visible fix from a fresh L2 root and returns its id.
func (e *tenv) seedFix(t *testing.T, title, symptom, fix string) string {
	t.Helper()
	_, tok := e.registerL(t, uniqName(), 2)
	st, body, _ := e.do(t, "POST", "/v1/kb", tok, map[string]any{"kind": "fix", "title": title, "symptom": symptom, "fix": fix, "force": true})
	if st != 201 {
		t.Fatalf("seed fix: %d %s", st, body)
	}
	id := strings.Fields(body)[1]
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM kb WHERE id = $1`, id) })
	return id
}

func (e *tenv) postE(t *testing.T, path, body string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	hs := append([]string{"Content-Type", "text/plain"}, hdr...)
	return e.do(t, "POST", path, "", body, hs...)
}

// --- FromTrace unit tests -------------------------------------------------------------------------

func TestFromTraceRecognisers(t *testing.T) {
	cases := []struct {
		name, lang, wantSig string
		in                  string
	}{
		{"python", "python", "ModuleNotFoundError", `Traceback (most recent call last):
  File "/app/main.py", line 3, in <module>
    import yaml
ModuleNotFoundError: No module named 'yaml'`},
		{"node", "node", "Error", `Error: Cannot find module 'express'
    at Function.Module._resolveFilename (node:internal/modules/cjs/loader:1145:15)
    at Function.Module._load (node:internal/modules/cjs/loader:986:27)`},
		{"go", "go", "panic", `panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1]

goroutine 1 [running]:
main.main()
	/app/main.go:10 +0x18`},
		{"java", "java", "NullPointerException", `Exception in thread "main" java.lang.NullPointerException: Cannot invoke "String.length()"
	at com.example.App.main(App.java:12)`},
		{"rust", "rust", "panicked at", `thread 'main' panicked at 'index out of bounds: the len is 3 but the index is 5', src/main.rs:10:5
note: run with RUST_BACKTRACE=1 environment variable to display a backtrace`},
		{"dotnet", "dotnet", "NullReferenceException", `Unhandled exception. System.NullReferenceException: Object reference not set to an instance of an object.
   at Program.Main(String[] args) in /app/Program.cs:line 7`},
		{"generic", "", "KafkaTimeoutError", `2026-10-07 12:00:01 WARN producer retrying
2026-10-07 12:00:02 KafkaTimeoutError: failed to produce after 30000 ms`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sig, _, lang := FromTrace([]byte(c.in))
			if lang != c.lang {
				t.Errorf("lang = %q, want %q", lang, c.lang)
			}
			if !strings.Contains(sig, c.wantSig) {
				t.Errorf("sig = %q, want substring %q", sig, c.wantSig)
			}
		})
	}
}

func TestLibExtractionFromFrames(t *testing.T) {
	cases := []struct {
		name, in string
		want     []LibVer
	}{
		{"python-site-packages", `Traceback (most recent call last):
  File "/usr/lib/python3.11/site-packages/fastapi/routing.py", line 10, in app
  File "/usr/lib/python3.11/site-packages/pydantic/main.py", line 20, in validate
pydantic.ValidationError: 1 validation error`, []LibVer{{"pydantic", ""}, {"fastapi", ""}}},
		{"node-modules-scope", `TypeError: boom
    at Object.<anonymous> (/app/node_modules/@nestjs/core/index.js:1:1)
    at require (/app/node_modules/express/lib/router.js:5:5)`, []LibVer{{"@nestjs/core", ""}, {"express", ""}}},
		{"go-mod", `panic: boom

goroutine 1 [running]:
github.com/jackc/pgx/v5.(*Conn).Query(...)
	/root/go/pkg/mod/github.com/jackc/pgx/v5@v5.7.1/conn.go:123 +0x18`, []LibVer{{"github.com/jackc/pgx/v5", "5.7.1"}}},
		{"cargo", `thread 'main' panicked at 'boom', /root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/tokio-1.35.0/src/runtime/mod.rs:5:5`, []LibVer{{"tokio", "1.35.0"}}},
		{"maven", `Exception in thread "main" java.lang.IllegalStateException: boom
	at com.google.common.base.Preconditions.checkState(/home/u/.m2/repository/com/google/guava/guava/32.1.0/guava-32.1.0.jar:1)`, []LibVer{{"guava", "32.1.0"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, libs, _ := FromTrace([]byte(c.in))
			if !sameLibs(libs, c.want) {
				t.Errorf("libs = %v, want %v", libs, c.want)
			}
		})
	}
}

func sameLibs(got, want []LibVer) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i].Lib != want[i].Lib || got[i].Ver != want[i].Ver {
			return false
		}
	}
	return true
}

// --- HTTP tests -----------------------------------------------------------------------------------

const pyYamlTrace = `Traceback (most recent call last):
  File "/app/main.py", line 3, in <module>
    import yaml
ModuleNotFoundError: No module named 'yaml'`

func TestPostEReplyAndCaps(t *testing.T) {
	e := newTraceEnv(t)
	id := e.seedFix(t, uniq("ModuleNotFoundError No module named yaml"), "ModuleNotFoundError: No module named 'yaml'", "pip install pyyaml")

	st, body, h := e.postE(t, "/e", pyYamlTrace)
	if st != 200 {
		t.Fatalf("POST /e: %d %s", st, body)
	}
	head := first(body)
	if !strings.HasPrefix(head, "e: ModuleNotFoundError") || !strings.Contains(head, "raw=") {
		t.Errorf("head = %q", head)
	}
	if !strings.Contains(body, id) {
		t.Errorf("hit %s missing from reply:\n%s", id, body)
	}
	if !strings.Contains(body, "libs: yaml") {
		t.Errorf("libs line missing:\n%s", body)
	}
	if lh := h.Get("Link"); !strings.Contains(lh, `rel="canonical"`) || !strings.Contains(lh, "/e/") {
		t.Errorf("canonical Link = %q", lh)
	}

	// Caps: pre-seed the hourly IP-group counter to the limit, the next POST is refused.
	grp := core.IPGroup(e.ip)
	kind := "e" + strconv.Itoa(time.Now().UTC().Hour())
	if _, err := testPool.Exec(context.Background(),
		`INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		 ON CONFLICT (scope, kind, day) DO UPDATE SET n = $3`, "ip:"+grp, kind, traceEPerHour); err != nil {
		t.Fatal(err)
	}
	st, body, _ = e.postE(t, "/e", pyYamlTrace)
	if st != 429 {
		t.Fatalf("over-cap POST /e: %d %s (want 429)", st, body)
	}
}

func TestGhaFormatOnlyNotice(t *testing.T) {
	e := newTraceEnv(t)
	id := e.seedFix(t, uniq("disk full 100% DiskFullError"), "DiskFullError: volume 100% used", "prune old logs")

	st, body, _ := e.do(t, "POST", "/e?f=gha", "", "DiskFullError: volume 100% used on /data", "Content-Type", "text/plain")
	if st != 200 {
		t.Fatalf("POST /e?f=gha: %d %s", st, body)
	}
	if strings.TrimSpace(body) == "" {
		t.Fatalf("empty gha body (no hit for seeded %s)", id)
	}
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if !strings.HasPrefix(line, "::notice title=agents.ekaii.fr::") {
			t.Fatalf("non-notice line: %q", line)
		}
		rest := strings.TrimPrefix(line, "::notice title=agents.ekaii.fr::")
		if strings.Contains(rest, "::") {
			t.Fatalf("second workflow command in line: %q", line)
		}
	}
	for _, cmd := range []string{"::error", "::warning", "::set-output", "::add-mask", "::group"} {
		if strings.Contains(body, cmd) {
			t.Fatalf("forbidden workflow command %q in:\n%s", cmd, body)
		}
	}
	if !strings.Contains(body, Permalink(id)) {
		t.Errorf("permalink %s missing:\n%s", Permalink(id), body)
	}
	if !strings.Contains(body, "%25") { // the title's `%` must be percent-encoded
		t.Errorf("literal %% not encoded:\n%s", body)
	}
}

func TestPostETier1EchoesSigOnly(t *testing.T) {
	e := newTraceEnv(t)
	const secret = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
	body := "AuthError: rejected bearer " + secret + " at the gateway"
	st, out, _ := e.postE(t, "/e", body)
	if st != 200 && st != 404 {
		t.Fatalf("POST /e: %d %s", st, out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("tier-1 secret leaked into reply:\n%s", out)
	}
	if !strings.Contains(out, "<jwt>") {
		t.Errorf("secret not masked to <jwt>:\n%s", out)
	}
}

func TestPostVQBodyTwin(t *testing.T) {
	e := newTraceEnv(t)
	id := e.seedFix(t, uniq("flaky websocket reconnect loop"), "WebSocket keeps reconnecting in a loop", "add backoff")

	// JSON body twin of GET /q/.
	st, body, _ := e.do(t, "POST", "/v1/q", "", map[string]any{"q": "websocket reconnect loop", "k": 5})
	if st != 200 {
		t.Fatalf("POST /v1/q (json): %d %s", st, body)
	}
	if !strings.Contains(body, id) {
		t.Errorf("hit %s missing from /v1/q reply:\n%s", id, body)
	}
	// Same hit through GET /v1/kb (the GET search this route is the body twin of).
	st, gbody, _ := e.do(t, "GET", "/v1/kb?q=websocket+reconnect+loop&k=5", "", nil)
	if st != 200 || !strings.Contains(gbody, id) {
		t.Errorf("GET /v1/kb twin mismatch: %d\n%s", st, gbody)
	}
}

func TestCiPage(t *testing.T) {
	e := newTraceEnv(t)
	st, body, _ := e.do(t, "GET", "/ci", "", nil)
	if st != 200 {
		t.Fatalf("GET /ci: %d %s", st, body)
	}
	for _, want := range []string{"build.log", "/e?f=gha", "--data-binary"} {
		if !strings.Contains(body, want) {
			t.Errorf("/ci missing %q:\n%s", want, body)
		}
	}
}
