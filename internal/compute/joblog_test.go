package compute

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
)

// insertDiagJob creates a failed job owned by root with n reported replicas carrying diag, so the
// joblog surface has rows to render without driving the full lease/consensus path.
func (e *env) insertDiagJob(root string, diags []map[string]any) string {
	e.t.Helper()
	ctx := context.Background()
	jid := core.NewID('j')
	if _, err := testPool.Exec(ctx, `INSERT INTO jobs (id, submitter, root, wasm, input, ms, mb, status, reason, finished_at)
		VALUES ($1, $2, $2, $3, $4, 10000, 64, 'failed', 'exit 1', now())`,
		jid, root, sha([]byte("w"+jid)), sha([]byte("i"+jid))); err != nil {
		e.t.Fatal(err)
	}
	for i, d := range diags {
		raw, _ := json.Marshal(d)
		if _, err := testPool.Exec(ctx, `INSERT INTO replicas (job, state, worker_root, status, code, out, ms, diag, reported_at)
			VALUES ($1, 'reported', $2, 'exit', 1, '', $3, $4, now())`,
			jid, "donor"+core.NewID('u'), 800+i, raw); err != nil {
			e.t.Fatal(err)
		}
	}
	return jid
}

func ident(root string) *core.Ident { return &core.Ident{ID: root, Root: root, Name: "n"} }

func TestJobLogSubmitterOnlyAndMasked(t *testing.T) {
	e := newEnv(t, false)
	sub, _ := e.register("jlog-sub")
	mallory, _ := e.register("jlog-other")

	const secret = "sk-ant-api03-DEADBEEFDEADBEEFDEADBEEF01234567"
	stderr := "panic: boom\nleaked " + secret + " here\nstack ..."
	jid := e.insertDiagJob(sub, []map[string]any{
		{"stderr": base64.RawURLEncoding.EncodeToString([]byte(stderr)), "trace": "wasm[0] at start", "compile_ms": 3900, "mem_pages": 656},
		{"compile_ms": 120},
	})

	// Submitter sees both replica blocks, stderr as '| ' lines, trace as '# ', secret masked.
	text, j, err := e.s.jobLog(context.Background(), ident(sub), jid)
	if err != nil {
		t.Fatalf("jobLog: %v", err)
	}
	if strings.Contains(text, secret) {
		t.Fatalf("secret not masked:\n%s", text)
	}
	for _, want := range []string{"replica 1 by donor", "status=exit code=1", "compile_ms=3900", "mem=41/64MiB", "\n| panic: boom", "\n# wasm[0] at start", "replica 2 by donor"} {
		if !strings.Contains(text, want) {
			t.Fatalf("log missing %q in:\n%s", want, text)
		}
	}
	// No user text ever starts a line at column 0 (line-injection safety).
	for _, ln := range strings.Split(text, "\n") {
		if ln == "" {
			continue
		}
		switch ln[0] {
		case 'r', '|', '#': // replica head, stderr, trace
		default:
			t.Fatalf("line starts unsafely: %q", ln)
		}
	}
	if reps, _ := j["replicas"].([]map[string]any); len(reps) != 2 {
		t.Fatalf("want 2 replica blocks, got %d", len(reps))
	}

	// A different root gets the same 404 as an unknown job; anonymous is ErrAuth.
	if _, _, err := e.s.jobLog(context.Background(), ident(mallory), jid); err != core.ErrNotFound {
		t.Fatalf("other root: want ErrNotFound, got %v", err)
	}
	if _, _, err := e.s.jobLog(context.Background(), ident(sub), core.NewID('j')); err != core.ErrNotFound {
		t.Fatalf("unknown job: want ErrNotFound, got %v", err)
	}
	if _, err := e.s.opJLog(context.Background(), nil, nil); err != core.ErrAuth {
		t.Fatalf("anon op: want ErrAuth, got %v", err)
	}

	// The op returns the same text as the HTTP path.
	optext, err := e.s.opJLog(context.Background(), ident(sub), json.RawMessage(`{"id":"`+jid+`"}`))
	if err != nil || optext != text {
		t.Fatalf("op mismatch: %v\n%s", err, optext)
	}
}

func TestInfoExtraCompileHint(t *testing.T) {
	e := newEnv(t, false)
	_, tok := e.register("hint")
	hash := e.put(tok, minWasm("hint-mod"))
	// A module whose median compile time eats over 25 % of the 10 s budget carries the warning and
	// the p50 lines on GET /v1/b/<hash>/info (27.6 compile diagnostics).
	if _, err := testPool.Exec(context.Background(),
		`INSERT INTO blob_meta (hash, kind, compile_ms, mem_pages) VALUES ($1, 'wasm', '{4000,4200,3800}', '{200,220}')
		 ON CONFLICT (hash) DO UPDATE SET compile_ms = EXCLUDED.compile_ms, mem_pages = EXCLUDED.mem_pages`, hash); err != nil {
		t.Fatal(err)
	}
	st, body, _ := e.do("GET", "/v1/b/"+hash+"/info", tok, nil)
	if st != 200 {
		t.Fatalf("info: %d %s", st, body)
	}
	for _, want := range []string{"compile_ms_p50=4000", "warn compile uses", "set ms>=20000"} {
		if !strings.Contains(body, want) {
			t.Fatalf("info missing %q in:\n%s", want, body)
		}
	}

	// A fast module carries no warning.
	hash2 := e.put(tok, minWasm("fast-mod"))
	if _, err := testPool.Exec(context.Background(),
		`INSERT INTO blob_meta (hash, kind, compile_ms) VALUES ($1, 'wasm', '{200,180}')
		 ON CONFLICT (hash) DO UPDATE SET compile_ms = EXCLUDED.compile_ms`, hash2); err != nil {
		t.Fatal(err)
	}
	if _, body, _ := e.do("GET", "/v1/b/"+hash2+"/info", tok, nil); strings.Contains(body, "warn compile") {
		t.Fatalf("fast module should not warn:\n%s", body)
	}
}
