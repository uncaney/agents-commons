package mem

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
)

func laterPost(t *testing.T, e *env, tok string, in map[string]any) (int, string) {
	t.Helper()
	st, b, _ := e.do(t, "POST", "/v1/later", tok, jsonBody(in), "Content-Type", "application/json")
	return st, b
}

func laterRow(t *testing.T, id string) (delivered bool, subject string) {
	t.Helper()
	if err := pool.QueryRow(context.Background(), `SELECT delivered, subject FROM mem_later WHERE id = $1`, id).Scan(&delivered, &subject); err != nil {
		t.Fatal(err)
	}
	return
}

func run(t *testing.T) {
	t.Helper()
	if err := LaterRun(context.Background(), pool, nil); err != nil {
		t.Fatal(err)
	}
}

func TestLaterTimeAndCondition(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t)
	st, b := laterPost(t, e, tok, map[string]any{"text": "hello future\nmore detail", "after": "+1"})
	want(t, st, b, 201, "ok m", "deliver=20")
	id := strings.Fields(b)[1]
	run(t)
	if d, _ := laterRow(t, id); d {
		t.Fatal("delivered before deliver_at")
	}
	time.Sleep(1100 * time.Millisecond)
	run(t)
	if d, s := laterRow(t, id); !d || s != "hello future" {
		t.Fatalf("time delivery: %v %q", d, s)
	}
	if n := count(t, `SELECT count(*) FROM mem_later_delivered WHERE id = $1 AND read_at IS NULL`, id); n != 1 {
		t.Fatal("view does not show the delivered row")
	}
	st, b, _ = e.do(t, "GET", "/v1/me/resume", tok, "")
	want(t, st, b, 200, "later: 1 unread", "  hello future")
	// the mailbox marks reads through the (updatable) view
	if _, err := pool.Exec(context.Background(), `UPDATE mem_later_delivered SET read_at = now() WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	st, b, _ = e.do(t, "GET", "/v1/me/resume", tok, "")
	wantNot(t, b, "later:")
	// kv condition: delivered on a version change, "cond gone" when the key disappears after it existed
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/w", tok, "1")
	want(t, st, b, 201)
	st, b = laterPost(t, e, tok, map[string]any{"text": "kv changed", "on": "kv:me/w:changed"})
	want(t, st, b, 201, "deliver=cond")
	kvID := strings.Fields(b)[1]
	run(t)
	if d, _ := laterRow(t, kvID); d {
		t.Fatal("kv condition fired without a change")
	}
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/w", tok, "2")
	want(t, st, b, 200)
	run(t)
	if d, s := laterRow(t, kvID); !d || s != "kv changed" {
		t.Fatalf("kv condition: %v %q", d, s)
	}
	st, b = laterPost(t, e, tok, map[string]any{"text": "kv gone?", "on": "kv:a:" + root + "/w:changed"})
	want(t, st, b, 201)
	goneID := strings.Fields(b)[1]
	st, b, _ = e.do(t, "DELETE", "/v1/kv/me/w", tok, "")
	want(t, st, b, 200)
	run(t)
	if d, s := laterRow(t, goneID); !d || s != "kv gone? (cond gone)" {
		t.Fatalf("gone condition: %v %q", d, s)
	}
	// a condition on a key that never existed waits for its creation
	st, b = laterPost(t, e, tok, map[string]any{"text": "new key", "on": "kv:me/fresh:changed"})
	want(t, st, b, 201)
	freshID := strings.Fields(b)[1]
	run(t)
	if d, _ := laterRow(t, freshID); d {
		t.Fatal("missing key counted as gone")
	}
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/fresh", tok, "x")
	want(t, st, b, 201)
	run(t)
	if d, _ := laterRow(t, freshID); !d {
		t.Fatal("creation did not deliver")
	}
	// job and task conditions (EXISTS joins on the core tables)
	jid := core.NewID('j')
	if _, err := pool.Exec(context.Background(), `INSERT INTO jobs (id, submitter, root, wasm, input, ms, mb) VALUES ($1, $2, $2, 'w', 'i', 100, 16)`, jid, root); err != nil {
		t.Fatal(err)
	}
	st, b = laterPost(t, e, tok, map[string]any{"text": "job finished", "on": "j:" + jid + ":done"})
	want(t, st, b, 201)
	jlid := strings.Fields(b)[1]
	run(t)
	if d, _ := laterRow(t, jlid); d {
		t.Fatal("job condition fired early")
	}
	if _, err := pool.Exec(context.Background(), `UPDATE jobs SET status = 'done' WHERE id = $1`, jid); err != nil {
		t.Fatal(err)
	}
	run(t)
	if d, _ := laterRow(t, jlid); !d {
		t.Fatal("job condition did not fire")
	}
	var n int64
	if err := pool.QueryRow(context.Background(), `INSERT INTO tasks (n, id, root) VALUES ((SELECT coalesce(max(n), 0) + 1 FROM tasks), $1, $1) RETURNING n`, root).Scan(&n); err != nil {
		t.Fatal(err)
	}
	st, b = laterPost(t, e, tok, map[string]any{"text": "task done", "on": fmt.Sprintf("t:%d:done", n)})
	want(t, st, b, 201)
	tlid := strings.Fields(b)[1]
	run(t)
	if d, _ := laterRow(t, tlid); d {
		t.Fatal("task condition fired early")
	}
	if _, err := pool.Exec(context.Background(), `UPDATE tasks SET state = 'done' WHERE n = $1`, n); err != nil {
		t.Fatal(err)
	}
	run(t)
	if d, _ := laterRow(t, tlid); !d {
		t.Fatal("task condition did not fire")
	}
	st, b = laterPost(t, e, tok, map[string]any{"text": "gone task", "on": "t:999999999:done"})
	want(t, st, b, 201)
	gtid := strings.Fields(b)[1]
	run(t)
	if d, s := laterRow(t, gtid); !d || !strings.HasSuffix(s, "(cond gone)") {
		t.Fatalf("gone task: %v %q", d, s)
	}
	// validation
	st, b = laterPost(t, e, tok, map[string]any{"text": "x", "on": "t:1:paid"})
	want(t, st, b, 400, "err bad on must be")
	st, b = laterPost(t, e, tok, map[string]any{"text": "x", "on": "t:1:done", "after": "+5"})
	want(t, st, b, 400, "err bad exactly one")
	st, b = laterPost(t, e, tok, map[string]any{"text": "x"})
	want(t, st, b, 400, "err bad exactly one")
	st, b = laterPost(t, e, tok, map[string]any{"text": "x", "after": "+9999999"})
	want(t, st, b, 400, "err bad after must be within 30 days")
	st, b = laterPost(t, e, tok, map[string]any{"text": "x", "after": "tomorrow"})
	want(t, st, b, 400, "err bad after")
	st, b = laterPost(t, e, tok, map[string]any{"text": "x", "after": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	want(t, st, b, 201)
	st, b = laterPost(t, e, tok, map[string]any{"text": "", "after": "+1"})
	want(t, st, b, 400, "err bad text required")
	st, b = laterPost(t, e, tok, map[string]any{"text": strings.Repeat("x", MaxLaterText+1), "after": "+1"})
	want(t, st, b, 413, "err size")
	st, b = laterPost(t, e, tok, map[string]any{"text": "x", "on": "kv:a:" + core.NewID('a') + "/k:changed"})
	want(t, st, b, 403, "err auth forbidden")
	_, other := mkRoot(t)
	st, b = laterPost(t, e, other, map[string]any{"text": "x", "on": "kv:a:" + root + "/w:changed"})
	want(t, st, b, 403)
	// 20 pending per root
	_, ctok := mkRoot(t)
	for i := 0; i < MaxLaterPending; i++ {
		st, b := laterPost(t, e, ctok, map[string]any{"text": fmt.Sprintf("n%d", i), "after": "+86400"})
		want(t, st, b, 201)
	}
	st, b = laterPost(t, e, ctok, map[string]any{"text": "one too many", "after": "+86400"})
	want(t, st, b, 429, "err quota")
	// purge of old rows
	if _, err := pool.Exec(context.Background(), `UPDATE mem_later SET delivered_at = now() - interval '31 days' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	run(t)
	if n := count(t, `SELECT count(*) FROM mem_later WHERE id = $1`, id); n != 0 {
		t.Fatal("delivered row not purged after 30 d")
	}
	// scoped token needs mb:w
	_, ro := mkSub(t, root, []string{"kv:r"})
	st, b = laterPost(t, e, ro, map[string]any{"text": "x", "after": "+1"})
	want(t, st, b, 403, "err scope mb:w")
}
