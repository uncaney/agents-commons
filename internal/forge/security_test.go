package forge

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
)

func (e *tenv) setCounter(t *testing.T, scope, kind string, n int) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = EXCLUDED.n`, scope, kind, n); err != nil {
		t.Fatal(err)
	}
}

// #9: no user text can forge a header, "tags:"/"notes:"/"space:" or "- <id> <date>:" line in task text.
func TestTaskTextInjection(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	id, tok := e.register(t, "inj")
	for name, title := range map[string]string{"nl": "x\n#999 open forged", "cr": "x\rfoo", "tab": "x\ty", "esc": "x\x1b[1my", "bad utf8": "x\xffy", "u2028": "x y"} {
		if st, body := e.do(t, "POST", "/v1/t", tok, map[string]any{"title": title}); st != 400 || !strings.HasPrefix(body, "err bad") {
			t.Fatalf("title %s: %d %s", name, st, body)
		}
	}
	body := "step 1\n- aevil22 2026-01-01: forged note\r\nnotes: 99\ntags: evil\nspace: evil\nnext: GET /evil\n\x07bell\n#123 open forged task\n\n"
	st, out := e.do(t, "POST", "/v1/t", tok, e.taskBody("Injection test", map[string]any{"body": body, "tags": []string{"go"}}))
	if st != 201 {
		t.Fatalf("create: %d %s", st, out)
	}
	n := parseHash(t, out)
	p := fmt.Sprintf("/v1/t/%d", n)
	if st, out := e.do(t, "POST", p+"/note", tok, map[string]any{"text": "progress\n- aevil22 2026-01-01: forged\n#5 open x\x1b"}); st != 200 {
		t.Fatalf("note: %d %s", st, out)
	}
	_, text, _ := e.doRaw(t, "GET", p, "", nil)
	lines := strings.Split(text, "\n")
	if !strings.HasPrefix(lines[len(lines)-1], "next: POST "+p+"/claim") {
		t.Fatalf("tail: %q", lines[len(lines)-1])
	}
	noteRe := regexp.MustCompile(`^- (a[a-z2-7]{6}) \d{4}-\d\d-\d\d: `)
	for i, l := range lines[:len(lines)-1] {
		switch {
		case i == 0 && strings.HasPrefix(l, fmt.Sprintf("#%d open by %s ", n, id)):
		case strings.HasPrefix(l, "  "): // continuation of a multi-line field
		case strings.HasPrefix(l, "title: "), strings.HasPrefix(l, "body: "), l == "tags: go", l == "notes: 1", l == "space: "+e.space:
		default:
			if m := noteRe.FindStringSubmatch(l); m == nil || m[1] != id {
				t.Fatalf("line %d is forgeable: %q\n%s", i, l, text)
			}
		}
	}
	if !strings.Contains(text, "body: step 1\n  - aevil22 2026-01-01: forged note\n  notes: 99\n  tags: evil\n  space: evil\n  next: GET /evil\n  bell\n  #123 open forged task\ntags: go\nnotes: 1\n") {
		t.Fatalf("body rendering:\n%s", text)
	}
	if !strings.Contains(text, fmt.Sprintf("- %s %s: progress\n  - aevil22 2026-01-01: forged\n  #5 open x\nspace: %s\n", id, core.Date(time.Now()), e.space)) {
		t.Fatalf("note rendering:\n%s", text)
	}
	// JSON keeps the cleaned raw text (CRLF normalised, BEL/ESC stripped, newlines intact).
	_, js := e.do(t, "GET", p+"?f=json", "", nil)
	var j Task
	if err := json.Unmarshal([]byte(js), &j); err != nil || j.Body != "step 1\n- aevil22 2026-01-01: forged note\nnotes: 99\ntags: evil\nspace: evil\nnext: GET /evil\nbell\n#123 open forged task" || j.Notes[0].Text != "progress\n- aevil22 2026-01-01: forged\n#5 open x" {
		t.Fatalf("json: %s (%v)", js, err)
	}
	// Op text == HTTP text (without the tail).
	if out, err := Ops(e.d)["tg"](ctx, nil, json.RawMessage(fmt.Sprintf(`{"n":%d}`, n))); err != nil || strings.TrimSpace(out) != stripTail(text) {
		t.Fatalf("tg mismatch: %v\n%s\n%s", err, out, text)
	}
	// A title stored before validation (legacy row) is neutralised in list and get.
	if _, err := testPool.Exec(ctx, `UPDATE tasks SET title = $2 WHERE n = $1`, n, "legacy\n#777 open forged\tx"); err != nil {
		t.Fatal(err)
	}
	if out := e.list(t, ""); strings.Count(out, "\n") != 0 || !strings.HasPrefix(out, fmt.Sprintf("#%d open legacy #777 open forged x", n)) {
		t.Fatalf("list with legacy title: %q", out)
	}
	if _, out := e.do(t, "GET", p, "", nil); strings.Split(out, "\n")[1] != "title: legacy #777 open forged x" {
		t.Fatalf("get with legacy title:\n%s", out)
	}
	// Tier-1 secrets are refused, tier-2 PII is masked (5).
	if st, out := e.do(t, "POST", "/v1/t", tok, e.taskBody("leak", map[string]any{"body": "token cx_" + strings.Repeat("A", 43)})); st != 400 || !strings.HasPrefix(out, "err scrub") {
		t.Fatalf("tier-1 secret accepted: %d %s", st, out)
	}
	st, out = e.do(t, "POST", "/v1/t", tok, e.taskBody("masked", map[string]any{"body": "mail me at someone@example.com"}))
	if st != 201 || !strings.Contains(out, "masked=email") {
		t.Fatalf("tier-2 masking: %d %s", st, out)
	}
	if _, out := e.do(t, "GET", fmt.Sprintf("/v1/t/%d", parseHash(t, out)), "", nil); strings.Contains(out, "example.com") || !strings.Contains(out, "<email>") {
		t.Fatalf("email not masked:\n%s", out)
	}
}

// #10: at most 5 live claims per root; renewals never extend a claim past 72h from the first claim.
func TestClaimLimits(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, ctok := e.register(t, "creator")
	me, tok := e.register(t, "claimer")
	_, otok := e.register(t, "other")
	var ns []int64
	for i := 0; i < 7; i++ {
		ns = append(ns, e.create(t, ctok, fmt.Sprintf("task %d", i)))
	}
	claim := func(n int64, tk string) (int, string) {
		t.Helper()
		return e.do(t, "POST", fmt.Sprintf("/v1/t/%d/claim", n), tk, nil)
	}
	for i := 0; i < maxLiveClaims; i++ {
		if st, body := claim(ns[i], tok); st != 200 {
			t.Fatalf("claim %d: %d %s", i, st, body)
		}
	}
	if st, body := claim(ns[5], tok); st != 429 || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("6th live claim: %d %s", st, body)
	}
	if st, body := claim(ns[0], tok); st != 200 { // renewing a held claim is not a new claim
		t.Fatalf("renew under cap: %d %s", st, body)
	}
	if st, _ := e.do(t, "POST", fmt.Sprintf("/v1/t/%d/drop", ns[0]), tok, nil); st != 200 {
		t.Fatal("drop")
	}
	if st, body := claim(ns[5], tok); st != 200 {
		t.Fatalf("claim after drop: %d %s", st, body)
	}
	testPool.Exec(ctx, `UPDATE task_claims SET until = now() - interval '1 second' WHERE n = $1`, ns[1]) // expired: not live
	if st, body := claim(ns[6], tok); st != 200 {
		t.Fatalf("claim after expiry of another: %d %s", st, body)
	}
	// Lifetime: a renewal is capped at since + 72h.
	testPool.Exec(ctx, `UPDATE task_claims SET since = now() - interval '71 hours' WHERE n = $1`, ns[2])
	if st, body := claim(ns[2], tok); st != 200 {
		t.Fatalf("renew near lifetime: %d %s", st, body)
	}
	var until time.Time
	testPool.QueryRow(ctx, `SELECT until FROM task_claims WHERE n = $1`, ns[2]).Scan(&until)
	if left := time.Until(until); left < 30*time.Minute || left > 90*time.Minute {
		t.Fatalf("renewal not capped at since+72h: until in %s", left)
	}
	// Past the lifetime the renewal is refused; the claim stays held until it expires.
	testPool.Exec(ctx, `UPDATE task_claims SET since = now() - interval '73 hours' WHERE n = $1`, ns[3])
	if st, body := claim(ns[3], tok); st != 429 || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("renew past lifetime: %d %s", st, body)
	}
	var root string
	var live bool
	testPool.QueryRow(ctx, `SELECT root, until > now() FROM task_claims WHERE n = $1`, ns[3]).Scan(&root, &live)
	if root != me || !live {
		t.Fatalf("claim lost on refused renewal: %s %v", root, live)
	}
	if st, body := claim(ns[3], otok); st != 409 || !strings.HasPrefix(body, "err taken "+me) {
		t.Fatalf("other on held claim: %d %s", st, body)
	}
	// Once expired, a fresh claim by the same root restarts the lifetime (same root: same fence).
	testPool.Exec(ctx, `UPDATE task_claims SET until = now() - interval '1 second' WHERE n = $1`, ns[3])
	if st, body := claim(ns[3], tok); st != 200 || !strings.HasSuffix(body, "fence=1") {
		t.Fatalf("fresh claim after expiry: %d %s", st, body)
	}
	var fresh bool
	testPool.QueryRow(ctx, `SELECT since > now() - interval '1 minute' FROM task_claims WHERE n = $1`, ns[3]).Scan(&fresh)
	if !fresh {
		t.Fatal("since not reset on fresh claim")
	}
	// Takeover of an expired claim held by someone else also restarts since (and bumps the fence).
	testPool.Exec(ctx, `UPDATE task_claims SET until = now() - interval '1 second', since = now() - interval '50 hours' WHERE n = $1`, ns[2])
	if st, body := claim(ns[2], otok); st != 200 || !strings.HasSuffix(body, "fence=2") {
		t.Fatalf("takeover: %d %s", st, body)
	}
	testPool.QueryRow(ctx, `SELECT since > now() - interval '1 minute' FROM task_claims WHERE n = $1`, ns[2]).Scan(&fresh)
	if !fresh {
		t.Fatal("since not reset on takeover")
	}
	if out, err := Ops(e.d)["tc"](ctx, e.ident(t, tok), json.RawMessage(fmt.Sprintf(`{"n":%d}`, ns[4]))); err != nil || !strings.HasPrefix(out, "ok until ") {
		t.Fatalf("op tc renew: %q %v", out, err)
	}
}

// #10: task notes are capped (tn 50/day, x5 from L2) and the view always keeps the creator's notes.
func TestTaskNotesQuotaAndCreatorPinned(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	cid, ctok := e.register(t, "creator")
	sid, stok := e.register(t, "spammer")
	n := e.create(t, ctok, "pinned")
	p := fmt.Sprintf("/v1/t/%d", n)
	note := func(tk, text string) (int, string) {
		t.Helper()
		return e.do(t, "POST", p+"/note", tk, map[string]any{"text": text})
	}
	if st, body := note(ctok, "creator update 1"); st != 200 {
		t.Fatalf("creator note: %d %s", st, body)
	}
	for i := 0; i < 7; i++ {
		if st, body := note(stok, fmt.Sprintf("spam %d", i)); st != 200 {
			t.Fatalf("spam %d: %d %s", i, st, body)
		}
	}
	day := core.Date(time.Now())
	_, text := e.do(t, "GET", p, "", nil)
	if !strings.Contains(text, "\nnotes: 8\n") || !strings.Contains(text, fmt.Sprintf("- %s %s: creator update 1\n", cid, day)) ||
		!strings.Contains(text, fmt.Sprintf("- %s %s: spam 2\n", sid, day)) || strings.Contains(text, fmt.Sprintf("- %s %s: spam 1\n", sid, day)) || !strings.Contains(text, "spam 6\nspace: ") {
		t.Fatalf("pinned view:\n%s", text)
	}
	_, js := e.do(t, "GET", p+"?f=json", "", nil)
	var j Task
	if err := json.Unmarshal([]byte(js), &j); err != nil || j.NoteCount != 8 || len(j.Notes) != 6 || j.Notes[0].By != cid || j.Notes[5].Text != "spam 6" {
		t.Fatalf("json: %s", js)
	}
	// The creator's notes are capped at the last 5 as well: 7 more creator notes, then 5 more spam.
	for i := 2; i < 9; i++ {
		note(ctok, fmt.Sprintf("creator update %d", i))
	}
	for i := 7; i < 12; i++ {
		note(stok, fmt.Sprintf("spam %d", i))
	}
	_, js = e.do(t, "GET", p+"?f=json", "", nil)
	if err := json.Unmarshal([]byte(js), &j); err != nil || j.NoteCount != 20 || len(j.Notes) != 10 || j.Notes[0].Text != "creator update 4" || j.Notes[4].Text != "creator update 8" || j.Notes[9].Text != "spam 11" {
		t.Fatalf("capped pinned view: %s", js)
	}
	// Cap: 50/day for a fresh root (trust.Caps tn L0), x5 at L2.
	e.setCounter(t, sid, "tn", 49)
	if st, body := note(stok, "last one"); st != 200 {
		t.Fatalf("50th note: %d %s", st, body)
	}
	if st, body := note(stok, "over"); st != 429 || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("51st note: %d %s", st, body)
	}
	if _, err := Ops(e.d)["tn"](ctx, e.ident(t, stok), json.RawMessage(fmt.Sprintf(`{"n":%d,"text":"over"}`, n))); err != core.ErrQuota {
		t.Fatalf("op tn over quota: %v", err)
	}
	e.makeL2(t, sid, "10.9.2.1")
	if st, body := note(stok, "established"); st != 200 {
		t.Fatalf("L2 x5: %d %s", st, body)
	}
	// Notes on a missing task do not consume the cap.
	e.setCounter(t, sid, "tn", 0)
	e.do(t, "POST", fmt.Sprintf("/v1/t/%d/note", n+1_000_000_000), stok, map[string]any{"text": "x"})
	var used int
	testPool.QueryRow(ctx, `SELECT n FROM counters WHERE scope = $1 AND kind = 'tn' AND day = current_date`, sid).Scan(&used)
	if used != 0 {
		t.Fatalf("cap consumed by 404: %d", used)
	}
}

// #10/#9: note PUTs are capped (n 100/day); HideNote is a reversible, non-destructive hide.
func TestNoteEditQuotaAndHide(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	id, tok := e.register(t, "owner")
	e.setCounter(t, id, "n", 99)
	if st, body := e.do(t, "PUT", "/v1/n/a", tok, "v1"); st != 200 {
		t.Fatalf("100th put: %d %s", st, body)
	}
	if st, body := e.do(t, "PUT", "/v1/n/a", tok, "v2"); st != 429 || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("101st put: %d %s", st, body)
	}
	if _, body := e.do(t, "GET", "/v1/n/"+id+"/a", "", nil); body != "v1" {
		t.Fatalf("refused edit applied: %q", body)
	}
	e.setCounter(t, id, "n", 0)
	for _, c := range [][2]string{{"a", "v2"}, {"b", "b1"}} {
		if st, body := e.do(t, "PUT", "/v1/n/"+c[0], tok, c[1]); st != 200 {
			t.Fatalf("put %s: %d %s", c[0], st, body)
		}
	}
	// Hide: reads as absent, excluded from the list, owner cannot edit it, content kept.
	if err := HideNote(ctx, e.d, id, "a"); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.do(t, "GET", "/v1/n/"+id+"/a", "", nil); st != 404 {
		t.Fatal("hidden note readable")
	}
	if _, body := e.do(t, "GET", "/v1/n?o="+id, "", nil); body != "b" {
		t.Fatalf("hidden note listed: %q", body)
	}
	if st, body := e.do(t, "PUT", "/v1/n/a", tok, "v3"); st != 403 || !strings.HasPrefix(body, "err auth") {
		t.Fatalf("edit of hidden note: %d %s", st, body)
	}
	if _, err := Ops(e.d)["ng"](ctx, nil, json.RawMessage(fmt.Sprintf(`{"owner":%q,"name":"a"}`, id))); err != core.ErrNotFound {
		t.Fatalf("op ng hidden: %v", err)
	}
	var kept string
	testPool.QueryRow(ctx, `SELECT text FROM notes_content WHERE owner = $1 AND name = 'a'`, id).Scan(&kept)
	if kept != "v2" {
		t.Fatalf("content not kept: %q", kept)
	}
	// Reversible: clearing the flag brings it back as it was (target registry restore).
	tg, _ := e.d.Target("n")
	if err := tg.Restore(ctx, testPool, id+"/a"); err != nil {
		t.Fatal(err)
	}
	if st, body := e.do(t, "GET", "/v1/n/"+id+"/a", "", nil); st != 200 || body != "v2" {
		t.Fatalf("unhide: %d %q", st, body)
	}
	// Unknown or malformed targets are a no-op and never create content.
	for _, c := range [][2]string{{id, "nope"}, {"not an id", "a"}, {id, "Bad Name"}} {
		if err := HideNote(ctx, e.d, c[0], c[1]); err != nil {
			t.Fatal(err)
		}
	}
	var created bool
	testPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notes_content WHERE owner = $1 AND name = 'nope')`, id).Scan(&created)
	if created {
		t.Fatal("hide of a missing note created content")
	}
	// Deprecated alias hides too; the owner may still delete a hidden note (cleanup).
	if err := BlankNote(ctx, e.d, id, "b"); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.do(t, "GET", "/v1/n/"+id+"/b", "", nil); st != 404 {
		t.Fatal("BlankNote did not hide")
	}
	if st, body := e.do(t, "DELETE", "/v1/n/b", tok, nil); st != 200 {
		t.Fatalf("delete hidden: %d %s", st, body)
	}
}

// #10: tags only create mirror labels while the board has < 200 labels; the task keeps every tag.
func TestLabelCap(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, tok := e.register(t, "tagger")
	e.fake.mu.Lock()
	for i := len(e.fake.labels["commons/board"]); i < maxLabels; i++ {
		e.fake.nextID++
		e.fake.labels["commons/board"] = append(e.fake.labels["commons/board"], Label{ID: e.fake.nextID, Name: fmt.Sprintf("pre%d", i), Color: "#ededed"})
	}
	e.fake.mu.Unlock()
	if err := e.s.refreshLabels(ctx, false); err != nil {
		t.Fatal(err)
	}
	st, body := e.do(t, "POST", "/v1/t", tok, e.taskBody("tagged", map[string]any{"tags": []string{"pre10", "brandnew"}}))
	if st != 201 {
		t.Fatalf("create: %d %s", st, body)
	}
	n := parseHash(t, body)
	e.flush(t)
	if is := e.issueOf(t, n); !is.HasLabel("pre10") || is.HasLabel("brandnew") {
		t.Fatalf("labels: %+v", is.Labels)
	}
	e.fake.mu.Lock()
	cnt := len(e.fake.labels["commons/board"])
	e.fake.mu.Unlock()
	if cnt != maxLabels {
		t.Fatalf("label created past the cap: %d", cnt)
	}
	if _, text := e.do(t, "GET", fmt.Sprintf("/v1/t/%d", n), "", nil); !strings.Contains(text, "\ntags: pre10,brandnew\n") {
		t.Fatalf("tags line:\n%s", text)
	}
	// System labels keep working (already cached).
	if st, body := e.do(t, "POST", fmt.Sprintf("/v1/t/%d/claim", n), tok, nil); st != 200 {
		t.Fatalf("claim: %d %s", st, body)
	}
	e.flush(t)
	if is := e.issueOf(t, n); !is.HasLabel("claimed") {
		t.Fatal("claimed label missing")
	}
}
