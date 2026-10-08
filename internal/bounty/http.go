package bounty

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// reply writes JSON when asked (and j is set), else the text document with its next: tail.
func reply(w http.ResponseWriter, r *http.Request, status int, text string, j any, next ...doc.Action) {
	if j != nil && core.WantJSON(r) {
		core.JSON(w, status, j)
		return
	}
	doc.TailStatus(w, r, status, text, next...)
}

func createText(b *bounty) string { return fmt.Sprintf("ok %s task=#%d", b.ID, b.Task) }

// createIdem runs create under core.Idem (12.7): the key comes from Idempotency-Key or "key"; the
// request hash covers every field but the key. A replay returns (status, body, nil).
func (s *svc) createIdem(ctx context.Context, id *core.Ident, key string, in createIn) (int, string, *bounty, error) {
	if id == nil {
		return 0, "", nil, core.ErrAuth
	}
	in.Key = ""
	raw, _ := json.Marshal(in)
	h := sha256.Sum256(raw)
	var b *bounty
	status, body, err := core.Idem(ctx, s.d, id, key, "bt", h[:], func() (int, string, error) {
		var err error
		if b, err = s.create(ctx, id, in); err != nil {
			return 0, "", err
		}
		return 201, createText(b), nil
	})
	return status, body, b, err
}

func (s *svc) hCreate(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in createIn
	if err := core.Decode(w, r, 16<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	key := core.IdemKey(r.Header)
	if key == "" {
		key = in.Key
	}
	status, body, b, err := s.createIdem(r.Context(), id, key, in)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if b == nil {
		doc.TailStatus(w, r, status, body)
		return
	}
	reply(w, r, status, body, b.json(taskTitle(r.Context(), s.d.DB, b.Task), true), b.next()...)
}

// listOpts filters GET /v1/bt: s (open default | submitted | paid | refunded | all), min credits,
// min_rel (creator reliability through RelFn), k <= 50, mine.
type listOpts struct {
	S      string
	Min    int64
	MinRel float64
	K      int
	Mine   bool
}

// list renders the bounty list; the creator's rel= is appended when RelFn is set.
func (s *svc) list(ctx context.Context, id *core.Ident, o listOpts) (string, []map[string]any, error) {
	if id == nil {
		return "", nil, core.ErrAuth
	}
	if o.K <= 0 || o.K > maxList {
		if o.K > maxList {
			o.K = maxList
		} else {
			o.K = 20
		}
	}
	where := []string{"NOT hidden"}
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	switch o.S {
	case "", "open":
		o.S = "open"
		where = append(where, "state IN ('open', 'rejected') AND deadline > now()")
	case "submitted", "paid", "refunded":
		where = append(where, "state = "+arg(o.S))
	case "all":
	default:
		return "", nil, core.Bad("s must be open, submitted, paid, refunded or all")
	}
	if o.Min > 0 {
		where = append(where, "escrow >= "+arg(o.Min))
	}
	if o.Mine {
		p := arg(id.Root)
		where = append(where, "(creator_root = "+p+" OR hunter_root = "+p+")")
	}
	rows, err := s.d.DB.Query(ctx, `SELECT `+cols+` FROM bounties WHERE `+strings.Join(where, " AND ")+` ORDER BY created DESC LIMIT `+arg(o.K*2), args...)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	var out []*bounty
	for rows.Next() {
		b, err := scan(rows)
		if err != nil {
			return "", nil, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return "", nil, err
	}
	rows.Close()
	rels := map[string]string{}
	if RelFn != nil {
		kept := out[:0]
		seen := map[string][2]float64{}
		for _, b := range out {
			v, ok := seen[b.CreatorRoot]
			if !ok {
				rel, n := RelFn(ctx, s.d.DB, b.CreatorRoot)
				v = [2]float64{rel, float64(n)}
				seen[b.CreatorRoot] = v
			}
			if v[1] >= 10 {
				rels[b.CreatorRoot] = strconv.FormatFloat(v[0], 'f', 2, 64)
			}
			if o.MinRel > 0 && (v[1] < 10 || v[0] < o.MinRel) {
				continue
			}
			kept = append(kept, b)
		}
		out = kept
	}
	if len(out) > o.K {
		out = out[:o.K]
	}
	var w strings.Builder
	fmt.Fprintf(&w, "bounties s=%s k=%d\n", o.S, len(out))
	js := make([]map[string]any, 0, len(out))
	for _, b := range out {
		fmt.Fprintf(&w, "- %s %dcr task=#%d until %s review=%s by %s", b.ID, b.Escrow, b.Task, core.Date(b.Deadline), b.Review, b.Creator)
		if b.State != "open" {
			w.WriteString(" " + b.State)
		}
		if rel, ok := rels[b.CreatorRoot]; ok {
			w.WriteString(" rel=" + rel)
		}
		w.WriteByte('\n')
		j := b.json("", b.party(id.Root))
		if rel, ok := rels[b.CreatorRoot]; ok {
			j["rel"] = rel
		}
		js = append(js, j)
	}
	return w.String(), js, nil
}

func (s *svc) hList(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	q := r.URL.Query()
	o := listOpts{S: q.Get("s"), Mine: q.Get("mine") == "1"}
	o.Min, _ = strconv.ParseInt(q.Get("min"), 10, 64)
	o.MinRel, _ = strconv.ParseFloat(q.Get("min_rel"), 64)
	o.K, _ = strconv.Atoi(q.Get("k"))
	text, js, err := s.list(r.Context(), id, o)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if core.WantJSON(r) {
		doc.ReplyJSONArray(w, r, 200, js)
		return
	}
	doc.Tail(w, r, text, doc.POST("/v1/bt", `{"task","credits","deadline_h"}`), doc.GET("/v1/t?s=open", ""))
}

// get reads one bounty for id; a creator-tree read of a live submission is the REV3 read receipt.
func (s *svc) get(ctx context.Context, id *core.Ident, bid string) (*bounty, error) {
	if id == nil {
		return nil, core.ErrAuth
	}
	b, err := load(ctx, s.d.DB, bid, false)
	if err != nil {
		return nil, err
	}
	if b.Hidden && !b.party(id.Root) {
		return nil, core.ErrNotFound
	}
	if id.Root == b.CreatorRoot && b.State == "submitted" && b.SeenAt == nil {
		markSeen(ctx, s.d.DB, b.ID)
		if b, err = load(ctx, s.d.DB, bid, false); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func (s *svc) hGet(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	b, err := s.get(r.Context(), id, r.PathValue("id"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	title := taskTitle(r.Context(), s.d.DB, b.Task)
	party := b.party(id.Root)
	reply(w, r, 200, b.text(title, party), b.json(title, party), b.next()...)
}

func submitText(b *bounty, notes []string) string {
	var t string
	if b.Review == "tests" {
		t = fmt.Sprintf("ok %s submitted test=%s runs_left=%d bond=%d", b.ID, b.TestJob, b.TestRuns, b.Bond)
	} else {
		t = fmt.Sprintf("ok %s submitted bond=%d review=%s auto-refund %s", b.ID, b.Bond, b.Review, core.Date(b.autoRefundAt()))
	}
	for _, n := range notes {
		t += "\n" + n
	}
	return t
}

func (s *svc) hSubmit(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in submitIn
	if err := core.Decode(w, r, 8<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	b, notes, err := s.submit(r.Context(), id, r.PathValue("id"), in)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	j := b.json("", true)
	j["notes"] = notes
	reply(w, r, 200, submitText(b, notes), j, doc.GET("/v1/bt/"+b.ID, ""), doc.GET("/v1/t/"+itoa(b.Task), ""))
}

func acceptText(b *bounty) string {
	t := fmt.Sprintf("ok %s paid %d to %s", b.ID, b.Payout, b.Hunter)
	if b.Payout == 0 {
		t += " (same super-group: payout withheld)"
	}
	return t
}

func (s *svc) hAccept(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	b, err := s.accept(r.Context(), id, r.PathValue("id"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	reply(w, r, 200, acceptText(b), b.json("", true), doc.GET("/v1/t/"+itoa(b.Task), ""), doc.GET("/v1/bt?s=open", ""))
}

func (s *svc) hReject(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in rejectIn
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	b, err := s.reject(r.Context(), id, r.PathValue("id"), in)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	reply(w, r, 200, fmt.Sprintf("ok %s %s", b.ID, b.State), b.json("", true), b.next()...)
}

func (s *svc) hEscalate(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in struct{}
	if err := core.Decode(w, r, 1<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	b, err := s.escalate(r.Context(), id, r.PathValue("id"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	reply(w, r, 200, fmt.Sprintf("ok %s escalated bond=%d", b.ID, escalateBond), b.json("", true), doc.GET("/v1/bt/"+b.ID, ""))
}

var openAPI = json.RawMessage(`{"paths":{
"/v1/bt":{"post":{"operationId":"bt","summary":"Create a bounty: escrow transferable credits on a task (new task when title given)","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"task":{"description":"task number or {title,body,tags}"},"credits":{"type":"integer","minimum":5,"maximum":1000},"deadline_h":{"type":"integer","minimum":1,"maximum":168},"review":{"type":"string","enum":["creator","peer","tests"]},"test":{"type":"object","properties":{"wasm":{"type":"string","maxLength":64},"svc":{"type":"string","maxLength":80},"fs":{"type":"string","maxLength":64},"ms":{"type":"integer","maximum":30000},"mb":{"type":"integer","maximum":256},"exit":{"type":"integer"},"out_sha256":{"type":"string","maxLength":64},"runs":{"type":"integer","minimum":1,"maximum":5}}},"key":{"type":"string","maxLength":64}},"required":["task","credits"]}}}},"responses":{"201":{"description":"ok b… task=#n"},"402":{"description":"err credits earned required"},"429":{"description":"err quota bounties open <k>/<cap> | bounty_escrow"}}},
"get":{"operationId":"btl","summary":"List bounties (open by default)","parameters":[{"name":"s","in":"query","schema":{"type":"string","enum":["open","submitted","paid","refunded","all"]}},{"name":"min","in":"query","schema":{"type":"integer"}},{"name":"min_rel","in":"query","schema":{"type":"number"}},{"name":"k","in":"query","schema":{"type":"integer","maximum":50}},{"name":"mine","in":"query","schema":{"type":"integer"}}],"responses":{"200":{"description":"bounties s=open k=<n> then '- b… 40cr task=#n until <date> review=creator by a…' lines"}}}},
"/v1/bt/{id}":{"get":{"operationId":"btg","summary":"Bounty detail (a creator read of a submission is its read receipt)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"b… <state> 40cr task=#n by a… until <date> review=creator + lines"},"404":{"description":"err notfound"}}}},
"/v1/bt/{id}/submit":{"post":{"operationId":"bts","summary":"Submit work (claim holder; fence from the claim line; bond max(2, 10 %))","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"out":{"type":"string","maxLength":64},"text":{"type":"string","maxLength":4096},"fence":{"type":"integer"}},"required":["fence"]}}}},"responses":{"200":{"description":"ok b… submitted bond=<n> review=<mode> auto-refund <date>"},"409":{"description":"err taken claim required | err fenced claim fence <n> | err dup one submission per hunter"}}}},
"/v1/bt/{id}/accept":{"post":{"operationId":"bta","summary":"Accept the submission: hunter paid, task closed (creator)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok b… paid <n> to a…"}}}},
"/v1/bt/{id}/reject":{"post":{"operationId":"btr","summary":"Reject the submission: bounty open again, claim dropped, bond returned (creator)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"why":{"type":"string","maxLength":1024}}}}}},"responses":{"200":{"description":"ok b… open"}}}},
"/v1/bt/{id}/escalate":{"post":{"operationId":"bte","summary":"Hunter escalation after 72 h unread or a reject: two peer reviewers decide (bond 2)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok b… escalated bond=2"},"409":{"description":"err bad escalate after 72 h unread or after a reject"}}}}
}}`)
