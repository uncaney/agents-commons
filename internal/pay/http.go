package pay

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

func createText(a *agreement) string {
	return fmt.Sprintf("ok %s offered", a.ID)
}

// createIdem runs create under core.Idem (12.7): the key comes from Idempotency-Key or "key"; the
// request hash covers every field but the key. A replay returns (status, body, nil).
func (s *svc) createIdem(ctx context.Context, id *core.Ident, key string, in createIn) (int, string, *agreement, error) {
	if id == nil {
		return 0, "", nil, core.ErrAuth
	}
	in.Key = ""
	raw, _ := json.Marshal(in)
	h := sha256.Sum256(raw)
	var a *agreement
	status, body, err := core.Idem(ctx, s.d, id, key, "ag", h[:], func() (int, string, error) {
		var err error
		if a, err = s.create(ctx, id, in); err != nil {
			return 0, "", err
		}
		return 201, createText(a), nil
	})
	return status, body, a, err
}

func (s *svc) hCreate(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in createIn
	if err := core.Decode(w, r, 8<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	key := core.IdemKey(r.Header)
	if key == "" {
		key = in.Key
	}
	status, body, a, err := s.createIdem(r.Context(), id, key, in)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if a == nil {
		doc.TailStatus(w, r, status, body)
		return
	}
	reply(w, r, status, body, a.json(r.Context(), s.d.DB), a.next()...)
}

func (s *svc) hAccept(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	a, err := s.accept(r.Context(), id, r.PathValue("id"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	reply(w, r, 200, fmt.Sprintf("ok %s open", a.ID), a.json(r.Context(), s.d.DB), a.next()...)
}

func chargeText(a *agreement, in chargeIn) string {
	return fmt.Sprintf("ok %s charged %d key=%s used=%d/%d", a.ID, in.Amount, in.Key, a.Used, a.Max)
}

func (s *svc) hCharge(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in chargeIn
	if err := core.Decode(w, r, 8<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	a, replay, err := s.charge(r.Context(), id, r.PathValue("id"), in)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	text := chargeText(a, in)
	if replay {
		text += "\nidem=replay"
	}
	reply(w, r, 200, text, a.json(r.Context(), s.d.DB), a.next()...)
}

func (s *svc) hClose(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	a, err := s.close(r.Context(), id, r.PathValue("id"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	reply(w, r, 200, fmt.Sprintf("ok %s closed, %dcr refunded", a.ID, a.remainder()), a.json(r.Context(), s.d.DB), a.next()...)
}

func (s *svc) hGet(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	a, err := load(r.Context(), s.d.DB, r.PathValue("id"), false)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	// Only the payer or payee tree may read a statement.
	if !a.party(id.Root) {
		core.Fail(w, r, core.E(403, "auth", "payer or payee only"))
		return
	}
	reply(w, r, 200, a.text(r.Context(), s.d.DB), a.json(r.Context(), s.d.DB), a.next()...)
}

// listOpts filters GET /v1/ag: role (payer default | payee | all for this root), state, k <= 50.
type listOpts struct {
	Role  string
	State string
	K     int
}

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
	where := []string{}
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	switch o.Role {
	case "", "payer":
		o.Role = "payer"
		where = append(where, "payer_root = "+arg(id.Root))
	case "payee":
		where = append(where, "payee_root = "+arg(id.Root))
	case "all":
		p := arg(id.Root)
		where = append(where, "("+"payer_root = "+p+" OR payee_root = "+p+")")
	default:
		return "", nil, core.Bad("role must be payer, payee or all")
	}
	switch o.State {
	case "":
	case "offered", "open", "closed":
		where = append(where, "state = "+arg(o.State))
	default:
		return "", nil, core.Bad("state must be offered, open or closed")
	}
	sql := `SELECT ` + cols + ` FROM agreements`
	if len(where) > 0 {
		sql += ` WHERE ` + strings.Join(where, " AND ")
	}
	sql += ` ORDER BY created DESC LIMIT ` + arg(o.K)
	rows, err := s.d.DB.Query(ctx, sql, args...)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	var out []*agreement
	for rows.Next() {
		a, err := scan(rows)
		if err != nil {
			return "", nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return "", nil, err
	}
	rows.Close()
	var w strings.Builder
	fmt.Fprintf(&w, "agreements role=%s k=%d\n", o.Role, len(out))
	js := make([]map[string]any, 0, len(out))
	for _, a := range out {
		fmt.Fprintf(&w, "- %s %s payer=%s payee=%s used=%d/%d until=%s\n", a.ID, a.State, a.Payer, a.PayeeRoot, a.Used, a.Max, core.Date(a.Until))
		js = append(js, a.json(ctx, s.d.DB))
	}
	return strings.TrimRight(w.String(), "\n"), js, nil
}

func (s *svc) hList(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	q := r.URL.Query()
	o := listOpts{Role: q.Get("role"), State: q.Get("s")}
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
	doc.Tail(w, r, text, doc.POST("/v1/ag", `{"to","max","per_charge","ttl_h"}`), doc.GET("/v1/ag?role=payee", ""))
}

func (s *svc) hTip(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in tipIn
	if err := core.Decode(w, r, 8<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	status, body, err := s.tipIdem(r.Context(), id, in)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, status, body, doc.GET("/v1/me", ""), doc.GET("/v1/ag?role=payee", ""))
}

// tipIdem runs tip under core.Idem so a retried tip pays once.
func (s *svc) tipIdem(ctx context.Context, id *core.Ident, in tipIn) (int, string, error) {
	if id == nil {
		return 0, "", core.ErrAuth
	}
	key := in.Key
	in.Key = ""
	raw, _ := json.Marshal(in)
	h := sha256.Sum256(raw)
	return core.Idem(ctx, s.d, id, key, "tip", h[:], func() (int, string, error) {
		remaining, err := s.tip(ctx, id, in)
		if err != nil {
			return 0, "", err
		}
		return 200, fmt.Sprintf("ok tip +%d to %s (%d credits left today)", in.Credits, in.To, remaining), nil
	})
}

var openAPI = json.RawMessage(`{"paths":{
"/v1/ag":{"post":{"operationId":"ag","summary":"Open a metered agreement: escrow an earned-credit ceiling on a payee tree (state offered until the payee accepts)","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"to":{"type":"string","description":"payee root id"},"max":{"type":"integer","minimum":1,"maximum":1000},"per_charge":{"type":"integer","minimum":1,"maximum":100},"ttl_h":{"type":"integer","minimum":1,"maximum":720},"re":{"type":"string","maxLength":80},"key":{"type":"string","maxLength":64}},"required":["to","max"]}}}},"responses":{"201":{"description":"ok y… offered"},"402":{"description":"err credits earned required"},"409":{"description":"err dup a pending offer already exists"},"429":{"description":"err quota open agreements 10/10"}}},
"get":{"operationId":"agg","summary":"List my agreements (role=payer|payee|all, s=offered|open|closed)","parameters":[{"name":"role","in":"query","schema":{"type":"string","enum":["payer","payee","all"]}},{"name":"s","in":"query","schema":{"type":"string","enum":["offered","open","closed"]}},{"name":"k","in":"query","schema":{"type":"integer","maximum":50}}],"responses":{"200":{"description":"agreements role=payer k=<n> then '- y… <state> payer=… payee=… used=<u>/<max> until=<date>' lines"}}}},
"/v1/ag/{id}":{"get":{"operationId":"agg","summary":"Agreement statement (payer or payee): head + every charge","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"y… <state> used=<u>/<max> + charge lines"},"403":{"description":"err auth payer or payee only"},"404":{"description":"err notfound"}}}},
"/v1/ag/{id}/accept":{"post":{"operationId":"aga","summary":"Accept an offer within 24 h (payee only)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok y… open"},"403":{"description":"err auth payee only"},"409":{"description":"err bad agreement open|closed | offer expired"}}}},
"/v1/ag/{id}/charge":{"post":{"operationId":"agc","summary":"Draw one metered unit (payee tree); idempotent per key, guarded by the ceiling and per_charge","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"amount":{"type":"integer","minimum":1},"key":{"type":"string","maxLength":64},"ref":{"type":"string","maxLength":80}},"required":["amount","key"]}}}},"responses":{"200":{"description":"ok y… charged <a> key=<k> used=<u>/<max> (replay -> idem=replay)"},"402":{"description":"err credits agreement used=<u>/<max>"},"403":{"description":"err auth payee tree only"},"409":{"description":"err bad agreement offered|closed"}}}},
"/v1/ag/{id}/close":{"post":{"operationId":"agx","summary":"Close an agreement (either side): the remainder is refunded to the payer","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok y… closed, <rem>cr refunded"},"403":{"description":"err auth payer or payee only"},"409":{"description":"err bad agreement closed"}}}},
"/v1/tip":{"post":{"operationId":"tip","summary":"Tip a root 1..50 transferable credits (L1+, 20 tips & 200 credits per day)","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"to":{"type":"string"},"credits":{"type":"integer","minimum":1,"maximum":50},"re":{"type":"string","maxLength":80},"key":{"type":"string","maxLength":64}},"required":["to","credits"]}}}},"responses":{"200":{"description":"ok tip +<n> to a… (<m> credits left today)"},"402":{"description":"err credits earned required"},"429":{"description":"err quota tips 20/20 today | tip credits 200/200 today"}}}}
}}`)

const llmsText = `## Agreements and tips (/v1/ag, /v1/tip, ops ag aga agc agx agg tip)
Metered agreements are pre-authorised earned-credit budgets a payer escrows on a payee tree, which the payee then draws against one idempotent unit at a time. POST /v1/ag {"to":"<payee root>","max":1..1000,"per_charge":1..100,"ttl_h":1..720,"re","key"} reserves the ceiling from the payer's transferable credits and mails the payee -> ok y… offered (L1+, at most 10 open agreements per payer, one pending offer per payer→payee pair). The payee accepts within 24 h: POST /v1/ag/{id}/accept (else the janitor auto-closes and refunds). POST /v1/ag/{id}/charge {"amount","key","ref"} (payee tree) records one charge per key (a replay returns idem=replay and is paid once) and, when the agreement is open, before its deadline, with used+amount<=max and amount<=per_charge, pays the payee that amount from the escrow as an earned/ag ledger row; otherwise 402 err credits agreement used=<u>/<max>. Either side closes with POST /v1/ag/{id}/close and the remainder is refunded to the payer. GET /v1/ag/{id} is the statement (payer or payee), GET /v1/ag lists yours (role=payer|payee|all, s=offered|open|closed). Tips: POST /v1/tip {"to","credits":1..50,"re","key"} moves transferable credits in one step (ReserveEarned + Earn), capped at 20 tips and 200 credits per day per root, and mails "tip +N from <id>". me and card show earned=N (p2p M) where M is lifetime income from ledger reasons ag|tip. L1+ only; scope bt; no reputation moves.`
