package auction

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

func createText(a *auction) string {
	return fmt.Sprintf("ok %s closes %s", a.ID, core.Date(a.ClosesAt))
}

// createIdem runs create under core.Idem (12.7): the key comes from Idempotency-Key or "key"; the
// request hash covers every field but the key. A replay returns (status, body, nil).
func (s *svc) createIdem(ctx context.Context, id *core.Ident, key string, in createIn) (int, string, *auction, error) {
	if id == nil {
		return 0, "", nil, core.ErrAuth
	}
	in.Key = ""
	raw, _ := json.Marshal(in)
	h := sha256.Sum256(raw)
	var a *auction
	status, body, err := core.Idem(ctx, s.d, id, key, "au", h[:], func() (int, string, error) {
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
	if err := core.Decode(w, r, 16<<10, &in); err != nil {
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
	reply(w, r, status, body, a.json(r.Context(), s.d.DB, taskTitle(r.Context(), s.d.DB, a.Task), true), a.next()...)
}

// listOpts filters GET /v1/au: s (open default | closed | mine | all), k <= 50.
type listOpts struct {
	S    string
	K    int
	Mine bool
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
	switch o.S {
	case "", "open":
		o.S = "open"
		where = append(where, "state = 'open'")
	case "closed":
		where = append(where, "state IN ('awarded', 'nobid', 'cancelled')")
	case "all":
	default:
		return "", nil, core.Bad("s must be open, closed or all")
	}
	if o.Mine {
		where = append(where, "creator_root = "+arg(id.Root))
	}
	sql := `SELECT ` + cols + ` FROM auctions`
	if len(where) > 0 {
		sql += ` WHERE ` + strings.Join(where, " AND ")
	}
	sql += ` ORDER BY closes_at DESC LIMIT ` + arg(o.K)
	rows, err := s.d.DB.Query(ctx, sql, args...)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	var out []*auction
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
	fmt.Fprintf(&w, "auctions s=%s k=%d\n", o.S, len(out))
	js := make([]map[string]any, 0, len(out))
	for _, a := range out {
		fmt.Fprintf(&w, "- %s budget<=%dcr task=#%d closes %s min_bidders=%d bids=%d", a.ID, a.Budget, a.Task, core.Date(a.ClosesAt), a.MinBidders, bidCount(ctx, s.d.DB, a.ID))
		if a.State != "open" {
			w.WriteString(" " + a.State)
		}
		w.WriteByte('\n')
		js = append(js, a.json(ctx, s.d.DB, "", a.party(id.Root)))
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
	doc.Tail(w, r, text, doc.POST("/v1/au", `{"task","budget","closes_m","min_bidders"}`), doc.GET("/v1/au?s=open", ""))
}

// get reads one auction (bids listed only after close).
func (s *svc) get(ctx context.Context, id *core.Ident, auctionID string) (*auction, error) {
	if id == nil {
		return nil, core.ErrAuth
	}
	return load(ctx, s.d.DB, auctionID, false)
}

func (s *svc) hGet(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	a, err := s.get(r.Context(), id, r.PathValue("id"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	title := taskTitle(r.Context(), s.d.DB, a.Task)
	reply(w, r, 200, a.text(r.Context(), s.d.DB, title), a.json(r.Context(), s.d.DB, title, a.party(id.Root)), a.next()...)
}

func bidText(a *auction) string {
	return fmt.Sprintf("ok %s bid placed (sealed until %s)", a.ID, core.Date(a.ClosesAt))
}

func (s *svc) hBid(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in bidIn
	if err := core.Decode(w, r, 8<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	a, err := s.bid(r.Context(), id, r.PathValue("id"), in)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	reply(w, r, 200, bidText(a), a.json(r.Context(), s.d.DB, "", a.party(id.Root)), a.next()...)
}

func (s *svc) hCancel(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	a, err := s.cancel(r.Context(), id, r.PathValue("id"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	reply(w, r, 200, fmt.Sprintf("ok %s cancelled, budget refunded", a.ID), a.json(r.Context(), s.d.DB, "", true), a.next()...)
}

// taskTitle reads a task's title ("" when gone).
func taskTitle(ctx context.Context, q core.Q, n int64) string {
	var title string
	q.QueryRow(ctx, `SELECT title FROM tasks WHERE n = $1`, n).Scan(&title)
	return title
}

var openAPI = json.RawMessage(`{"paths":{
"/v1/au":{"post":{"operationId":"au","summary":"Open a sealed-bid reverse auction: escrow a budget ceiling on a task (new task when title given)","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"task":{"description":"task number or {title,body,tags}"},"budget":{"type":"integer","minimum":5,"maximum":1000},"closes_m":{"type":"integer","minimum":10,"maximum":1440},"min_bidders":{"type":"integer","minimum":2,"maximum":5},"fallback":{"type":"string","enum":["","bounty"]},"key":{"type":"string","maxLength":64}},"required":["task","budget"]}}}},"responses":{"201":{"description":"ok n… closes <date>"},"402":{"description":"err credits earned required"},"429":{"description":"err quota bounties open <k>/<cap>"}}},
"get":{"operationId":"aul","summary":"List auctions (open by default)","parameters":[{"name":"s","in":"query","schema":{"type":"string","enum":["open","closed","all"]}},{"name":"mine","in":"query","schema":{"type":"integer"}},{"name":"k","in":"query","schema":{"type":"integer","maximum":50}}],"responses":{"200":{"description":"auctions s=open k=<n> then '- n… budget<=40cr task=#n closes <date> min_bidders=2 bids=<k>' lines"}}}},
"/v1/au/{id}":{"get":{"operationId":"aug","summary":"Auction detail (bid amounts listed only after close)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"n… <state> budget<=40cr task=#n closes <date> + bids=<k> (sealed) / the bids after close"},"404":{"description":"err notfound"}}}},
"/v1/au/{id}/bid":{"post":{"operationId":"aub","summary":"Place a sealed bid below the budget (L1+, distinct from the creator, 1-credit bond, re-bid replaces)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"amount":{"type":"integer","minimum":1},"note":{"type":"string","maxLength":200},"key":{"type":"string","maxLength":64}},"required":["amount"]}}}},"responses":{"200":{"description":"ok n… bid placed (sealed until <date>)"},"403":{"description":"err level L1 required"},"409":{"description":"err bad bidder must be distinct from the creator | flagged collusion pair"},"429":{"description":"err quota open bids 5/5"}}}},
"/v1/au/{id}/cancel":{"post":{"operationId":"aux","summary":"Cancel a live auction before close: budget and all bonds refunded (creator)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok n… cancelled, budget refunded"},"409":{"description":"err bad auction awarded"}}}}
}}`)
