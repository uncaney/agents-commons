package kb

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"mime"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Anonymous confirmations (SPEC-v2 27.2, P78): POST /w/k/{id}/ok|bad with an X-PoW header (hash or
// wait lane) record a day-keyed, group-collapsed row in kb_votes_anon (one per IP group per entry
// per day, 30-day TTL) and bump the soft counters kb.anon_ok / kb.anon_bad. These counters feed the
// `anon+n-m` header line and the ranking nudge only; they are NEVER counted in ok_w/bad_w, nor in
// promotion, hiding, reputation or upvoteCount. A `bad` with a reason adds an anon-marked fails:
// hint (kb_anon_fails, <= 20 per entry). Quarantined entries accept them as reviewer hints.

const (
	anonVotePerGroup = 10       // confirmations per IP group per day (super-group = 4x, 27.2)
	anonVoteKind     = "kbanon" // day-counter kind for core.UseNetQuota
	anonWhyMax       = maxWhy   // bytes of an anonymous `bad` reason
	anonFailsCap     = 20       // anon-marked fails: hints kept per entry
	anonVoteTTL      = 30 * 24 * time.Hour
)

// ErrAnonVoted: this IP group already confirmed this entry today (one per group per entry per day).
var errAnonVoted = core.E(409, "dup", "already confirmed today")

// anonDayKey is HKDF(server_secret, "kb_anon_vote"|YYYY-MM-DD): the daily key the group hash rotates
// under, so no raw network key is ever stored and yesterday's rows are not re-countable.
func anonDayKey(secret []byte, t time.Time) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, "kb_anon_vote|"+t.UTC().Format("2006-01-02"), 32)
	if err != nil {
		return make([]byte, 32)
	}
	return k
}

// anonGrpHash is HMAC(day key, group)[:16]: the stored, un-reversible per-day group identifier.
func anonGrpHash(secret []byte, group string, t time.Time) []byte {
	m := hmac.New(sha256.New, anonDayKey(secret, t))
	m.Write([]byte(group))
	return m.Sum(nil)[:16]
}

// AnonVoteResult is what an anonymous confirmation changed.
type AnonVoteResult struct {
	Up      bool `json:"up"`
	AnonOK  int  `json:"anon_ok"`
	AnonBad int  `json:"anon_bad"`
}

// Line is the reply head: `ok anon+<ok>-<bad>`.
func (r AnonVoteResult) Line() string {
	return "ok anon+" + itoa(r.AnonOK) + "-" + itoa(r.AnonBad)
}

func (r AnonVoteResult) json() map[string]any {
	return map[string]any{"ok": true, "anon_ok": r.AnonOK, "anon_bad": r.AnonBad}
}

// AnonVote records one anonymous confirmation (27.2): dedupe by day-keyed group hash (one per group
// per entry per day), charge the per-group (10/day) and per-super-group (40/day) caps, bump the soft
// counter, and for a `bad` with a reason keep an anon fails: hint (<= 20). Hidden, merged and
// expired rows answer 404; quarantined rows accept the vote as a reviewer hint.
func AnonVote(ctx context.Context, d *core.Deps, kid string, up bool, grp, super, why string) (AnonVoteResult, error) {
	res := AnonVoteResult{Up: up}
	if !core.ValidIDPrefix(kid, 'k') {
		return res, core.ErrNotFound
	}
	if d.Frozen("write") {
		return res, core.Frozen("write")
	}
	if grp == "" {
		return res, core.Bad("anonymous vote needs its network keys")
	}
	why = cleanMulti(why)
	if len(why) > anonWhyMax {
		return res, core.Bad("why > 200 bytes")
	}
	kind := "ok"
	col := "anon_ok"
	if !up {
		kind, col = "bad", "anon_bad"
	}
	now := time.Now()
	grpH := anonGrpHash(d.Cfg.ServerSecret, grp, now)
	err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		e, err := lockEntry(ctx, tx, kid)
		if err != nil {
			return err
		}
		if e.Hidden || e.SupersededBy != "" {
			return core.ErrNotFound
		}
		tag, err := tx.Exec(ctx, `INSERT INTO kb_votes_anon (kb_id, grp_h, day, kind) VALUES ($1, $2, current_date, $3) ON CONFLICT (kb_id, grp_h) DO NOTHING`,
			kid, grpH, kind)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errAnonVoted // same group, same entry, same day
		}
		if err := core.UseNetQuota(ctx, tx, grp, anonVoteKind, anonVotePerGroup); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `UPDATE kb SET `+col+` = `+col+` + 1 WHERE id = $1 RETURNING anon_ok, anon_bad`, kid).Scan(&res.AnonOK, &res.AnonBad); err != nil {
			return err
		}
		if !up && why != "" {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM kb_anon_fails WHERE kb_id = $1`, kid).Scan(&n); err != nil {
				return err
			}
			if n < anonFailsCap {
				if _, err := tx.Exec(ctx, `INSERT INTO kb_anon_fails (kb_id, why, day) VALUES ($1, $2, current_date)`, kid, doc.SafeLine(why)); err != nil {
					return err
				}
			}
		}
		return mirror(ctx, tx, kid)
	})
	if err != nil {
		return AnonVoteResult{Up: up}, err
	}
	return res, nil
}

// AnonFails returns the anon-marked fails: hints of an entry, newest first (reviewer aid, 27.2).
func AnonFails(ctx context.Context, q core.Q, kid string, n int) ([]string, error) {
	if n <= 0 || n > anonFailsCap {
		n = anonFailsCap
	}
	rows, err := q.Query(ctx, `SELECT why FROM kb_anon_fails WHERE kb_id = $1 ORDER BY day DESC, ctid DESC LIMIT $2`, kid, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var why string
		if err := rows.Scan(&why); err != nil {
			return nil, err
		}
		out = append(out, "fails: "+doc.SafeLine(why)+" (anon)")
	}
	return out, rows.Err()
}

// PurgeAnonVotes drops kb_votes_anon rows older than 30 days (janitor task kb_anon_votes); returns
// the number removed. The day-keyed hash is already un-countable by then; this reclaims the rows.
func PurgeAnonVotes(ctx context.Context, q core.Q) (int, error) {
	tag, err := q.Exec(ctx, `DELETE FROM kb_votes_anon WHERE day < current_date - $1::int`, int(anonVoteTTL/(24*time.Hour)))
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// AnonNext are the next: actions GET /k/{id} offers an anonymous caller (pages.KbNextFn, 27.2): the
// anonymous confirmation lane with its PoW variant. A token caller gets nil (the default actions).
func AnonNext(id string, anon bool) []doc.Action {
	if !anon || !core.ValidIDPrefix(id, 'k') {
		return nil
	}
	return doc.Next(doc.POST("/w/k/"+id+"/ok", "+X-PoW"), doc.POST("/w/k/"+id+"/bad", "+X-PoW"), doc.GET("/k/"+id+".md", ""))
}

// --- HTTP + ops ---------------------------------------------------------------------------------

// AnonVotesHelp is the op list of this file for help{t:kb} (<= 60 tokens).
const AnonVotesHelp = `kaok{id,pow} confirm anonymously (X-PoW) | kabad{id,why,pow} report anonymously; soft anon+n-m counters, never counted in ok_w/bad_w/promotion/rep`

// AnonVotesOpMeta describes the ops of AnonVotesOps for the MCP registry (3.5).
var AnonVotesOpMeta = map[string]core.OpMeta{
	"kaok":  {Scope: "kb:r", Cost: 1, Mutating: true},
	"kabad": {Scope: "kb:r", Cost: 1, Mutating: true},
}

var anonVotesOpenAPI = json.RawMessage(`{"paths":{
"/w/k/{id}/ok":{"post":{"operationId":"kaok","summary":"Confirm an entry anonymously (header X-PoW: <c>:<nonce> for=w, hash or wait lane): one per network per entry per day; soft anon counter, never promotes","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"v":{"type":"string","maxLength":120}}}}}},"responses":{"200":{"description":"ok anon+<ok>-<bad> then next:"},"400":{"description":"err pow"},"404":{"description":"err notfound"},"409":{"description":"err dup already confirmed today"},"429":{"description":"err quota"}}}},
"/w/k/{id}/bad":{"post":{"operationId":"kabad","summary":"Report an entry anonymously (X-PoW): optional why becomes an anon-marked fails: hint (<= 20 per entry); never hides","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"why":{"type":"string","maxLength":200}}}}}},"responses":{"200":{"description":"ok anon+<ok>-<bad> then next:"},"400":{"description":"err pow"},"404":{"description":"err notfound"},"409":{"description":"err dup already confirmed today"},"429":{"description":"err quota"}}}}
}}`)

// RegisterAnonVotes mounts the anonymous confirmation routes and the 30-day purge of kb_votes_anon.
func RegisterAnonVotes(mux *http.ServeMux, d *core.Deps) {
	h := &anonVotesHandlers{d}
	mux.HandleFunc("POST /w/k/{id}/ok", h.vote(true))
	mux.HandleFunc("POST /w/k/{id}/bad", h.vote(false))
	d.RegisterOpenAPI(anonVotesOpenAPI)
	d.Janitor.Add("kb_anon_votes", func(ctx context.Context) error {
		_, err := PurgeAnonVotes(ctx, d.DB)
		return err
	})
}

type anonVotesHandlers struct{ d *core.Deps }

// powKeys spends the X-PoW header (hash or wait lane via the installed XPoWFn) and returns the
// network keys the caps are charged to, falling back to the request's own IP group.
func (h *anonVotesHandlers) powKeys(w http.ResponseWriter, r *http.Request) (grp, super string, err error) {
	if r.Header.Get("X-PoW") == "" {
		h.d.PoWAuthenticate(w, r)
	}
	grp, super, err = h.d.XPoW(r.Context(), r)
	if err != nil {
		return "", "", err
	}
	if grp == "" {
		grp = h.d.IPGroup(r)
	}
	if super == "" {
		super = core.IPSuper(grp)
	}
	return grp, super, nil
}

func (h *anonVotesHandlers) vote(up bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.d.Frozen("write") {
			doc.Fail(w, r, core.Frozen("write"))
			return
		}
		grp, super, err := h.powKeys(w, r)
		if err != nil {
			doc.Fail(w, r, err, doc.POST("/v1/challenge", "for=w"))
			return
		}
		why := h.reason(w, r, up)
		res, err := AnonVote(r.Context(), h.d, r.PathValue("id"), up, grp, super, why)
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		h.d.PoWAuthenticate(w, r)
		next := doc.Next(doc.GET("/k/"+r.PathValue("id"), ""), doc.POST("/w/k/"+r.PathValue("id")+"/ok", "+X-PoW"))
		if doc.Negotiate(r) == doc.JSON {
			core.JSON(w, 200, res.json())
			return
		}
		doc.TailStatus(w, r, 200, res.Line(), next...)
	}
}

// reason reads the optional v (ok) / why (bad) field from a form or JSON body; a decode failure
// leaves it empty (the vote still counts).
func (h *anonVotesHandlers) reason(w http.ResponseWriter, r *http.Request, up bool) string {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct == "application/x-www-form-urlencoded" || ct == "multipart/form-data" {
		core.MaxBytes(w, r, 4<<10)
		if up {
			return r.PostFormValue("v")
		}
		return r.PostFormValue("why")
	}
	var in struct {
		V   string `json:"v"`
		Why string `json:"why"`
	}
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		return ""
	}
	if up {
		return in.V
	}
	return in.Why
}

// AnonVotesOps returns the MCP operations of this file: kaok, kabad (anonymous confirmations).
func AnonVotesOps(d *core.Deps) map[string]Op {
	vote := func(up bool) Op {
		return func(ctx context.Context, _ *core.Ident, a json.RawMessage) (string, error) {
			if d.Frozen("write") {
				return "", core.Frozen("write")
			}
			var in struct {
				ID  string `json:"id"`
				Why string `json:"why"`
				V   string `json:"v"`
				Pow string `json:"pow"`
			}
			if len(a) > 0 {
				if err := json.Unmarshal(a, &in); err != nil {
					return "", core.Bad("a: " + err.Error())
				}
			}
			if in.Pow == "" {
				return "", core.ErrAuth
			}
			r, _ := http.NewRequest(http.MethodPost, "/w/k/"+in.ID+"/ok", nil)
			r = r.WithContext(ctx)
			r.Header.Set("X-PoW", in.Pow)
			ip, _, _ := core.ClientFrom(ctx)
			r.RemoteAddr = ip + ":0"
			grp, super, err := d.XPoW(ctx, r)
			if err != nil {
				return "", err
			}
			if grp == "" {
				_, grp, super = core.ClientFrom(ctx)
			}
			why := in.Why
			if up {
				why = in.V
			}
			res, err := AnonVote(ctx, d, in.ID, up, grp, super, why)
			if err != nil {
				return "", err
			}
			return res.Line(), nil
		}
	}
	return map[string]Op{"kaok": vote(true), "kabad": vote(false)}
}
