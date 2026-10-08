package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Admin plane v2 (SPEC-v2 16.1, 21.4, 4.8): the econ and operator routes next to the v1 ones
// mounted by Register (freeze, stats, purge), the daily conservation audit and the 12-month
// retention of ledger, admin_log, audit_fail and ident_retention.

const (
	faucetMax  = 10_000_000 // credits per POST /admin/credits
	originRows = 100        // default rows of GET /admin/origin
	originMax  = 500
)

var asnClasses = map[string]bool{"shared": true, "residential": true, "hosting": true, "blocked": true}

// RegisterAdminV2 mounts GET /admin/audit (poll+), POST /admin/credits, /admin/trusted,
// /admin/seed-root, /admin/asn and GET /admin/origin (admin), registers their scopes and OpenAPI
// fragment, and adds the ledger janitor tasks (daily audit, retention, failure-window sweep).
func RegisterAdminV2(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /admin/audit", d.PollOnly(d.hAudit))
	mux.HandleFunc("POST /admin/credits", d.AdminOnly(d.hCredits))
	mux.HandleFunc("POST /admin/trusted", d.AdminOnly(d.hRootFlag("trusted")))
	mux.HandleFunc("POST /admin/seed-root", d.AdminOnly(d.hRootFlag("seed")))
	mux.HandleFunc("POST /admin/asn", d.AdminOnly(d.hASN))
	mux.HandleFunc("GET /admin/origin", d.AdminOnly(d.hOrigin))
	for _, pat := range []string{"GET /admin/audit", "POST /admin/credits", "POST /admin/trusted", "POST /admin/seed-root",
		"POST /admin/asn", "GET /admin/origin", "POST /admin/freeze", "GET /admin/stats", "POST /admin/purge"} {
		d.RegisterScope(pat, "admin")
	}
	d.RegisterOpenAPI(json.RawMessage(adminOpenAPI))
	d.Janitor.Add("ledger_audit", d.dailyLedgerAudit)
	d.Janitor.Add("ledger_retention", d.ledgerRetention)
	d.Janitor.Add("admin_fails", func(context.Context) error { adminFails.sweep(time.Now()); return nil })
}

// GET /admin/audit -> `ok conserved mint=… burn=…` or `MISMATCH …` (compute and bounties frozen).
func (d *Deps) hAudit(w http.ResponseWriter, r *http.Request) {
	a, err := d.RunLedgerAudit(r.Context())
	if err != nil {
		Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	OK(w, r, a.Line(), a.JSON())
}

// POST /admin/credits {id, n}: the only mint after registration (the faucet funds the system root).
func (d *Deps) hCredits(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID string `json:"id"`
		N  int64  `json:"n"`
	}
	if err := Decode(w, r, 1<<10, &in); err != nil {
		Fail(w, r, err)
		return
	}
	if !ValidIDPrefix(in.ID, 'a') {
		Fail(w, r, Bad("bad id"))
		return
	}
	if in.N < 1 || in.N > faucetMax {
		Fail(w, r, Bad(fmt.Sprintf("n must be 1..%d", faucetMax)))
		return
	}
	AdminArg(r, fmt.Sprintf("id=%s n=%d", in.ID, in.N))
	ctx := r.Context()
	var balance int64
	err := Tx(ctx, d.DB, func(tx pgx.Tx) error {
		var err error
		if balance, err = mint(ctx, tx, in.ID, in.N, "faucet"); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		return Event(ctx, tx, "ops", "faucet:"+in.ID, "", fmt.Sprintf("faucet %d credits to %s", in.N, in.ID))
	})
	if err != nil {
		Fail(w, r, err)
		return
	}
	OK(w, r, fmt.Sprintf("ok id=%s credits=%d minted=%d", in.ID, balance, in.N),
		map[string]any{"ok": true, "id": in.ID, "credits": balance, "minted": in.N})
}

// hRootFlag serves POST /admin/trusted and POST /admin/seed-root {id, on}: a boolean on a root row.
func (d *Deps) hRootFlag(col string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ID string `json:"id"`
			On bool   `json:"on"`
		}
		if err := Decode(w, r, 1<<10, &in); err != nil {
			Fail(w, r, err)
			return
		}
		if !ValidIDPrefix(in.ID, 'a') {
			Fail(w, r, Bad("bad id"))
			return
		}
		AdminArg(r, fmt.Sprintf("id=%s on=%v", in.ID, in.On))
		tag, err := d.DB.Exec(r.Context(), `UPDATE identities SET `+col+` = $2 WHERE id = $1 AND parent IS NULL AND revoked_at IS NULL`, in.ID, in.On)
		if err != nil {
			Fail(w, r, err)
			return
		}
		if tag.RowsAffected() == 0 {
			Fail(w, r, ErrNotFound)
			return
		}
		on := 0
		if in.On {
			on = 1
		}
		OK(w, r, fmt.Sprintf("ok id=%s %s=%d", in.ID, col, on), map[string]any{"ok": true, "id": in.ID, col: in.On})
	}
}

// POST /admin/asn {asn, class, note}: operator rows of asn_policy (3.2, 27.8).
func (d *Deps) hASN(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ASN   int64  `json:"asn"`
		Class string `json:"class"`
		Note  string `json:"note"`
	}
	if err := Decode(w, r, 2<<10, &in); err != nil {
		Fail(w, r, err)
		return
	}
	if in.ASN < 1 || in.ASN > 1<<32 {
		Fail(w, r, Bad("asn must be 1..4294967296"))
		return
	}
	if !asnClasses[in.Class] {
		Fail(w, r, Bad("class must be shared|residential|hosting|blocked"))
		return
	}
	note := cleanLine(in.Note, 200)
	AdminArg(r, fmt.Sprintf("asn=%d class=%s", in.ASN, in.Class))
	if _, err := d.DB.Exec(r.Context(), `INSERT INTO asn_policy (asn, class, note) VALUES ($1, $2, $3)
		ON CONFLICT (asn) DO UPDATE SET class = EXCLUDED.class, note = EXCLUDED.note, updated = now()`, in.ASN, in.Class, note); err != nil {
		Fail(w, r, err)
		return
	}
	OK(w, r, fmt.Sprintf("ok asn=%d class=%s", in.ASN, in.Class), map[string]any{"ok": true, "asn": in.ASN, "class": in.Class, "note": note})
}

// GET /admin/origin?ref=&kind=&k= lists content_origin rows of one ref (4.8): admin only, never
// exported. Rows are newest first; every value was cleaned by core.Origin when written.
func (d *Deps) hOrigin(w http.ResponseWriter, r *http.Request) {
	qs := r.URL.Query()
	ref := cleanLine(qs.Get("ref"), 200)
	if ref == "" {
		Fail(w, r, Bad("ref required"))
		return
	}
	kind := cleanLine(qs.Get("kind"), 32)
	k := originRows
	if v := qs.Get("k"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > originMax {
			Fail(w, r, Bad(fmt.Sprintf("k must be 1..%d", originMax)))
			return
		}
		k = n
	}
	AdminArg(r, "ref="+ref)
	rows, err := d.DB.Query(r.Context(), `SELECT kind, ref, root, id, ip, at FROM content_origin
		WHERE ref = $1 AND ($2 = '' OR kind = $2) ORDER BY at DESC, kind LIMIT $3`, ref, kind, k)
	if err != nil {
		Fail(w, r, err)
		return
	}
	defer rows.Close()
	var b strings.Builder
	var list []map[string]any
	for rows.Next() {
		var o struct {
			kind, ref, root, id, ip string
			at                      time.Time
		}
		if err := rows.Scan(&o.kind, &o.ref, &o.root, &o.id, &o.ip, &o.at); err != nil {
			Fail(w, r, err)
			return
		}
		fmt.Fprintf(&b, "\n- %s %s root=%s id=%s ip=%s at=%s", cleanLine(o.kind, 32), cleanLine(o.ref, 200),
			cleanLine(o.root, 64), cleanLine(o.id, 64), cleanLine(o.ip, 64), o.at.UTC().Format(time.RFC3339))
		list = append(list, map[string]any{"kind": o.kind, "ref": o.ref, "root": o.root, "id": o.id, "ip": o.ip, "at": o.at.UTC().Format(time.RFC3339)})
	}
	if err := rows.Err(); err != nil {
		Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	OK(w, r, fmt.Sprintf("origin ref=%s n=%d", ref, len(list))+b.String(), map[string]any{"ref": ref, "n": len(list), "rows": list})
}

// adminOpenAPI is the fragment of the admin routes (schemas feed Decode's expect: lines).
const adminOpenAPI = `{"paths":{
"/admin/audit":{"get":{"summary":"ledger conservation audit (poll token)"}},
"/admin/stats":{"get":{"summary":"platform counters, flags, storage classes (poll token)"}},
"/admin/freeze":{"post":{"summary":"freeze or lift reg|write|compute|all, freeze:<class>, shed:<level>","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["what"],"properties":{"what":{"type":"string","maxLength":80},"on":{"type":"boolean"}}}}}}}},
"/admin/purge":{"post":{"summary":"revoke a root tree and delete its rows (credits burnt)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"string","maxLength":7}}}}}}}},
"/admin/credits":{"post":{"summary":"faucet: mint grant credits to an identity (the system root)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["id","n"],"properties":{"id":{"type":"string","maxLength":7},"n":{"type":"integer","maximum":10000000}}}}}}}},
"/admin/trusted":{"post":{"summary":"mark a root as an operator-trusted donor","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"string","maxLength":7},"on":{"type":"boolean"}}}}}}}},
"/admin/seed-root":{"post":{"summary":"mark a root as an operator seed root","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"string","maxLength":7},"on":{"type":"boolean"}}}}}}}},
"/admin/asn":{"post":{"summary":"set the registration policy of an ASN","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["asn","class"],"properties":{"asn":{"type":"integer","maximum":4294967296},"class":{"type":"string","maxLength":11},"note":{"type":"string","maxLength":200}}}}}}}},
"/admin/origin":{"get":{"summary":"content_origin rows of one ref (?ref=&kind=&k=)"}}
}}`
