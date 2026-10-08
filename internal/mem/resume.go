package mem

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// resumeOpts are the resume parameters: name picks a lineage (default: newest checkpoint), full
// shows the whole body, kv inlines the KV values.
type resumeOpts struct {
	name     string
	full, kv bool
}

// resume builds the bundle (10.1) in one read tx: me line, latest checkpoint, unread later,
// KV keys, live task claims, jobs, recent audit, then the OnResume hooks; `fresh` when empty.
// Updates last_seen.
func (s *svc) resume(ctx context.Context, id *core.Ident, o resumeOpts) (*doc.Doc, error) {
	d := &doc.Doc{Budget: 800}
	var (
		cp                *Checkpoint
		laterN            int
		subjects, kvLines []string
		kvN               int
		claims            []string
		queued, running   int
		recent            []string
		mk                bool
	)
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var mkb []byte
		if err := tx.QueryRow(ctx, `UPDATE identities SET last_seen = now() WHERE id = $1 RETURNING coalesce(mk_wrapped, ''::bytea)`, id.Root).Scan(&mkb); err != nil {
			return err
		}
		mk = len(mkb) > 0
		var err error
		if o.name != "" {
			if cp, err = cpLatest(ctx, tx, id.Root, o.name); err != nil && err != core.ErrNotFound {
				return err
			}
		} else if cp, err = cpNewest(ctx, tx, id.Root); err != nil {
			return err
		}
		if laterN, subjects, err = laterUnread(ctx, tx, id.Root, 5); err != nil {
			return err
		}
		rows, err := kvList(ctx, tx, nspace{raw: "a:" + id.Root, kind: 'a', name: id.Root}, "", 50)
		if err != nil {
			return err
		}
		kvN = len(rows)
		for _, x := range rows {
			line := kvRowLine(x)
			if o.kv {
				line += "\n  " + strings.ReplaceAll(doc.Indent(kvValText(x, false)), "\n", "\n  ")
			}
			kvLines = append(kvLines, line)
		}
		cl, err := tx.Query(ctx, `SELECT n, until FROM task_claims WHERE root = $1 AND until > now() ORDER BY until LIMIT 20`, id.Root)
		if err != nil {
			return err
		}
		for cl.Next() {
			var n int64
			var until time.Time
			if err := cl.Scan(&n, &until); err != nil {
				cl.Close()
				return err
			}
			claims = append(claims, fmt.Sprintf("t:%d until=%s", n, rfc(until)))
		}
		cl.Close()
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'queued'), count(*) FILTER (WHERE status = 'running') FROM jobs WHERE root = $1 AND status IN ('queued', 'running')`, id.Root).Scan(&queued, &running); err != nil {
			return err
		}
		recent, err = auditLines(ctx, tx, id.Root, time.Time{}, "", 5)
		return err
	})
	if err != nil {
		return nil, err
	}
	lvl := levelOf(ctx, s.d.DB, id.Root)
	seal := "set"
	if !mk {
		seal = "unset"
	}
	fresh := cp == nil && laterN == 0 && kvN == 0 && len(claims) == 0 && queued+running == 0
	if fresh {
		d.Head = fmt.Sprintf("resume %s fresh lvl=L%d seal=%s", id.Root, lvl, seal)
	} else {
		d.Head = fmt.Sprintf("resume %s lvl=L%d seal=%s cp=%d later=%d kv=%d claims=%d jobs=%d", id.Root, lvl, seal, b2i(cp != nil), laterN, kvN, len(claims), queued+running)
	}
	d.Fields = append(d.Fields, doc.F{Name: "me", Val: fmt.Sprintf("id=%s name=%s root=%s credits=%d rep=%d lvl=L%d", id.ID, id.Name, id.Root, id.Credits, id.Rep, lvl)})
	if cp != nil {
		d.Fields = append(d.Fields, doc.F{Name: "cp", Val: cpHead(cp)})
		if cp.Summary != "" {
			d.Fields = append(d.Fields, doc.F{Name: "summary", Val: cp.Summary})
		}
		if cp.Sealed {
			d.Fields = append(d.Fields, doc.F{Name: "body", Val: "[sealed]"})
		} else if o.full {
			if b := cpBody(cp, nil, false); b != "" {
				d.Fields = append(d.Fields, doc.F{Name: "body", Val: b, Multi: true})
			}
		} else if cp.Sections != nil {
			d.Fields = append(d.Fields, doc.F{Name: "body", Val: renderCP1(cp.Sections, cp1Default), Multi: true})
		}
	}
	if laterN > 0 {
		d.Fields = append(d.Fields, doc.F{Name: "later", Val: strconv.Itoa(laterN) + " unread\n" + strings.Join(subjects, "\n"), Multi: true})
	}
	if kvN > 0 {
		d.Fields = append(d.Fields, doc.F{Name: "kv", Val: strconv.Itoa(kvN) + " keys\n" + strings.Join(kvLines, "\n"), Multi: true})
	}
	if len(claims) > 0 {
		d.Fields = append(d.Fields, doc.F{Name: "claims", Val: strconv.Itoa(len(claims)) + "\n" + strings.Join(claims, "\n"), Multi: true})
	}
	if queued+running > 0 {
		d.Fields = append(d.Fields, doc.F{Name: "jobs", Val: fmt.Sprintf("queued=%d running=%d", queued, running)})
	}
	if len(recent) > 0 {
		d.Fields = append(d.Fields, doc.F{Name: "recent", Val: strings.Join(recent, "\n"), Multi: true})
	}
	for _, l := range s.d.ResumeLines(ctx, id.Root) {
		d.Rows = append(d.Rows, []string{l})
	}
	d.Next = []doc.Action{doc.POST("/v1/cp", "checkpoint"), doc.GET("/v1/me/log", ""), doc.GET("/v1/kv/me", ""), doc.GET("/v1/me", "")}
	if cp != nil {
		d.Next = append([]doc.Action{doc.GET("/v1/cp/"+cp.Name, "latest body")}, d.Next[:3]...)
	}
	return d, nil
}

func (s *svc) hResume(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	q := r.URL.Query()
	o := resumeOpts{name: q.Get("name"), full: q.Get("full") == "1", kv: q.Get("kv") == "1"}
	if o.name != "" && !cpNameRe.MatchString(o.name) {
		doc.Fail(w, r, core.Bad("name must match [a-z0-9._-]{1,64}"))
		return
	}
	d, err := s.resume(r.Context(), id, o)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	reply(w, r, 200, d)
}

// --- audit log (10.5) --------------------------------------------------------------------------------

var opRe = regexp.MustCompile(`^[a-z][a-z0-9:_-]{0,31}$`)

// auditLines returns "<ts> <id> <op> <ref> <n>" lines of a root tree, newest first.
func auditLines(ctx context.Context, q core.Q, root string, since time.Time, op string, k int) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT ts, id, op, ref, n FROM audit WHERE root = $1 AND ($2::timestamptz IS NULL OR ts >= $2) AND ($3 = '' OR op = $3)
		ORDER BY ts DESC LIMIT $4`, root, nullTime(since), op, k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ts time.Time
		var id, o, ref string
		var n int
		if err := rows.Scan(&ts, &id, &o, &ref, &n); err != nil {
			return nil, err
		}
		if ref == "" {
			ref = "-"
		}
		out = append(out, fmt.Sprintf("%s %s %s %s %d", ts.UTC().Format("2006-01-02T15:04:05Z"), id, o, doc.SafeLine(ref), n))
	}
	return out, rows.Err()
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// parseSince accepts RFC 3339 or YYYY-MM-DD.
func parseSince(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, core.Bad("since must be RFC 3339 or YYYY-MM-DD")
}

func (s *svc) hLog(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	since, err := parseSince(r.URL.Query().Get("since"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	op := r.URL.Query().Get("op")
	if op != "" && !opRe.MatchString(op) {
		doc.Fail(w, r, core.Bad("op must match [a-z][a-z0-9:_-]{0,31}"))
		return
	}
	lines, err := auditLines(r.Context(), s.d.DB, id.Root, since, op, intParam(r, "k", 50, 1, 100))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	reply(w, r, 200, logDoc(id.Root, lines))
}

func logDoc(root string, lines []string) *doc.Doc {
	d := &doc.Doc{Head: fmt.Sprintf("log %s n=%d", root, len(lines)), Cols: []string{"ts", "id", "op", "ref", "n"}, Budget: 400}
	for _, l := range lines {
		d.Rows = append(d.Rows, strings.SplitN(l, " ", 5))
	}
	d.Next = []doc.Action{doc.GET("/v1/me/resume", ""), doc.GET("/v1/me/log?k=100", "more")}
	return d
}

// AuditTrim keeps the ring (10.5): 30 d TTL and the last AuditRows rows per root (janitor task).
func AuditTrim(ctx context.Context, q core.Q) error {
	if _, err := q.Exec(ctx, `DELETE FROM audit WHERE ts < now() - interval '30 days'`); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `WITH big AS (SELECT root FROM audit GROUP BY root HAVING count(*) > $1)
		DELETE FROM audit a USING big WHERE a.root = big.root
		  AND a.ts <= (SELECT b.ts FROM audit b WHERE b.root = a.root ORDER BY b.ts DESC OFFSET $1 LIMIT 1)`, AuditRows)
	return err
}
