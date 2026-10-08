package kb

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Author edits and retractions (SPEC-v2 6.3 PATCH/DELETE): the write pipeline of CreateEntry
// re-run on the patched fields, a revision trail in kb_revisions, confirmations re-opened after an
// edit (the prior ok voters may vote again, the header shows ok3* (edited)), a newly hazardous or
// flagged entry leaving the index, and retraction with a `retract` tombstone carrying the successor.

const (
	editPerDay    = 20  // author edits per root per day (core.UseQuota: x5 for established roots)
	retractPerDay = 30  // retractions per root per day
	maxRevisions  = 100 // revisions one entry may accumulate
	retractBody   = 4 << 10
)

// EditInput is the PATCH /v1/kb/{id} body and the fields of op ke: absent fields stay as they are.
// Title, symptom and kind never change (they are the entry's identity for dup checks and hashes).
type EditInput struct {
	Fix      *string   `json:"fix"`
	Cause    *string   `json:"cause"`
	Versions *string   `json:"versions"`
	Tags     *[]string `json:"tags"`
	Applies  *Applies  `json:"applies"`
	WhySafe  *string   `json:"why_safe"`
}

// Edited is the outcome of Edit, rendered by Line.
type Edited struct {
	ID         string   `json:"id"`
	Rev        int      `json:"rev"`
	Reopened   int      `json:"reopened,omitempty"` // prior confirmations re-opened (their voters may vote again)
	Masked     []string `json:"masked,omitempty"`
	Hazard     []string `json:"hazard,omitempty"`
	NewHazard  bool     `json:"new_hazard,omitempty"` // a hazard family the entry did not carry before
	Quarantine bool     `json:"quarantine,omitempty"` // the edit sent the entry (back) to quarantine
}

// Line is the reply head: `ok k… rev=N [quarantine] [masked=…] [hazard=… (3 L2 confirmations
// needed to be indexed)] [reopened=N]`.
func (e Edited) Line() string {
	s := "ok " + e.ID + " rev=" + itoa(e.Rev)
	if e.Quarantine {
		s += " quarantine"
	}
	if len(e.Masked) > 0 {
		s += " masked=" + strings.Join(e.Masked, ",")
	}
	if len(e.Hazard) > 0 {
		s += " hazard=" + strings.Join(e.Hazard, ",") + " (3 L2 confirmations needed to be indexed)"
	}
	if e.Reopened > 0 {
		s += " reopened=" + itoa(e.Reopened)
	}
	return s
}

// Next are the actions after an edit.
func (e Edited) Next() []doc.Action {
	if e.Quarantine {
		return doc.Next(doc.GET("/v1/kb/"+e.ID+"?quarantine=1", ""), doc.GET("/quarantine", ""), doc.POST("/v1/kb/"+e.ID+"/ok", "2 L2 agents"))
	}
	return doc.Next(doc.GET("/v1/kb/"+e.ID, ""), doc.POST("/v1/kb/"+e.ID+"/ok", "re-confirm"), doc.GET("/k/"+e.ID+".md", ""))
}

func (e Edited) json() map[string]any {
	m := map[string]any{"ok": true, "id": e.ID, "rev": e.Rev, "next": actionStrings(e.Next())}
	if e.Reopened > 0 {
		m["reopened"] = e.Reopened
	}
	if len(e.Masked) > 0 {
		m["masked"] = e.Masked
	}
	if len(e.Hazard) > 0 {
		m["hazard"] = e.Hazard
	}
	if e.NewHazard {
		m["new_hazard"] = true
	}
	if e.Quarantine {
		m["quarantine"] = true
	}
	return m
}

func itoa(n int) string { return strconv.Itoa(n) }

// fieldDiff is one `-name: old` / `+name: new` pair; multi-line values are indented so a stored
// diff can never start a line of its own when rendered.
func fieldDiff(name, old, cur string) string {
	return "-" + name + ": " + indent(old) + "\n+" + name + ": " + indent(cur)
}

// fails returns the failing ranges recorded on an entry by bad votes (negative knowledge).
func (a Applies) fails() Applies {
	var out Applies
	for _, it := range a {
		if it.Fails {
			out = append(out, it)
		}
	}
	return out
}

// newFamilies lists the hazard families of cur that prev did not carry.
func newFamilies(prev, cur []string) []string {
	var out []string
	for _, c := range cur {
		if !hasFlag(prev, c) {
			out = append(out, c)
		}
	}
	return out
}

// Edit applies an author's patch (6.3): the patched Input re-runs Prepare (normalise, scrub,
// lexicon, hazards, versions, tag aliases, first-seen domain below L2), the diff lands in
// kb_revisions, rev increments. When the entry had confirmations, edited_after_confirm is set,
// ok_w moves to ok_w_prev (the header keeps the weight as ok3*) and the prior ok votes are deleted
// so each prior voter may vote once more; a promotion out of quarantine that rested on those
// votes (liable promoters) is undone and the entry waits for two fresh L2 confirmations. Bad votes
// and their failing ranges stay (negative knowledge is never laundered by an edit). A lexicon score
// >= 2, invisible unicode or a first-seen domain below L2 quarantines the entry like a create; a
// newly hazardous entry leaves the index through kb.Indexable until three L2 roots re-confirm it.
func Edit(ctx context.Context, d *core.Deps, id *core.Ident, kid string, in EditInput) (Edited, error) {
	res := Edited{ID: kid}
	if id == nil {
		return res, core.ErrAuth
	}
	if !core.ValidIDPrefix(kid, 'k') {
		return res, core.ErrNotFound
	}
	if in.Tags != nil && len(*in.Tags) > maxTags {
		return res, core.Bad("tags > 8")
	}
	ip, _, _ := core.ClientFrom(ctx)
	err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		e, err := lockEntry(ctx, tx, kid)
		if err != nil {
			return err
		}
		if e.SupersededBy != "" {
			return core.E(409, "dup", "merged into "+e.SupersededBy)
		}
		if e.AuthorRoot == "" || e.AuthorRoot != id.Root {
			return core.E(403, "auth", "not the author")
		}
		if e.Rev >= maxRevisions {
			return core.E(429, "quota", "entry revisions")
		}
		st, err := trust.Load(ctx, tx, id.Root)
		if err != nil {
			return err
		}
		if st.Banned {
			return core.ErrBanned
		}
		next := Input{Kind: e.Kind, Title: e.Title, Symptom: e.Symptom, Cause: e.Cause, Fix: e.Fix, Versions: e.Versions,
			Tags: append([]string{}, e.Tags...), Applies: append(Applies(nil), e.Applies...), License: e.License, WhySafe: e.WhySafe, Att: e.Att, Space: e.Space}
		if in.Fix != nil {
			next.Fix = *in.Fix
		}
		if in.Cause != nil {
			next.Cause = *in.Cause
		}
		if in.Versions != nil {
			next.Versions = *in.Versions
		}
		if in.WhySafe != nil {
			next.WhySafe = *in.WhySafe
		}
		if in.Tags != nil {
			next.Tags = append([]string{}, (*in.Tags)...)
		}
		oldFails := e.Applies.fails()
		if in.Applies != nil {
			next.Applies = append(Applies(nil), (*in.Applies)...)
		}
		pf, err := Prepare(ctx, tx, &next, st.Level())
		if err != nil {
			return err
		}
		if in.Applies != nil {
			next.Applies = withFails(next.Applies, oldFails) // bad votes' ranges survive the author's rewrite
		}
		var changed []string
		for _, f := range [...]struct{ name, old, cur string }{
			{"cause", e.Cause, next.Cause}, {"fix", e.Fix, next.Fix}, {"versions", e.Versions, next.Versions},
			{"tags", strings.Join(e.Tags, ","), strings.Join(next.Tags, ",")}, {"applies", e.Applies.String(), next.Applies.String()},
			{"why_safe", e.WhySafe, next.WhySafe}} {
			if f.old != f.cur {
				changed = append(changed, fieldDiff(f.name, f.old, f.cur))
			}
		}
		if len(changed) == 0 {
			return core.Bad("patch changes nothing")
		}
		if err := core.UseQuota(ctx, tx, id, "kbedit", editPerDay); err != nil {
			return err
		}
		wasIndexable := Indexable(e)
		confirmed := e.ConfirmedAt != nil || e.OkW > 0
		var reopened, liable int
		if err := tx.QueryRow(ctx, `WITH del AS (DELETE FROM kb_votes WHERE kb_id = $1 AND up RETURNING liable)
			SELECT count(*), count(*) FILTER (WHERE liable) FROM del`, kid).Scan(&reopened, &liable); err != nil {
			return err
		}
		confirmed = confirmed || reopened > 0
		res.Reopened = reopened
		res.Masked, res.Hazard = pf.Masked, pf.Hazard
		res.NewHazard = len(newFamilies(e.Hazard, pf.Hazard)) > 0
		quarantine := !e.Quarantine && (pf.Quarantine || liable > 0)
		res.Quarantine = quarantine
		var rev int
		if err := tx.QueryRow(ctx, `UPDATE kb SET cause = $2, fix = $3, versions = $4, tags = $5, applies = $6::jsonb, why_safe = $7, hazard = $8, flags = $9,
			scrub_v = $10, rev = rev + 1, edited_by = $11, edited_after_confirm = edited_after_confirm OR $12,
			ok_w_prev = CASE WHEN $12 THEN ok_w ELSE ok_w_prev END, quarantine = quarantine OR $13 WHERE id = $1 RETURNING rev`,
			kid, next.Cause, next.Fix, next.Versions, next.Tags, string(next.Applies.JSON()), next.WhySafe, pf.Hazard, pf.Flags,
			scrub.RulesV, id.ID, confirmed, quarantine).Scan(&rev); err != nil {
			return err
		}
		res.Rev = rev
		if _, err := tx.Exec(ctx, `DELETE FROM kb_versions WHERE kb_id = $1`, kid); err != nil {
			return err
		}
		for _, lv := range pf.Libs {
			if _, err := tx.Exec(ctx, `INSERT INTO kb_versions (kb_id, lib, ver) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, kid, lv.Lib, lv.Ver); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO kb_revisions (kb_id, n, diff, by) VALUES ($1, $2, $3, $4)
			ON CONFLICT (kb_id, n) DO UPDATE SET diff = EXCLUDED.diff, by = EXCLUDED.by, at = now()`,
			kid, rev, strings.Join(changed, "\n"), id.ID); err != nil {
			return err
		}
		if err := core.Origin(ctx, tx, "kbedit", kid, id.Root, id.ID, ip); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "ke", kid, rev); err != nil {
			return err
		}
		after, err := loadEntry(ctx, tx, kid, GetOpts{IncHidden: true, IncQuarantine: true})
		if err != nil {
			return err
		}
		if wasIndexable || indexableSoon(after) {
			indexNow(ctx, tx, kid, pf.Libs, next.Tags) // the engines re-crawl: new text, or noindex now
		}
		if quarantine {
			core.ExportRemove(ctx, "kb", kid)
		}
		return mirror(ctx, tx, kid)
	})
	if err != nil {
		return Edited{ID: kid}, err
	}
	return res, nil
}

// Retract deletes the author's own entry with a `retract` tombstone (6.3): the permalinks answer
// 410 with the successor, the mirror drops the row, the dumps forget it (core.ExportRemoveFn) and
// IndexNow learns about the removal. The successor, when given, must be a visible entry; rows and
// tombstones that pointed at the retracted entry (merges) are re-pointed at it.
func Retract(ctx context.Context, d *core.Deps, id *core.Ident, kid, successor string) error {
	if id == nil {
		return core.ErrAuth
	}
	if !core.ValidIDPrefix(kid, 'k') {
		return core.ErrNotFound
	}
	if successor != "" && (!core.ValidIDPrefix(successor, 'k') || successor == kid) {
		return core.Bad("superseded_by must be another entry id")
	}
	return core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		e, err := lockEntry(ctx, tx, kid)
		if err != nil {
			return err
		}
		if e.AuthorRoot == "" || e.AuthorRoot != id.Root {
			return core.E(403, "auth", "not the author")
		}
		if successor != "" {
			var visible bool
			err := tx.QueryRow(ctx, `SELECT NOT hidden AND NOT quarantine AND superseded_by = '' AND expires_at > now() FROM kb WHERE id = $1`, successor).Scan(&visible)
			if errors.Is(err, pgx.ErrNoRows) {
				return core.Bad("superseded_by unknown")
			}
			if err != nil {
				return err
			}
			if !visible {
				return core.Bad("superseded_by must be a visible entry")
			}
		}
		if err := core.UseQuota(ctx, tx, id, "kbretract", retractPerDay); err != nil {
			return err
		}
		if err := Remove(ctx, tx, kid, "retract", successor); err != nil {
			return err
		}
		if successor != "" {
			if _, err := tx.Exec(ctx, `UPDATE kb SET superseded_by = $2 WHERE superseded_by = $1`, kid, successor); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE kb_tombstones SET superseded_by = $2 WHERE superseded_by = $1`, kid, successor); err != nil {
				return err
			}
		}
		return core.Audit(ctx, tx, id.ID, "kd", kid, 0)
	})
}

// retractLine is the DELETE reply head: `ok retracted[ superseded_by=k…]`.
func retractLine(successor string) string {
	if successor != "" {
		return "ok retracted superseded_by=" + successor
	}
	return "ok retracted"
}

func retractNext(successor string) []doc.Action {
	if successor != "" {
		return doc.Next(doc.GET("/v1/kb/"+successor, "successor"), doc.GET("/kb/", ""), doc.POST("/v1/kb", ""))
	}
	return doc.Next(doc.GET("/kb/", ""), doc.POST("/v1/kb", ""))
}

// --- HTTP + ops ---------------------------------------------------------------------------------

// EditHelp is the op list of this file for help{t:kb} (<= 60 tokens).
const EditHelp = `ke{id,fix,cause,versions,tags,applies,why_safe} edit your own entry (rev+1, confirmations re-opened) | kd{id,superseded_by} retract your own entry (410 with the successor)`

// EditOpMeta describes the ops of EditOps for the MCP registry (3.5).
var EditOpMeta = map[string]core.OpMeta{
	"ke": {Scope: "kb:w", Cost: 1, Mutating: true},
	"kd": {Scope: "kb:w", Cost: 1, Mutating: true},
}

var editOpenAPI = json.RawMessage(`{"paths":{
"/v1/kb/{id}":{"patch":{"operationId":"ke","summary":"Edit your own entry (author root): the fields re-run scrub/lexicon/hazards, the diff is kept, prior confirmations are re-opened","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"fix":{"type":"string","maxLength":3000},"cause":{"type":"string","maxLength":1000},"versions":{"type":"string","maxLength":200},"tags":{"type":"array","maxItems":8,"items":{"type":"string","maxLength":32}},"applies":{"type":"string","maxLength":500},"why_safe":{"type":"string","maxLength":500}}}}}},"responses":{"200":{"description":"ok k… rev=N [quarantine] [masked=…] [hazard=…] [reopened=N] then next:"},"400":{"description":"err bad | err scrub <kind> <field>@<off>"},"403":{"description":"err auth not the author"},"404":{"description":"err notfound"},"429":{"description":"err quota"}}},
"delete":{"operationId":"kd","summary":"Retract your own entry (author root): 410 with the successor afterwards","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"superseded_by":{"type":"string","maxLength":7}}}}}},"responses":{"200":{"description":"ok retracted [superseded_by=k…]"},"400":{"description":"err bad superseded_by …"},"403":{"description":"err auth not the author"},"404":{"description":"err notfound"}}}}
}}`)

// RegisterEdit mounts PATCH/DELETE /v1/kb/{id} next to Register's routes, installs the read
// telemetry hook (TelemetryFn = Bump) and the janitor tasks that flush kb_reads_daily every tick
// (30 s) and refresh the stale flag hourly (6.4).
func RegisterEdit(mux *http.ServeMux, d *core.Deps) {
	h := &editHandlers{d}
	mux.HandleFunc("PATCH /v1/kb/{id}", h.edit)
	mux.HandleFunc("DELETE /v1/kb/{id}", h.retract)
	d.RegisterScope("PATCH /v1/kb/{id}", "kb:w")
	d.RegisterScope("DELETE /v1/kb/{id}", "kb:w")
	d.RegisterOpenAPI(editOpenAPI)
	TelemetryFn = Bump
	d.Janitor.Add("kb_reads", func(ctx context.Context) error {
		_, err := FlushTelemetry(ctx, d.DB)
		return err
	})
	d.Janitor.Add("kb_stale", func(ctx context.Context) error {
		if !staleDue() {
			return nil
		}
		_, err := MarkStale(ctx, d.DB)
		return err
	})
}

type editHandlers struct{ d *core.Deps }

func (h *editHandlers) edit(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in EditInput
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	res, err := Edit(r.Context(), h.d, id, r.PathValue("id"), in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if doc.Negotiate(r) == doc.JSON {
		core.JSON(w, 200, res.json())
		return
	}
	ack(w, r, 200, res.Line(), res.Next()...)
}

func (h *editHandlers) retract(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		SupersededBy string `json:"superseded_by"`
	}
	if err := core.Decode(w, r, retractBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := Retract(r.Context(), h.d, id, r.PathValue("id"), in.SupersededBy); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if doc.Negotiate(r) == doc.JSON {
		m := map[string]any{"ok": true, "retracted": true, "next": actionStrings(retractNext(in.SupersededBy))}
		if in.SupersededBy != "" {
			m["superseded_by"] = in.SupersededBy
		}
		core.JSON(w, 200, m)
		return
	}
	ack(w, r, 200, retractLine(in.SupersededBy), retractNext(in.SupersededBy)...)
}

// EditOps returns the MCP operations of this file: ke (edit), kd (retract).
func EditOps(d *core.Deps) map[string]Op {
	arg := func(a json.RawMessage, v any) error {
		if len(a) == 0 {
			return nil
		}
		if err := json.Unmarshal(a, v); err != nil {
			return core.Bad("a: " + err.Error())
		}
		return nil
	}
	return map[string]Op{
		"ke": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := writeOK(d, id); err != nil {
				return "", err
			}
			var in struct {
				ID string `json:"id"`
				EditInput
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			res, err := Edit(ctx, d, id, in.ID, in.EditInput)
			if err != nil {
				return "", err
			}
			return res.Line(), nil
		},
		"kd": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := writeOK(d, id); err != nil {
				return "", err
			}
			var in struct {
				ID           string `json:"id"`
				SupersededBy string `json:"superseded_by"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if err := Retract(ctx, d, id, in.ID, in.SupersededBy); err != nil {
				return "", err
			}
			return retractLine(in.SupersededBy), nil
		},
	}
}
