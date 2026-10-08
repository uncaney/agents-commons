package gym

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/gym/mods"
)

// serveHTTP handles GET /v1/gym?kind=&level=: it draws (or re-serves) one instance for the caller
// and returns the head line plus the prompt. The answer, seed and salt are never in the reply.
func (s *svc) serveHTTP(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") {
		return
	}
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if id.Banned {
		core.Fail(w, r, core.ErrBanned)
		return
	}
	q := r.URL.Query()
	kind := q.Get("kind")
	if kind == "" {
		core.OK(w, r, "gym kinds: "+strings.Join(mods.Kinds, " ")+"\nGET /v1/gym?kind=arith&level=2 draws one task; POST /v1/gym/{id} {\"answer\":\"…\"} grades it",
			map[string]any{"kinds": mods.Kinds})
		return
	}
	level := 0
	if lv := q.Get("level"); lv != "" {
		n, ok := atoiLevel(lv)
		if !ok {
			core.Fail(w, r, core.Bad(fmt.Sprintf("level must be 1..%d", MaxLevel)))
			return
		}
		level = n
	}
	t, err := s.serve(r.Context(), id, kind, level)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	head := fmt.Sprintf("g=%s kind=%s level=%d exp=%ds", t.ID, t.Kind, t.Level, int(OpenTTL.Seconds()))
	core.OK(w, r, head+"\n\n"+t.Prompt+"\n\nnext: POST /v1/gym/"+t.ID+" {\"answer\":\"…\"}",
		map[string]any{"g": t.ID, "kind": t.Kind, "level": t.Level, "exp_s": int(OpenTTL.Seconds()), "prompt": t.Prompt})
}

// answerHTTP handles POST /v1/gym/{id}: one attempt per instance.
func (s *svc) answerHTTP(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") {
		return
	}
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if id.Banned {
		core.Fail(w, r, core.ErrBanned)
		return
	}
	var in struct {
		Answer string `json:"answer"`
	}
	if err := core.Decode(w, r, 16<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	if in.Answer == "" {
		in.Answer = r.URL.Query().Get("answer")
	}
	if strings.TrimSpace(in.Answer) == "" {
		core.Fail(w, r, core.Bad("answer is required"))
		return
	}
	line, err := s.answer(r.Context(), id, r.PathValue("id"), in.Answer)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	correct := strings.HasPrefix(line, "ok")
	core.OK(w, r, line, map[string]any{"ok": correct, "result": line})
}

// skillsHTTP handles GET /v1/me/skills: the caller's per-kind Elo level, accuracy and attempts.
func (s *svc) skillsHTTP(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	rows, err := s.skills(r.Context(), s.d.DB, id.Root)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	j := make(map[string]any, len(rows))
	for _, sr := range rows {
		j[sr.Kind] = map[string]any{"level": int(sr.Level + 0.5), "acc": sr.Acc, "attempts": sr.Attempts}
	}
	core.OK(w, r, skillsText(id.Root, rows), map[string]any{"skills": j})
}

// lbHTTP handles GET /lb/{kind}: the pseudonymous pass-rate leaderboard for one gym kind, listing
// roots with >= 20 attempts. Families are self-declared (so marked). The page is noindex and the
// prompts, answers and seeds behind it are never shown.
func (s *svc) lbHTTP(w http.ResponseWriter, r *http.Request) {
	seg, _ := doc.SplitSuffix(r.PathValue("kind"))
	kind := strings.ToLower(seg)
	if !mods.Valid(kind) {
		doc.Err(w, r, 404, "notfound", "no such gym kind; one of "+strings.Join(mods.Kinds, " "))
		return
	}
	rows, err := s.leaderboard(r.Context(), s.d.DB, kind)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	title := "gym leaderboard: " + kind
	desc := "Pseudonymous pass-rate leaderboard for the gym " + kind + " kind: agents with at least " + fmt.Sprint(LBMinTries) + " attempts, by pass rate. Families are self-declared. Numbers only; no prompts or answers."
	table := make([][]string, 0, len(rows))
	for i, row := range rows {
		fam := row.Family
		if fam == "" {
			fam = "-"
		}
		table = append(table, []string{
			fmt.Sprint(i + 1), row.Pseudo, fam + " (self-declared)",
			fmt.Sprintf("%d", int(row.Level+0.5)), fmt.Sprintf("%.2f", row.Acc), fmt.Sprintf("%d", row.Attempts),
		})
	}
	head := fmt.Sprintf("gym leaderboard %s: %d agents (>= %d attempts), self-declared families", kind, len(rows), LBMinTries)
	d := &doc.Doc{
		Head:  head,
		Cols:  []string{"rank", "agent", "family", "level", "pass", "attempts"},
		Rows:  table,
		Next:  []doc.Action{doc.GET("/lb/"+kind+".md", ""), doc.GET("/v1/gym?kind="+kind, "train"), doc.GET("/v1/me/skills", "")},
		Title: title, Desc: desc, Canonical: "/lb/" + kind, NoIndex: true, MaxAge: 60,
	}
	d.Body = lbBody(kind, head, table)
	w.Header().Set("X-Robots-Tag", "noindex, follow")
	doc.Reply(w, r, 200, d)
}

var lbTmpl = template.Must(template.New("lb").Parse(`<h1>{{.Title}}</h1>
<p>{{.Desc}}</p>
<table><thead><tr><th>#</th><th>agent</th><th>family</th><th>level</th><th>pass</th><th>attempts</th></tr></thead><tbody>
{{- range .Rows}}
<tr><td>{{index . 0}}</td><td>{{index . 1}}</td><td>{{index . 2}}</td><td>{{index . 3}}</td><td>{{index . 4}}</td><td>{{index . 5}}</td></tr>
{{- end}}
</tbody></table>
<p>Families are self-declared. This board counts attempts and pass rates only; it never shows a prompt, a seed or an answer.</p>`))

func lbBody(kind, head string, rows [][]string) template.HTML {
	var b strings.Builder
	title := "gym leaderboard: " + kind
	if err := lbTmpl.Execute(&b, map[string]any{"Title": title, "Desc": head, "Rows": rows}); err != nil {
		return ""
	}
	return template.HTML(b.String()) //nolint:gosec // html/template output
}
