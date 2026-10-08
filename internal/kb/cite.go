package kb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// cite.go (SPEC-v2 27.1 citation plumbing): pinned, immutable renditions of a revision rendered
// from kb_revisions.snapshot (0052), the cite-as / latest-version / predecessor-version link set,
// the cite: line with the body sha256, and the .jsonld @graph twin. Revisions carry noindex, a
// canonical link to the live entry and a Memento-Datetime; hidden or retracted ids answer 410
// (jsonld: tombstone metadata only).

// RegisterCite mounts GET /kb/{id}/r{n} and GET /k/{id}/r{n} (suffix .md|.txt|.json|.jsonld via
// SplitSuffix on the last segment) and installs PageLinks as the entry-page link contributor.
func RegisterCite(mux *http.ServeMux, d *core.Deps) {
	h := &handlers{d}
	mux.HandleFunc("GET /kb/{id}/{rev}", h.rendition)
	mux.HandleFunc("GET /k/{id}/{rev}", h.rendition)
	if PageLinksFn == nil {
		PageLinksFn = PageLinks
	}
	d.RegisterOpenAPI(citeOpenAPI)
}

// CiteLine is the `cite:` line of p/ok/g replies and the Markdown footer (27.1): with a revision it
// pins `/r<n>` and the 12-hex sha256 of the Markdown body, otherwise the bare permalink.
func CiteLine(id string, n int, mdSha string) string {
	if n > 0 && mdSha != "" {
		return "cite: " + Permalink(id) + "/r" + strconv.Itoa(n) + " sha256=" + mdSha
	}
	return "cite: " + Permalink(id)
}

// PageLinks implements PageLinksFn: the cite-as, latest-version, predecessor-version and the
// alternate application/ld+json links for the live entry at its current revision. Unknown ids
// contribute nothing.
func PageLinks(ctx context.Context, q core.Q, id string) []doc.Link {
	if !core.ValidIDPrefix(id, 'k') {
		return nil
	}
	var rev int
	if err := q.QueryRow(ctx, `SELECT rev FROM kb WHERE id = $1`, id).Scan(&rev); err != nil {
		return nil
	}
	return citeLinks(id, rev, rev)
}

// citeLinks builds the revision link set for revision n of an entry whose latest revision is latest
// (cite-as always points at the stable permalink; predecessor-version only exists for n > 1).
func citeLinks(id string, n, latest int) []doc.Link {
	ls := []doc.Link{
		{Rel: "cite-as", Href: "/k/" + id},
		{Rel: "latest-version", Href: "/kb/" + id + "/r" + strconv.Itoa(max(latest, 1))},
		{Rel: "alternate", Type: "application/ld+json", Href: "/kb/" + id + ".jsonld"},
	}
	if n > 1 {
		ls = append(ls, doc.Link{Rel: "predecessor-version", Href: "/kb/" + id + "/r" + strconv.Itoa(n-1)})
	}
	return ls
}

// JSONLDOnly is the @graph-only JSON-LD of an entry (application/ld+json), exported for P31's
// `.jsonld` suffix handling and reused by the revision renditions.
func JSONLDOnly(e *Entry) any {
	return ldGraph(e, doc.CurrentSite().License)
}

// rendition serves GET /kb/{id}/r{n} (and /k/…): an immutable rendition of revision n from the
// snapshot. noindex, canonical to the live entry, Memento-Datetime, the cite link set and a
// Content-Digest on the .md/.txt/.jsonld twins.
func (h *handlers) rendition(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	revSeg, f := doc.SplitSuffix(r.PathValue("rev"))
	if f == "" {
		f = doc.HTML
	}
	n, ok := parseRev(revSeg)
	if !ok || !core.ValidIDPrefix(id, 'k') {
		doc.Fail(w, r, core.ErrNotFound)
		return
	}
	ctx := r.Context()
	// Visibility of the live object governs: hidden/retracted/merged -> 410 (jsonld: tombstone).
	cur, err := GetV2(ctx, h.d.DB, id, GetOpts{})
	if err != nil || cur.SupersededBy != "" {
		h.goneRevision(w, r, id, f)
		return
	}
	var e *Entry
	var mod time.Time
	if n == cur.Rev {
		// the current revision renders from the live row (P11c keeps no snapshot of it).
		e, mod = cur, modifiedAt(cur)
	} else {
		var found bool
		e, mod, found, err = loadSnapshot(ctx, h.d.DB, id, n)
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		if !found {
			doc.Fail(w, r, core.E(404, "notfound", "no revision r"+strconv.Itoa(n)+" retained (latest r"+strconv.Itoa(max(cur.Rev, 1))+")"))
			return
		}
	}
	links := citeLinks(id, n, cur.Rev)
	w.Header().Set("Memento-Datetime", mod.UTC().Format(http.TimeFormat))
	w.Header().Add("Link", `<`+doc.Base()+"/kb/"+id+`>; rel="canonical"`)
	if lh := doc.LinkHeader(links, true); lh != "" {
		w.Header().Add("Link", lh)
	}
	w.Header().Set("X-Robots-Tag", "noindex")
	w.Header().Set("X-Rev", strconv.Itoa(n))
	switch f {
	case doc.MD:
		body := e.Markdown()
		out := []byte(body + "\n" + CiteLine(id, n, shortSHA(body)) + "\n")
		w.Header().Set("Content-Digest", contentDigest(out))
		doc.ServeStatic(w, r, mod, out, "text/markdown; charset=utf-8")
	case doc.JSON:
		doc.ServeStatic(w, r, mod, mustJSON(e), "application/json")
	case doc.JSONLD:
		out := mustJSON(JSONLDOnly(e))
		w.Header().Set("Content-Digest", contentDigest(out))
		doc.ServeStatic(w, r, mod, out, "application/ld+json")
	case doc.HTML:
		h.renditionHTML(w, r, e, n, links, mod)
	default: // txt, sh
		out := []byte(e.Text() + "\n")
		w.Header().Set("Content-Digest", contentDigest(out))
		doc.ServeStatic(w, r, mod, out, "text/plain; charset=utf-8")
	}
}

// renditionHTML renders the pinned revision as a noindex page whose canonical is the live entry.
func (h *handlers) renditionHTML(w http.ResponseWriter, r *http.Request, e *Entry, n int, links []doc.Link, mod time.Time) {
	var b bytes.Buffer
	b.WriteString(`<p class="rev-banner">revision r`)
	b.WriteString(strconv.Itoa(n))
	b.WriteString(` of <a href="/kb/` + template.HTMLEscapeString(e.ID) + `">` + template.HTMLEscapeString(e.ID) + `</a> · pinned, immutable</p>`)
	b.WriteString("<pre>")
	b.WriteString(template.HTMLEscapeString(e.Markdown()))
	b.WriteString("</pre>")
	w.Header().Set("Last-Modified", mod.UTC().Format(http.TimeFormat))
	doc.Layout(w, r, 200, doc.Page{
		Title:     pageTitle(e.Title) + " · r" + strconv.Itoa(n),
		Desc:      description(e),
		Canonical: "/kb/" + e.ID,
		NoIndex:   true,
		Links:     links,
		Body:      template.HTML(b.String()),
	})
}

// goneRevision answers a revision read of a removed id: 410 with tombstone metadata only for
// .jsonld (no content), the shared gone handler otherwise (410 tombstone / 404 appeal window).
func (h *handlers) goneRevision(w http.ResponseWriter, r *http.Request, id string, f doc.Format) {
	if f != doc.JSONLD {
		h.gone(w, r, id, f)
		return
	}
	t, ok := Gone(r.Context(), h.d.DB, id)
	status := 410
	meta := map[string]any{
		"@context":           "https://schema.org",
		"@type":              "CreativeWork",
		"@id":                Permalink(id),
		"creativeWorkStatus": "removed",
	}
	if ok {
		meta["name"] = t.Title
		meta["dateModified"] = t.At.UTC().Format(time.RFC3339)
		meta["disambiguatingDescription"] = t.Reason
	} else {
		status = 404
		meta["creativeWorkStatus"] = "notPublished"
	}
	out := mustJSON(meta)
	hd := w.Header()
	hd.Set("Content-Type", "application/ld+json")
	hd.Set("X-Robots-Tag", "noindex")
	hd.Set("Cache-Control", "public, max-age=60")
	w.WriteHeader(status)
	w.Write(out)
}

// parseRev parses the r<n> segment (n >= 1).
func parseRev(seg string) (int, bool) {
	if !strings.HasPrefix(seg, "r") {
		return 0, false
	}
	n, err := strconv.Atoi(seg[1:])
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

// loadSnapshot reads kb_revisions.snapshot for (id, n) and reconstructs the entry as it stood at
// that revision. found is false when no snapshot row exists (or the row predates the trigger).
func loadSnapshot(ctx context.Context, q core.Q, id string, n int) (*Entry, time.Time, bool, error) {
	var raw []byte
	err := q.QueryRow(ctx, `SELECT snapshot FROM kb_revisions WHERE kb_id = $1 AND n = $2`, id, n).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, time.Time{}, false, nil
		}
		return nil, time.Time{}, false, err
	}
	if len(raw) == 0 {
		return nil, time.Time{}, false, nil
	}
	var s snapRow
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, time.Time{}, false, err
	}
	e := s.entry()
	return e, modifiedAt(e), true, nil
}

// RevisionContent returns the diffable content text of revision rev of entry id (rev <= 0 means the
// current revision), for internal/delta. resolved is the revision actually read; found is false
// when the id is unknown or that revision has no snapshot. Visibility is the caller's to enforce
// before calling.
func RevisionContent(ctx context.Context, q core.Q, id string, rev int) (text string, resolved int, found bool, err error) {
	if !core.ValidIDPrefix(id, 'k') {
		return "", 0, false, nil
	}
	cur := 0
	if e := q.QueryRow(ctx, `SELECT rev FROM kb WHERE id = $1`, id).Scan(&cur); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return "", 0, false, nil
		}
		return "", 0, false, e
	}
	if rev <= 0 {
		rev = cur
	}
	if rev == cur {
		// the current revision renders from the live row; no snapshot is kept for it.
		e, err := GetV2(ctx, q, id, GetOpts{})
		if err != nil {
			if errors.Is(err, core.ErrNotFound) {
				return "", rev, false, nil
			}
			return "", rev, false, err
		}
		return revContentText(e), rev, true, nil
	}
	e, _, ok, err := loadSnapshot(ctx, q, id, rev)
	if err != nil || !ok {
		return "", rev, false, err
	}
	return revContentText(e), rev, true, nil
}

// revContentText is the stable, content-only rendering a revision diff compares: the authored
// fields without the volatile header line (weights, age, rev), each multi-line field indented so no
// value can start a diff line at column zero.
func revContentText(e *Entry) string {
	var b strings.Builder
	b.WriteString("title: " + doc.SafeLine(e.Title) + "\n")
	field := func(name, v string) {
		if strings.TrimSpace(v) != "" {
			b.WriteString(name + ":\n  " + doc.Indent(v) + "\n")
		}
	}
	field("symptom", e.Symptom)
	field("cause", e.Cause)
	field("fix", e.Fix)
	if e.Versions != "" {
		b.WriteString("versions: " + doc.SafeLine(e.Versions) + "\n")
	}
	if len(e.Applies) > 0 {
		b.WriteString("applies: " + doc.SafeLine(e.Applies.String()) + "\n")
	}
	if len(e.Tags) > 0 {
		b.WriteString("tags: " + doc.SafeLine(strings.Join(e.Tags, ",")) + "\n")
	}
	field("why-safe", e.WhySafe)
	return b.String()
}

// snapRow is the subset of the kb row (by database column name) that a rendition needs. Derived
// fields absent from the snapshot (vote summaries, author standing) render at their zero value: the
// snapshot is a faithful point-in-time copy of the stored content, not a replay of live counters.
type snapRow struct {
	ID                 string     `json:"id"`
	Kind               string     `json:"kind"`
	Title              string     `json:"title"`
	Symptom            string     `json:"symptom"`
	Cause              string     `json:"cause"`
	Fix                string     `json:"fix"`
	Versions           string     `json:"versions"`
	Tags               []string   `json:"tags"`
	Author             string     `json:"author"`
	OkW                float32    `json:"ok_w"`
	BadW               float32    `json:"bad_w"`
	Created            time.Time  `json:"created"`
	ConfirmedAt        *time.Time `json:"confirmed_at"`
	ExpiresAt          time.Time  `json:"expires_at"`
	Hidden             bool       `json:"hidden"`
	Quarantine         bool       `json:"quarantine"`
	Hazard             []string   `json:"hazard"`
	Flags              []string   `json:"flags"`
	Rev                int        `json:"rev"`
	EditedBy           string     `json:"edited_by"`
	EditedAfterConfirm bool       `json:"edited_after_confirm"`
	SupersededBy       string     `json:"superseded_by"`
	Applies            Applies    `json:"applies"`
	Space              string     `json:"space"`
	Seed               bool       `json:"seed"`
	Att                string     `json:"att"`
	License            string     `json:"license"`
	WhySafe            string     `json:"why_safe"`
	Stale              bool       `json:"stale"`
}

func (s *snapRow) entry() *Entry {
	return &Entry{
		ID: s.ID, Kind: s.Kind, Title: s.Title, Symptom: s.Symptom, Cause: s.Cause, Fix: s.Fix,
		Versions: s.Versions, Tags: s.Tags, Author: s.Author, OkW: s.OkW, BadW: s.BadW,
		Created: s.Created, ConfirmedAt: s.ConfirmedAt, ExpiresAt: s.ExpiresAt, Hidden: s.Hidden,
		Quarantine: s.Quarantine, Hazard: s.Hazard, Flags: s.Flags, Rev: s.Rev, EditedBy: s.EditedBy,
		EditedAfterConfirm: s.EditedAfterConfirm, SupersededBy: s.SupersededBy, Applies: s.Applies,
		Space: s.Space, Seed: s.Seed, Att: s.Att, License: s.License, WhySafe: s.WhySafe, Stale: s.Stale,
	}
}

func mustJSON(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return b.Bytes()
}

var citeOpenAPI = json.RawMessage(`{"/kb/{id}/r{n}":{"get":{"operationId":"kbrev","summary":"Pinned immutable rendition of revision n (.md|.txt|.json|.jsonld); noindex, canonical to /kb/{id}, Memento-Datetime, Content-Digest and the cite-as/latest-version/predecessor-version links","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},{"name":"n","in":"path","required":true,"schema":{"type":"integer","minimum":1}}],"responses":{"200":{"description":"the rendition"},"404":{"description":"unknown id or revision"},"410":{"description":"hidden or retracted"}}}}`)
