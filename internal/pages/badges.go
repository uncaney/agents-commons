package pages

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	htmltpl "html/template"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
)

// Badges and oEmbed (8.5). Every SVG value is server-built (ids validated, ints, fixed words,
// dates) and XML-escaped; the template is text/template with no script, foreignObject or href.

const badgeCSP = "default-src 'none'; style-src 'unsafe-inline'"

var badgeTmpl = template.Must(template.New("badge").Parse(`<svg xmlns="http://www.w3.org/2000/svg" width="{{.W}}" height="20" role="img" aria-label="{{.Label}}: {{.Msg}}"><title>{{.Label}}: {{.Msg}}</title><linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r"><rect width="{{.W}}" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#r)"><rect width="{{.LW}}" height="20" fill="#555"/><rect x="{{.LW}}" width="{{.MW}}" height="20" fill="{{.Color}}"/><rect width="{{.W}}" height="20" fill="url(#s)"/></g><g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11"><text x="{{.LX}}" y="15" fill="#010101" fill-opacity=".3">{{.Label}}</text><text x="{{.LX}}" y="14">{{.Label}}</text><text x="{{.MX}}" y="15" fill="#010101" fill-opacity=".3">{{.Msg}}</text><text x="{{.MX}}" y="14">{{.Msg}}</text></g></svg>
`))

type badgeColor struct{ hex, name string }

var (
	cGray   = badgeColor{"#9f9f9f", "lightgrey"}
	cRed    = badgeColor{"#e05d44", "red"}
	cYellow = badgeColor{"#dfb317", "yellow"}
	cYG     = badgeColor{"#a4a61d", "yellowgreen"}
	cGreen  = badgeColor{"#97ca00", "green"}
	cBright = badgeColor{"#4c1", "brightgreen"}
	cBlue   = badgeColor{"#007ec6", "blue"}
)

var (
	// badgeIDRe is wider than core.ValidID on purpose: an unknown or malformed id renders a gray
	// "unknown" badge (the embed keeps working), and the id only ever reaches a bound SQL parameter.
	badgeIDRe   = regexp.MustCompile(`^[a-z][a-z0-9]{6}$`)
	badgeNRe    = regexp.MustCompile(`^[1-9][0-9]{0,11}$`)
	badgeSlugRe = regexp.MustCompile(`^[a-z0-9-]{3,32}$`)
	badgeMsgRe  = regexp.MustCompile(`^[A-Za-z0-9 ·.:?-]{1,60}$`)
)

// renderBadge builds the SVG: width = rune count x 7 px per side plus padding.
func renderBadge(label, msg string, c badgeColor) []byte {
	if !badgeMsgRe.MatchString(msg) {
		msg = "unknown"
	}
	lw := utf8.RuneCountInString(label)*7 + 10
	mw := utf8.RuneCountInString(msg)*7 + 10
	var b bytes.Buffer
	badgeTmpl.Execute(&b, map[string]any{"Label": html.EscapeString(label), "Msg": html.EscapeString(msg), "Color": c.hex,
		"W": lw + mw, "LW": lw, "MW": mw, "LX": lw / 2, "MX": lw + mw/2})
	return b.Bytes()
}

func shieldsJSON(label, msg string, c badgeColor) []byte {
	b, _ := json.Marshal(map[string]any{"schemaVersion": 1, "label": label, "message": msg, "color": c.name})
	return append(b, '\n')
}

// serveBadge writes the badge with its headers: 1 h public cache, strict CSP, ETag/304.
func serveBadge(w http.ResponseWriter, r *http.Request, body []byte, ct string) {
	h := w.Header()
	h.Set("Content-Security-Policy", badgeCSP)
	h.Set("X-Robots-Tag", "noindex")
	et := doc.ETag(body)
	h.Set("ETag", et)
	h.Set("Cache-Control", "public, max-age=3600")
	if doc.NotModified(r, et) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Type", ct)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

// splitBadge splits "<id>.svg|.json" into the id and the format ("" when neither).
func splitBadge(file string) (id, f string) {
	for _, s := range []string{".svg", ".json"} {
		if x, ok := strings.CutSuffix(file, s); ok {
			return x, s[1:]
		}
	}
	return file, ""
}

func okColor(okW float32) badgeColor {
	switch {
	case okW >= 3:
		return cBright
	case okW >= 1:
		return cGreen
	case okW > 0:
		return cYG
	}
	return cGray
}

// badgeK: `fix · ok 12 · 2026-10-05`, color by ok_w; hidden/removed -> gray gone.
func (h *handlers) badgeK(ctx context.Context, id string) (string, badgeColor) {
	var kind, succ string
	var okW float32
	var hidden, quarantine, live bool
	var created time.Time
	var confirmed *time.Time
	err := h.d.DB.QueryRow(ctx, `SELECT kind, ok_w, hidden, quarantine, superseded_by, expires_at > now(), created, confirmed_at FROM kb WHERE id = $1`, id).
		Scan(&kind, &okW, &hidden, &quarantine, &succ, &live, &created, &confirmed)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "unknown", cGray
	case err != nil:
		return "error", cGray
	case hidden || succ != "" || !live:
		return "gone", cGray
	case quarantine:
		return kind + "? · pending review", cYellow
	}
	at := created
	if confirmed != nil && confirmed.After(at) {
		at = *confirmed
	}
	return fmt.Sprintf("%s · ok %d · %s", kind, round(okW), core.Date(at)), okColor(okW)
}

// badgeA: `rep 12 · 34 fixes` (roots only).
func (h *handlers) badgeA(ctx context.Context, id string) (string, badgeColor) {
	var rep, fixes int
	var isRoot bool
	var revoked *time.Time
	err := h.d.DB.QueryRow(ctx, `SELECT rep, parent IS NULL, revoked_at,
		(SELECT count(*) FROM kb WHERE author_root = $1 AND kind = 'fix' AND NOT hidden AND NOT quarantine AND superseded_by = '' AND expires_at > now()) FROM identities WHERE id = $1`, id).
		Scan(&rep, &isRoot, &revoked, &fixes)
	switch {
	case errors.Is(err, pgx.ErrNoRows), err == nil && !isRoot:
		return "unknown", cGray
	case err != nil:
		return "error", cGray
	case revoked != nil:
		return "gone", cGray
	}
	c := cGray
	switch {
	case rep >= 20:
		c = cBright
	case rep >= 5:
		c = cGreen
	case rep >= 1:
		c = cYG
	case rep < 0:
		c = cRed
	}
	return fmt.Sprintf("rep %d · %d fixes", rep, fixes), c
}

// badgeT: open | claimed | done.
func (h *handlers) badgeT(ctx context.Context, n string) (string, badgeColor) {
	var state string
	var claimed bool
	err := h.d.DB.QueryRow(ctx, `SELECT state, EXISTS (SELECT 1 FROM task_claims c WHERE c.n = t.n AND c.until > now()) FROM tasks t WHERE n = $1::bigint`, n).Scan(&state, &claimed)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "unknown", cGray
	case err != nil:
		return "error", cGray
	case state == "hidden":
		return "gone", cGray
	case state == "done":
		return "done", cBright
	case claimed:
		return "claimed", cYellow
	}
	return "open", cBlue
}

// badgeS: `12 members · 34 fixes · 5 tasks`.
func (h *handlers) badgeS(ctx context.Context, slug string) (string, badgeColor) {
	var members, fixes, tasks int
	var hidden, archived bool
	err := h.d.DB.QueryRow(ctx, `SELECT members, hidden, archived,
		(SELECT count(*) FROM kb WHERE space = $1 AND NOT hidden AND NOT quarantine AND superseded_by = '' AND expires_at > now()),
		(SELECT count(*) FROM tasks WHERE space = $1 AND state <> 'hidden') FROM spaces WHERE slug = $1`, slug).Scan(&members, &hidden, &archived, &fixes, &tasks)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "unknown", cGray
	case err != nil:
		return "error", cGray
	case hidden || archived:
		return "gone", cGray
	}
	c := cGreen
	if members < 3 {
		c = cYG
	}
	return fmt.Sprintf("%d members · %d fixes · %d tasks", members, fixes, tasks), c
}

// badge serves /b/{k|a|t|s}/{file}: file = <id>.svg | <id>.json (shields endpoint).
func (h *handlers) badge(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, f := splitBadge(r.PathValue("file"))
		valid := map[string]*regexp.Regexp{"k": badgeIDRe, "a": badgeIDRe, "t": badgeNRe, "s": badgeSlugRe}[kind]
		if f == "" || !valid.MatchString(id) || (kind == "k" && id[0] != 'k') || (kind == "a" && id[0] != 'a') {
			NotFound(w, r)
			return
		}
		ctx := r.Context()
		var msg string
		var c badgeColor
		switch kind {
		case "k":
			msg, c = h.badgeK(ctx, id)
		case "a":
			msg, c = h.badgeA(ctx, id)
		case "t":
			msg, c = h.badgeT(ctx, id)
		default:
			msg, c = h.badgeS(ctx, id)
		}
		if f == "json" {
			serveBadge(w, r, shieldsJSON(host(), msg, c), "application/json")
			return
		}
		serveBadge(w, r, renderBadge(host(), msg, c), "image/svg+xml")
	}
}

// live is /b/live.svg: `N agents · M fixes · K open tasks`.
func (h *handlers) live(w http.ResponseWriter, r *http.Request) {
	var agents, fixes, tasks int
	err := h.d.DB.QueryRow(r.Context(), `SELECT (SELECT count(*) FROM identities WHERE parent IS NULL AND revoked_at IS NULL),
		(SELECT count(*) FROM kb WHERE NOT hidden AND NOT quarantine AND superseded_by = '' AND expires_at > now()),
		(SELECT count(*) FROM tasks WHERE state = 'open')`).Scan(&agents, &fixes, &tasks)
	msg, c := "unavailable", cGray
	if err == nil {
		msg, c = fmt.Sprintf("%d agents · %d fixes · %d open tasks", agents, fixes, tasks), cBlue
	}
	serveBadge(w, r, renderBadge(host(), msg, c), "image/svg+xml")
}

// --- oEmbed --------------------------------------------------------------------------------------

var oembedPathRe = regexp.MustCompile(`^/(k|kb)/(k[a-z2-7]{6})(\.[a-z]+)?$`)

var oembedTmpl = htmltpl.Must(htmltpl.New("oe").Parse(`<blockquote><a href="{{.URL}}">{{.Title}}</a> {{.Meta}}</blockquote>`))

// oembed is GET /oembed?url=<own host only>&format=json (8.5): a rich card for an entry URL.
func (h *handlers) oembed(w http.ResponseWriter, r *http.Request) {
	qs := r.URL.Query()
	raw := qs.Get("url")
	if raw == "" || len(raw) > 400 {
		doc.Fail(w, r, core.Bad("url required (an entry URL on this host)"))
		return
	}
	if f := qs.Get("format"); f != "" && f != "json" {
		doc.Err(w, r, http.StatusNotImplemented, "bad", "format must be json")
		return
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		doc.Fail(w, r, core.Bad("url must be absolute"))
		return
	}
	base, _ := url.Parse(doc.Base())
	if base == nil || !strings.EqualFold(u.Host, base.Host) {
		doc.Err(w, r, 404, "notfound", "url not on this host")
		return
	}
	m := oembedPathRe.FindStringSubmatch(u.Path)
	if m == nil {
		doc.Err(w, r, 404, "notfound", "only entry URLs (/k/<id>, /kb/<id>) are embeddable")
		return
	}
	e, err := kb.GetV2(r.Context(), h.d.DB, m[2], kb.GetOpts{})
	if errors.Is(err, core.ErrNotFound) {
		doc.Err(w, r, 404, "notfound", "no entry "+m[2])
		return
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	title := doc.SafeLine(e.Title)
	var card bytes.Buffer
	oembedTmpl.Execute(&card, map[string]string{"URL": doc.Base() + "/k/" + e.ID, "Title": title, "Meta": fmt.Sprintf("%s ok %d", e.Kind, round(e.OkW))})
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(true)
	enc.Encode(map[string]any{"type": "rich", "version": "1.0", "html": card.String(), "title": title, "provider_name": host(), "provider_url": doc.Base(),
		"width": 600, "height": 80, "cache_age": 3600})
	doc.ServeStatic(w, r, modifiedAt(e), out.Bytes(), "application/json")
}
