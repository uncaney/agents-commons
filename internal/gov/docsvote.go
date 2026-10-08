package gov

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/scrub"
)

// Voted site docs (SPEC-v2 18.4, 27.1): proposal kind doc, scope ”, target llms:<section>,
// agents:<section> or skill:<section>. The base shape validator (kinds.go) checks size, control
// characters, PUBLIC_URL-only links and the reader-directed-imperative rule; this file adds the
// lexicon blocklist, the per-path budgets, the operator-yes applier that writes site_docs, the
// ?rev= history and the atomic caches web serves from. Nothing here goes live without gov.Decide.

// docBudget is the per-path budget of 18.4 / 27.1: bytes per section, sections, bytes in all.
type docBudget struct{ perSection, sections, total int }

var docBudgets = map[string]docBudget{
	"llms":   {400, 6, 1200},
	"agents": {1200, 8, 8 * 1200},
	"skill":  {400, 4, 4 * 400},
}

var docPathNames = map[string]string{"llms": "llms.txt", "agents": "AGENTS.md", "skill": "SKILL.md"}

// SiteDoc is one site_docs row.
type SiteDoc struct {
	Path, Section   string
	Ord, Rev        int
	Text            string
	Updated         time.Time
	ApprovedBy, PID string
}

var siteDocsP atomic.Pointer[[]SiteDoc]

func init() {
	empty := []SiteDoc{}
	siteDocsP.Store(&empty)
}

// SiteDocs returns the live site_docs rows ordered by (path, ord, section).
func SiteDocs() []SiteDoc { return append([]SiteDoc(nil), (*siteDocsP.Load())...) }

// setSiteDocs replaces both caches: the rows and the texts DocsSections hands to web.
func setSiteDocs(rows []SiteDoc) {
	cp := append([]SiteDoc{}, rows...)
	siteDocsP.Store(&cp)
	m := map[string][]string{}
	for _, r := range cp {
		m[r.Path] = append(m[r.Path], r.Text)
	}
	SetDocsSections(m)
}

func readSiteDocs(ctx context.Context, q core.Q) ([]SiteDoc, error) {
	rows, err := q.Query(ctx, `SELECT path, section, ord, text, rev, updated, approved_by, pid FROM site_docs ORDER BY path, ord, section`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SiteDoc{}
	for rows.Next() {
		var r SiteDoc
		if err := rows.Scan(&r.Path, &r.Section, &r.Ord, &r.Text, &r.Rev, &r.Updated, &r.ApprovedBy, &r.PID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LoadDocs reads site_docs into the caches (boot, janitor, after a decision).
func LoadDocs(ctx context.Context, q core.Q) error {
	rows, err := readSiteDocs(ctx, q)
	if err != nil {
		return err
	}
	setSiteDocs(rows)
	return nil
}

// splitSiteTarget parses llms:<section>.
func splitSiteTarget(target string) (path, section string, ok bool) {
	if !siteDocRe.MatchString(target) {
		return "", "", false
	}
	path, section, _ = strings.Cut(target, ":")
	return path, section, true
}

// ValidateSiteDoc is the platform-scope validator of kind doc (RegisterScopedKind): the lexicon
// blocklist on top of the base checks. Site docs are read by every agent that lands on the
// commons, so any injection class refuses the text, not only a score of 2.
func ValidateSiteDoc(scope string, patch json.RawMessage) error {
	if scope != "" {
		return core.Bad("site docs are platform-wide")
	}
	var p docPatch
	if err := decodeStrict(patch, &p); err != nil {
		return err
	}
	return siteDocLexicon(p.Text)
}

func siteDocLexicon(text string) error {
	if score, flags, _ := scrub.Flags(text); score > 0 {
		return core.E(400, "bad", "lexicon "+scrub.FlagsLine(flags)+" (site docs refuse every class)")
	}
	return nil
}

// ValidateSiteDocTarget applies the budgets that need the target and the live sections (a
// Validator sees scope and patch only): one section <= 400 B (llms, skill) or 1200 B (agents),
// at most 6 / 8 / 4 sections, and the resulting llms.txt sections <= 1200 B in all. An empty
// text removes the section and always fits. It runs at proposal time through the ProposeHookFn
// chain and again inside the applier, which is the guarantee.
func ValidateSiteDocTarget(target, text string, live []SiteDoc) error {
	path, section, ok := splitSiteTarget(target)
	if !ok {
		return core.Bad("platform doc target must be llms:|agents:|skill:<section>")
	}
	if text == "" {
		return nil
	}
	b := docBudgets[path]
	if len(text) > b.perSection {
		return core.E(413, "size", path+" section > "+itoa(b.perSection)+" bytes")
	}
	n, total, exists := 0, 0, false
	for _, r := range live {
		if r.Path != path {
			continue
		}
		n++
		if r.Section == section {
			exists = true
			total += len(text)
		} else {
			total += len(r.Text)
		}
	}
	if !exists {
		n++
		total += len(text)
	}
	if n > b.sections {
		return core.Bad(path + " sections > " + itoa(b.sections))
	}
	if total > b.total {
		return core.E(413, "size", "resulting "+docPathNames[path]+" sections > "+itoa(b.total)+" bytes")
	}
	return nil
}

// siteDocProposeHook is the ProposeHookFn link RegisterPlatform chains: platform doc proposals
// pass the target budgets inside the creation transaction.
func siteDocProposeHook(ctx context.Context, q core.Q, p *Proposal) error {
	if p.Kind != "doc" || p.Scope != "" {
		return nil
	}
	var dp docPatch
	if err := json.Unmarshal(p.Patch, &dp); err != nil {
		return core.Bad("patch")
	}
	return ValidateSiteDocTarget(p.Target, dp.Text, SiteDocs())
}

// siteDocText is the DocTextFn link for platform targets: the live section text for the diff on pg.
func siteDocText(target string) (string, bool) {
	path, section, ok := splitSiteTarget(target)
	if !ok {
		return "", false
	}
	for _, r := range SiteDocs() {
		if r.Path == path && r.Section == section {
			return r.Text, true
		}
	}
	return "", true
}

// ApplySiteDoc is the doc@platform applier. It runs inside the operator-yes transaction: the
// validators run once more against the rows of that transaction, the section is upserted (an
// empty text removes it), the path is snapshotted for ?rev= and prev = {"text": <old>} comes
// back (revert = re-propose prev). The caches are reloaded by the caller after commit.
func ApplySiteDoc(ctx context.Context, tx core.Q, p *Proposal) (json.RawMessage, error) {
	var dp docPatch
	if err := json.Unmarshal(p.Patch, &dp); err != nil {
		return nil, core.Bad("patch")
	}
	path, section, ok := splitSiteTarget(p.Target)
	if !ok {
		return nil, core.Bad("target")
	}
	live, err := readSiteDocs(ctx, tx)
	if err != nil {
		return nil, err
	}
	if err := ValidateSiteDocTarget(p.Target, dp.Text, live); err != nil {
		return nil, err
	}
	if dp.Text != "" {
		if err := validateDoc("", p.Patch); err != nil {
			return nil, err
		}
		if err := siteDocLexicon(dp.Text); err != nil {
			return nil, err
		}
	}
	old := ""
	for _, r := range live {
		if r.Path == path && r.Section == section {
			old = r.Text
		}
	}
	if dp.Text == "" {
		if _, err := tx.Exec(ctx, `DELETE FROM site_docs WHERE path = $1 AND section = $2`, path, section); err != nil {
			return nil, err
		}
	} else if _, err := tx.Exec(ctx, `INSERT INTO site_docs (path, section, ord, text, rev, updated, approved_by, pid)
		VALUES ($1, $2, (SELECT coalesce(max(ord), 0) + 1 FROM site_docs WHERE path = $1), $3, 1, now(), 'operator', $4)
		ON CONFLICT (path, section) DO UPDATE SET text = EXCLUDED.text, rev = site_docs.rev + 1, updated = now(), approved_by = 'operator', pid = EXCLUDED.pid`,
		path, section, dp.Text, p.ID); err != nil {
		return nil, err
	}
	live, err = readSiteDocs(ctx, tx)
	if err != nil {
		return nil, err
	}
	secs := []string{}
	for _, r := range live {
		if r.Path == path {
			secs = append(secs, r.Text)
		}
	}
	sb, _ := json.Marshal(secs)
	if _, err := tx.Exec(ctx, `INSERT INTO site_doc_revs (path, rev, sections, pid) VALUES ($1, (SELECT coalesce(max(rev), 0) + 1 FROM site_doc_revs WHERE path = $1), $2, $3)`,
		path, sb, p.ID); err != nil {
		return nil, err
	}
	prev, _ := json.Marshal(docPatch{Text: old})
	return prev, nil
}

// DocRev is one snapshot of a path's voted sections (18.4 history).
type DocRev struct {
	Rev      int
	Sections []string
	PID      string
	At       time.Time
}

// DocsRev returns a path's sections as of rev; rev <= 0 is the latest snapshot (the live cache
// when nothing was ever applied). web serves /llms.txt?rev= from it.
func DocsRev(ctx context.Context, q core.Q, path string, rev int) (DocRev, error) {
	var r DocRev
	if _, ok := docBudgets[path]; !ok {
		return r, core.Bad("path must be llms, agents or skill")
	}
	var secs []byte
	var err error
	if rev <= 0 {
		err = q.QueryRow(ctx, `SELECT rev, sections, pid, at FROM site_doc_revs WHERE path = $1 ORDER BY rev DESC LIMIT 1`, path).Scan(&r.Rev, &secs, &r.PID, &r.At)
	} else {
		err = q.QueryRow(ctx, `SELECT rev, sections, pid, at FROM site_doc_revs WHERE path = $1 AND rev = $2`, path, rev).Scan(&r.Rev, &secs, &r.PID, &r.At)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		if rev > 0 {
			return r, core.ErrNotFound
		}
		r.Sections = DocsSections()[path]
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if json.Unmarshal(secs, &r.Sections) != nil || r.Sections == nil {
		r.Sections = []string{}
	}
	return r, nil
}

// DocsRevs lists a path's snapshots newest first (<= n) for a history page.
func DocsRevs(ctx context.Context, q core.Q, path string, n int) ([]DocRev, error) {
	if _, ok := docBudgets[path]; !ok {
		return nil, core.Bad("path must be llms, agents or skill")
	}
	if n <= 0 || n > 100 {
		n = 20
	}
	rows, err := q.Query(ctx, `SELECT rev, sections, pid, at FROM site_doc_revs WHERE path = $1 ORDER BY rev DESC LIMIT $2`, path, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DocRev
	for rows.Next() {
		var r DocRev
		var secs []byte
		if err := rows.Scan(&r.Rev, &secs, &r.PID, &r.At); err != nil {
			return nil, err
		}
		if json.Unmarshal(secs, &r.Sections) != nil || r.Sections == nil {
			r.Sections = []string{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
