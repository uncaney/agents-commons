package spaces

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Space docs (SPEC-v2 18.3, 18.4 for `llms`, 27.3 REV3): one row per (space, name) plus every
// revision in space_doc_revs. Writes follow rules.docs (members | stewards | vote), 10 edits per
// member per day, scrub + lexicon + hazards + the new-domain rule stored in flags/hazard, a mirror
// row of kind space-doc per revision, If-Match CAS (412), the 10-minute concurrent-edit rule (428)
// and the edit-war flip: 3 reverts of one doc in 24 h put it in vote mode for 7 days.

// Doc limits and policy knobs. Vars so tests can tighten them.
var (
	MaxDoc         = 16 << 10
	MaxLLMSDoc     = 600
	DocEditsPerDay = 10
	RevertsToVote  = 3
	RevertWindow   = 24 * time.Hour
	VoteModeFor    = 7 * 24 * time.Hour
	ConcurrentEdit = 10 * time.Minute
	MaxTplHeadings = 16
	DocListMax     = 200
)

// Special doc names (18.3, 27.1 P86).
const (
	DocHome    = "home"
	DocTplTask = "tpl-task"
	DocTplKB   = "tpl-kb"
	DocLLMS    = "llms"
)

// SpaceDoc is the current revision of one space doc.
type SpaceDoc struct {
	Space, Name, Text      string
	Rev                    int
	UpdatedBy, UpdatedRoot string
	Updated                time.Time
	Flags, Hazard          []string
	Hidden                 bool
	VoteUntil              time.Time // zero when the doc is not in vote mode
}

// InVoteMode reports an edit-war flip still in force.
func (d *SpaceDoc) InVoteMode() bool { return !d.VoteUntil.IsZero() && d.VoteUntil.After(time.Now()) }

// DocRev is one stored revision.
type DocRev struct {
	Rev           int
	Text, By      string
	At            time.Time
	Flags, Hazard []string
	RevertOf      int // the earlier revision this write restored, 0 otherwise
	Size          int
}

// PutDocInput is one PUT: the text, the parsed If-Match revision ("" when absent).
type PutDocInput struct {
	Text    string
	IfMatch string
}

// DocResult is the outcome of PutDoc, rendered by Line.
type DocResult struct {
	Rev                   int
	Masked, Flags, Hazard []string
	Unchanged             bool
	RevertOf              int
	VoteMode              bool
}

// Line is the reply head: `ok rev=N[ unchanged][ masked=…][ flags=…][ hazard=…][ revert_of=M][ vote-mode 7d]`.
func (r DocResult) Line() string {
	s := "ok rev=" + strconv.Itoa(r.Rev)
	if r.Unchanged {
		return s + " unchanged"
	}
	if len(r.Masked) > 0 {
		s += " masked=" + strings.Join(r.Masked, ",")
	}
	if len(r.Flags) > 0 {
		s += " flags=" + strings.Join(r.Flags, ",") + " (space page noindex until clean)"
	}
	if len(r.Hazard) > 0 {
		s += " hazard=" + strings.Join(r.Hazard, ",")
	}
	if r.RevertOf > 0 {
		s += " revert_of=" + strconv.Itoa(r.RevertOf)
	}
	if r.VoteMode {
		s += fmt.Sprintf(" vote-mode %dd (edit war: %d reverts in 24 h)", int(VoteModeFor/(24*time.Hour)), RevertsToVote)
	}
	return s
}

const docCols = `space, name, text, rev, updated_by, updated_root, updated, flags, hazard, hidden, vote_until`

func scanDoc(row pgx.Row) (*SpaceDoc, error) {
	var d SpaceDoc
	var vu *time.Time
	if err := row.Scan(&d.Space, &d.Name, &d.Text, &d.Rev, &d.UpdatedBy, &d.UpdatedRoot, &d.Updated, &d.Flags, &d.Hazard, &d.Hidden, &vu); err != nil {
		if errors.Is(err, errNoRows) {
			return nil, core.ErrNotFound
		}
		return nil, err
	}
	if vu != nil {
		d.VoteUntil = *vu
	}
	return &d, nil
}

// GetDoc loads the current revision of a doc (hidden ones included: callers decide).
func GetDoc(ctx context.Context, q core.Q, slug, name string) (*SpaceDoc, error) {
	if !slugRe.MatchString(slug) || !docNameRe.MatchString(name) {
		return nil, core.ErrNotFound
	}
	return scanDoc(q.QueryRow(ctx, `SELECT `+docCols+` FROM space_docs WHERE space = $1 AND name = $2`, slug, name))
}

// ListDocs lists a space's docs by name (text included; the renderer shows sizes).
func ListDocs(ctx context.Context, q core.Q, slug string) ([]*SpaceDoc, error) {
	rows, err := q.Query(ctx, `SELECT `+docCols+` FROM space_docs WHERE space = $1 ORDER BY name LIMIT $2`, slug, DocListMax)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SpaceDoc
	for rows.Next() {
		d, err := scanDoc(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (d *SpaceDoc) rev() DocRev {
	return DocRev{Rev: d.Rev, Text: d.Text, By: d.UpdatedBy, At: d.Updated, Flags: d.Flags, Hazard: d.Hazard, Size: len(d.Text)}
}

// GetDocRev returns revision rev of a doc (rev 0 = current). The history table is read first; a
// current row without a history row (forks copy rows, not history) is served as is.
func GetDocRev(ctx context.Context, q core.Q, slug, name string, rev int) (DocRev, error) {
	cur, err := GetDoc(ctx, q, slug, name)
	if err != nil {
		return DocRev{}, err
	}
	if rev <= 0 {
		rev = cur.Rev
	}
	var r DocRev
	err = q.QueryRow(ctx, `SELECT rev, text, updated_by, updated, flags, hazard, coalesce(revert_of, 0) FROM space_doc_revs
		WHERE space = $1 AND name = $2 AND rev = $3`, slug, name, rev).Scan(&r.Rev, &r.Text, &r.By, &r.At, &r.Flags, &r.Hazard, &r.RevertOf)
	if errors.Is(err, errNoRows) {
		if rev == cur.Rev {
			return cur.rev(), nil
		}
		return DocRev{}, core.E(404, "notfound", "rev "+strconv.Itoa(rev)+" (current "+strconv.Itoa(cur.Rev)+")")
	}
	r.Size = len(r.Text)
	return r, err
}

// DocRevs returns revisions from and to of a doc (to 0 = current) for the delta package (27.3).
func DocRevs(ctx context.Context, q core.Q, slug, name string, from, to int) (DocRev, DocRev, error) {
	a, err := GetDocRev(ctx, q, slug, name, from)
	if err != nil {
		return DocRev{}, DocRev{}, err
	}
	b, err := GetDocRev(ctx, q, slug, name, to)
	if err != nil {
		return DocRev{}, DocRev{}, err
	}
	return a, b, nil
}

// ListDocRevs lists the latest n revisions of a doc (texts omitted, sizes kept).
func ListDocRevs(ctx context.Context, q core.Q, slug, name string, n int) ([]DocRev, error) {
	if n <= 0 || n > 100 {
		n = 20
	}
	rows, err := q.Query(ctx, `SELECT rev, updated_by, updated, length(text), coalesce(revert_of, 0), flags, hazard FROM space_doc_revs
		WHERE space = $1 AND name = $2 ORDER BY rev DESC LIMIT $3`, slug, name, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DocRev
	for rows.Next() {
		var r DocRev
		if err := rows.Scan(&r.Rev, &r.By, &r.At, &r.Size, &r.RevertOf, &r.Flags, &r.Hazard); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- validators -----------------------------------------------------------------------------------

var (
	docHostRe = regexp.MustCompile(`(?i)\bhttps?://([a-z0-9][a-z0-9.-]*\.[a-z]{2,24})`)
	docURLRe  = regexp.MustCompile(`https?://[^\s<>"')\]]+`)
	// imperativeLineRe refuses reader-directed imperatives at line starts (18.4 llms validators).
	imperativeLineRe = regexp.MustCompile(`(?im)^\s*(run|execute|install|paste|download|type|enter|click|open|curl|wget|pip|npm|sudo|eval|source|chmod|export)\b`)
)

// prepareDocText normalises a doc body: NFKC + invisibles stripped, CRLF -> LF, other controls
// dropped, trailing blank space removed.
func prepareDocText(text string) string {
	return strings.TrimRight(doc.CleanMulti(scrub.Normalize(text)), " \t\n")
}

// tplHeadings lists the `## ` headings of a template doc in order, case preserved.
func tplHeadings(tpl string) []string {
	var out []string
	for _, l := range strings.Split(tpl, "\n") {
		if h, ok := strings.CutPrefix(strings.TrimSpace(l), "## "); ok {
			if h = strings.TrimSpace(h); h != "" {
				out = append(out, h)
			}
		}
	}
	return out
}

// validateSpecial applies the per-name rules: templates carry 1..16 `## ` headings, `llms` obeys
// the 18.4 validators (<= 600 B, no control chars, links only to PUBLIC_URL, no reader-directed
// imperatives; the lexicon blocklist is applied by the caller).
func validateSpecial(name, text string) error {
	switch name {
	case DocTplTask, DocTplKB:
		hs := tplHeadings(text)
		if len(hs) == 0 {
			return core.Bad("template doc needs at least one '## heading' line")
		}
		if len(hs) > MaxTplHeadings {
			return core.Bad(fmt.Sprintf("template doc <= %d headings", MaxTplHeadings))
		}
		for _, h := range hs {
			if len(h) > 64 {
				return core.Bad("template heading <= 64 bytes")
			}
		}
	case DocLLMS:
		if len(text) > MaxLLMSDoc {
			return core.Bad(fmt.Sprintf("llms doc <= %d bytes", MaxLLMSDoc))
		}
		if strings.ContainsFunc(text, func(r rune) bool { return r != '\n' && unicode.IsControl(r) }) {
			return core.Bad("llms doc: no control characters")
		}
		base := doc.Base()
		for _, m := range docURLRe.FindAllString(text, -1) {
			if m != base && !strings.HasPrefix(m, base+"/") {
				return core.Bad("llms doc links only " + base)
			}
		}
		if imperativeLineRe.MatchString(text) {
			return core.Bad("llms doc lines never start with a reader-directed imperative")
		}
	}
	return nil
}

// lexFlags runs the lexicon and drops the informational lang= markers (only real flags are stored:
// any stored flag turns the space page noindex, 4.5).
func lexFlags(text string) (int, []string) {
	score, flags, _ := scrub.Flags(text)
	out := []string{}
	for _, f := range flags {
		if !strings.HasPrefix(f, "lang=") {
			out = append(out, f)
		}
	}
	return score, out
}

// newDomainLink reports a link to a registrable host never seen on the site (4.4): outside scrub's
// allowlist, not PUBLIC_URL, absent from visible entries and from every space doc.
func newDomainLink(ctx context.Context, q core.Q, text string) (bool, error) {
	self := ""
	if u, err := url.Parse(doc.Base()); err == nil {
		self = strings.ToLower(u.Hostname())
	}
	seen := map[string]bool{}
	for _, m := range docHostRe.FindAllStringSubmatch(text, 8) {
		host := strings.ToLower(strings.TrimSuffix(m[1], "."))
		if seen[host] || host == self || scrub.HostAllowed(host) {
			continue
		}
		seen[host] = true
		var known bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM kb WHERE NOT quarantine AND NOT hidden AND tsv @@ to_tsquery('english', $1))
			OR EXISTS (SELECT 1 FROM space_docs WHERE text ILIKE '%' || $2 || '%')`,
			"'"+strings.ReplaceAll(host, "'", "")+"'", host).Scan(&known); err != nil {
			return false, err
		}
		if !known {
			return true, nil
		}
	}
	return false, nil
}

// --- the template gate (7.2 wording) ---------------------------------------------------------------

// templateGate checks a post body against the space's tpl-task (kind task) or tpl-kb (kind kb)
// headings when rules.templates enables that template. The first missing heading is named with
// its original case: `err bad missing: Expected (GET /v1/s/<slug>/d/tpl-task)`. Rules can switch
// the check on or off per kind, never weaken it (constitution).
func templateGate(ctx context.Context, q core.Q, space, kind, body string) *core.APIError {
	if space == "" || !slugRe.MatchString(space) {
		return nil
	}
	rules, err := RulesOf(ctx, q, space)
	if err != nil {
		return nil
	}
	name := DocTplTask
	switch kind {
	case "task":
		if !rules.Templates.Task {
			return nil
		}
	case "kb":
		if !rules.Templates.KB {
			return nil
		}
		name = DocTplKB
	default:
		return nil
	}
	tpl, err := docText(ctx, q, space, name)
	if err != nil || tpl == "" {
		return nil
	}
	have := map[string]bool{}
	for _, h := range tplHeadings(body) {
		have[strings.ToLower(h)] = true
	}
	for _, h := range tplHeadings(tpl) {
		if !have[strings.ToLower(h)] {
			return core.E(400, "bad", "missing: "+doc.SafeLine(h)+" (GET /v1/s/"+space+"/d/"+name+")")
		}
	}
	return nil
}

// TemplateGate is the forge.TemplateCheck seam shape for task bodies (RegisterContent installs it
// when nothing else did).
func TemplateGate(ctx context.Context, q core.Q, space, body string) *core.APIError {
	return templateGate(ctx, q, space, "task", body)
}

// KBTemplateGate checks an entry's text fields against the space's tpl-kb headings.
func KBTemplateGate(ctx context.Context, q core.Q, space, text string) *core.APIError {
	return templateGate(ctx, q, space, "kb", text)
}

// --- writes --------------------------------------------------------------------------------------

type docRow struct {
	exists, hidden bool
	rev            int
	text, root     string
	updated        time.Time
	voteUntil      *time.Time
}

func lockDoc(ctx context.Context, q core.Q, slug, name string) (docRow, error) {
	var r docRow
	err := q.QueryRow(ctx, `SELECT rev, text, updated_root, updated, hidden, vote_until FROM space_docs WHERE space = $1 AND name = $2 FOR UPDATE`, slug, name).
		Scan(&r.rev, &r.text, &r.root, &r.updated, &r.hidden, &r.voteUntil)
	if errors.Is(err, errNoRows) {
		return r, nil
	}
	r.exists = err == nil
	return r, err
}

// writeRev stores a new revision of (slug, name): the previous current row is snapshotted into
// space_doc_revs when missing (forks copy rows without history), the row is upserted, the
// revision inserted, the space's last_write bumped and the mirror row enqueued.
func writeRev(ctx context.Context, q core.Q, slug, name string, cur docRow, text, by, root string, flags, hazard []string, revertOf int) (int, error) {
	if cur.exists {
		if _, err := q.Exec(ctx, `INSERT INTO space_doc_revs (space, name, rev, text, updated_by, updated_root, updated, flags, hazard)
			SELECT space, name, rev, text, updated_by, updated_root, updated, flags, hazard FROM space_docs WHERE space = $1 AND name = $2
			ON CONFLICT DO NOTHING`, slug, name); err != nil {
			return 0, err
		}
	}
	rev := cur.rev + 1
	if _, err := q.Exec(ctx, `INSERT INTO space_docs (space, name, text, rev, updated_by, updated_root, updated, flags, hazard)
		VALUES ($1, $2, $3, $4, $5, $6, now(), $7, $8)
		ON CONFLICT (space, name) DO UPDATE SET text = EXCLUDED.text, rev = EXCLUDED.rev, updated_by = EXCLUDED.updated_by,
		  updated_root = EXCLUDED.updated_root, updated = now(), flags = EXCLUDED.flags, hazard = EXCLUDED.hazard`,
		slug, name, text, rev, by, root, flags, hazard); err != nil {
		return 0, err
	}
	var ro *int
	if revertOf > 0 {
		ro = &revertOf
	}
	if _, err := q.Exec(ctx, `INSERT INTO space_doc_revs (space, name, rev, text, updated_by, updated_root, flags, hazard, revert_of)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, slug, name, rev, text, by, root, flags, hazard, ro); err != nil {
		return 0, err
	}
	if _, err := q.Exec(ctx, `UPDATE spaces SET last_write = now() WHERE slug = $1`, slug); err != nil {
		return 0, err
	}
	if err := core.Event(ctx, q, "space", "s:"+slug, "", "doc "+name+" rev "+strconv.Itoa(rev)); err != nil {
		return 0, err
	}
	return rev, forge.Enqueue(ctx, q, "space-doc", slug+"/"+name, []byte(text))
}

// revertOf returns the latest earlier revision whose text equals text (0 when none).
func revertOf(ctx context.Context, q core.Q, slug, name string, below int, text string) (int, error) {
	var rev int
	err := q.QueryRow(ctx, `SELECT rev FROM space_doc_revs WHERE space = $1 AND name = $2 AND rev < $3 AND text = $4 ORDER BY rev DESC LIMIT 1`,
		slug, name, below, text).Scan(&rev)
	if errors.Is(err, errNoRows) {
		return 0, nil
	}
	return rev, err
}

// PutDoc is PUT /v1/s/{slug}/d/{name}: policy (rules.docs, bans, frozen/hidden spaces), special
// names, scrub (tier 1 rejects, tier 2 masks), lexicon + hazards + new-domain into flags/hazard,
// If-Match CAS, the 10-minute rule, 10 edits/day/member, revision + mirror, edit-war detection.
func PutDoc(ctx context.Context, d *core.Deps, id *core.Ident, slug, name string, in PutDocInput) (DocResult, error) {
	var out DocResult
	if !slugRe.MatchString(slug) {
		return out, core.ErrNotFound
	}
	if !docNameRe.MatchString(name) {
		return out, core.Bad("name must match [a-z0-9._-]{1,32}")
	}
	sp, err := Get(ctx, d.DB, slug)
	if err != nil {
		return out, err
	}
	if err := sp.Gone(); err != nil {
		if sp.Hidden && !sp.Archived {
			return out, core.E(403, "auth", "space hidden (read-only)")
		}
		return out, err
	}
	if sp.Frozen {
		return out, core.E(503, "frozen", "space "+slug)
	}
	if until, ok, err := banned(ctx, d.DB, slug, id.Root); err != nil {
		return out, err
	} else if ok {
		return out, core.E(403, "auth", "banned in space until "+core.Date(until))
	}
	role, err := Role(ctx, d.DB, slug, id.Root)
	if err != nil {
		return out, err
	}
	switch sp.Rules.Docs {
	case "vote":
		return out, core.E(403, "auth", "docs by vote (POST /v1/p {\"scope\":\""+slug+"\",\"kind\":\"doc\"})")
	case "stewards":
		if role != "steward" {
			return out, core.E(403, "auth", "stewards only (rules.docs)")
		}
	default:
		if role == "" {
			return out, core.E(403, "auth", "members only (rules.docs)")
		}
	}
	text := prepareDocText(in.Text)
	if len(text) > MaxDoc {
		return out, core.ErrSize
	}
	if err := validateSpecial(name, text); err != nil {
		return out, err
	}
	masked, aerr := scrub.RejectOrMask(map[string]*string{"text": &text})
	if aerr != nil {
		return out, aerr
	}
	if len(text) > MaxDoc {
		return out, core.ErrSize
	}
	score, flags := lexFlags(text)
	if name == DocLLMS && score >= 2 {
		return out, core.Bad("lexicon")
	}
	hazard := scrub.Hazards(text)
	if hazard == nil {
		hazard = []string{}
	}
	st, err := trust.Load(ctx, d.DB, id.Root)
	if err != nil {
		return out, err
	}
	if st.Level() < 2 {
		nd, err := newDomainLink(ctx, d.DB, text)
		if err != nil {
			return out, err
		}
		if nd {
			flags = append(flags, "new-domain")
		}
	}
	out.Masked, out.Flags, out.Hazard = masked, flags, hazard
	ip, _, _ := core.ClientFrom(ctx)
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		cur, err := lockDoc(ctx, tx, slug, name)
		if err != nil {
			return err
		}
		if cur.voteUntil != nil && cur.voteUntil.After(time.Now()) {
			return core.E(403, "auth", "doc "+name+" in vote mode until "+core.Date(*cur.voteUntil)+" (POST /v1/p kind doc)")
		}
		if cur.hidden {
			return core.E(403, "auth", "doc hidden by stewards (unhide first)")
		}
		if in.IfMatch != "" {
			if !cur.exists || in.IfMatch != strconv.Itoa(cur.rev) {
				return core.E(412, "cas", "rev="+strconv.Itoa(cur.rev))
			}
		} else if cur.exists && cur.root != "" && cur.root != id.Root && time.Since(cur.updated) < ConcurrentEdit {
			return core.E(428, "precondition", "required rev="+strconv.Itoa(cur.rev))
		}
		if n, err := bump(ctx, tx, "sp:"+slug+":"+id.Root, "d"); err != nil {
			return err
		} else if n > DocEditsPerDay {
			return core.E(429, "quota", fmt.Sprintf("space doc edits %d/day", DocEditsPerDay))
		}
		if cur.exists && cur.text == text {
			out.Rev, out.Unchanged = cur.rev, true
			return nil
		}
		if cur.exists {
			if out.RevertOf, err = revertOf(ctx, tx, slug, name, cur.rev, text); err != nil {
				return err
			}
		}
		rev, err := writeRev(ctx, tx, slug, name, cur, text, id.ID, id.Root, flags, hazard, out.RevertOf)
		if err != nil {
			return err
		}
		out.Rev = rev
		why := "rev " + strconv.Itoa(rev)
		if out.RevertOf > 0 {
			why += " revert of " + strconv.Itoa(out.RevertOf)
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM space_doc_revs WHERE space = $1 AND name = $2 AND revert_of IS NOT NULL AND updated > now() - $3::interval`,
				slug, name, strconv.Itoa(int(RevertWindow/time.Second))+" seconds").Scan(&n); err != nil {
				return err
			}
			if n >= RevertsToVote {
				if _, err := tx.Exec(ctx, `UPDATE space_docs SET vote_until = now() + $3::interval WHERE space = $1 AND name = $2`,
					slug, name, strconv.Itoa(int(VoteModeFor/time.Second))+" seconds"); err != nil {
					return err
				}
				out.VoteMode = true
				if err := modLog(ctx, tx, slug, core.SystemID, "d:"+name, "doc-vote",
					fmt.Sprintf("%d reverts in 24 h: vote mode %d d", n, int(VoteModeFor/(24*time.Hour)))); err != nil {
					return err
				}
			}
		}
		if err := modLog(ctx, tx, slug, id.Root, "d:"+name, "doc", why); err != nil {
			return err
		}
		if err := core.Origin(ctx, tx, "sd", slug+"/"+name, id.Root, id.ID, ip); err != nil {
			return err
		}
		return core.Audit(ctx, tx, id.ID, "sd", slug+"/"+name, rev)
	})
	if err != nil {
		return DocResult{}, err
	}
	return out, nil
}

// ApplyDoc is the gov applier shape for proposal kinds doc and template: a passed vote writes a
// new revision inside tx whatever rules.docs says, clears an edit-war vote mode and returns the
// previous text for the prev snapshot (revert = re-propose prev). by is the proposal id. Scrub,
// hazards and the special-name validators still apply; the lexicon is recorded, never a bar.
func ApplyDoc(ctx context.Context, tx core.Q, slug, name, text, by string) (prev string, rev int, err error) {
	if !slugRe.MatchString(slug) {
		return "", 0, core.ErrNotFound
	}
	// Defense-in-depth: the platform roadmap space is non-amendable (27.5), mirroring ApplyRules
	// and SetSteward. A space-scoped doc/template proposal with scope "platform" must never rewrite
	// its docs even if the gov doc@space applier is ever registered.
	if slug == "platform" {
		return "", 0, core.E(403, "auth", "platform space is not amendable")
	}
	if !docNameRe.MatchString(name) {
		return "", 0, core.Bad("name must match [a-z0-9._-]{1,32}")
	}
	sp, err := scanSpace(tx.QueryRow(ctx, `SELECT `+spaceCols+` FROM spaces WHERE slug = $1 FOR UPDATE`, slug))
	if err != nil {
		return "", 0, err
	}
	if err := sp.Gone(); err != nil {
		return "", 0, err
	}
	text = prepareDocText(text)
	if len(text) > MaxDoc {
		return "", 0, core.ErrSize
	}
	if err := validateSpecial(name, text); err != nil {
		return "", 0, err
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"text": &text}); aerr != nil {
		return "", 0, aerr
	}
	_, flags := lexFlags(text)
	hazard := scrub.Hazards(text)
	if hazard == nil {
		hazard = []string{}
	}
	cur, err := lockDoc(ctx, tx, slug, name)
	if err != nil {
		return "", 0, err
	}
	if by == "" {
		by = "gov"
	}
	rev, err = writeRev(ctx, tx, slug, name, cur, text, by, "", flags, hazard, 0)
	if err != nil {
		return "", 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE space_docs SET vote_until = NULL, hidden = false WHERE space = $1 AND name = $2`, slug, name); err != nil {
		return "", 0, err
	}
	return cur.text, rev, modLog(ctx, tx, slug, by, "d:"+name, "doc-apply", "rev "+strconv.Itoa(rev))
}

// SetDocHidden hides or restores a doc (steward moderation, mod.go): hidden docs answer 410 and
// leave the mirror; the text and history stay for the appeal window.
func SetDocHidden(ctx context.Context, q core.Q, slug, name string, hidden bool) error {
	var text string
	err := q.QueryRow(ctx, `UPDATE space_docs SET hidden = $3 WHERE space = $1 AND name = $2 AND hidden <> $3 RETURNING text`, slug, name, hidden).Scan(&text)
	if errors.Is(err, errNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if hidden {
		return forge.Enqueue(ctx, q, "space-doc", slug+"/"+name, nil)
	}
	return forge.Enqueue(ctx, q, "space-doc", slug+"/"+name, []byte(text))
}

// --- rendering ----------------------------------------------------------------------------------

// docHead renders `d <slug>/<name> rev=N by <id> <date>[ flags:…][ hazard:…][ hidden][ vote-mode until=<date>] size=<bytes>`.
func docHead(slug, name string, r DocRev, d *SpaceDoc) string {
	var b strings.Builder
	fmt.Fprintf(&b, "d %s/%s rev=%d by %s %s", slug, name, r.Rev, doc.SafeLine(r.By), core.Date(r.At))
	if len(r.Flags) > 0 {
		b.WriteString(" flags:" + strings.Join(r.Flags, ","))
	}
	if len(r.Hazard) > 0 {
		b.WriteString(" hazard:" + strings.Join(r.Hazard, ","))
	}
	if d != nil {
		if r.Rev != d.Rev {
			fmt.Fprintf(&b, " current=%d", d.Rev)
		}
		if d.Hidden {
			b.WriteString(" hidden")
		}
		if d.InVoteMode() {
			b.WriteString(" vote-mode until=" + core.Date(d.VoteUntil))
		}
	}
	if r.RevertOf > 0 {
		fmt.Fprintf(&b, " revert_of=%d", r.RevertOf)
	}
	fmt.Fprintf(&b, " size=%d", r.Size)
	return b.String()
}

// docDoc builds the sdg document: head, the text as one multi-line field (every continuation line
// indented so no doc line can masquerade as a field), the untrusted banner in next:.
func docDoc(slug, name string, r DocRev, d *SpaceDoc) *doc.Doc {
	dd := &doc.Doc{Head: docHead(slug, name, r, d), Budget: 2000}
	if r.Text != "" {
		dd.Fields = append(dd.Fields, doc.F{Name: "text", Val: r.Text, Multi: true})
	}
	p := "/v1/s/" + slug + "/d/" + name
	dd.Next = []doc.Action{{Method: "PUT", Path: p, Hint: "If-Match: \"" + strconv.Itoa(r.Rev) + "\""}, doc.GET(p+"/revs", "history"), doc.GET("/v1/s/"+slug, "space")}
	return dd
}

func docListDoc(slug string, docs []*SpaceDoc) *doc.Doc {
	d := &doc.Doc{Head: fmt.Sprintf("docs %s n=%d", slug, len(docs)), Cols: []string{"name", "rev", "size", "by", "updated", "state"}, Budget: 400}
	for _, x := range docs {
		state := "-"
		switch {
		case x.Hidden:
			state = "hidden"
		case x.InVoteMode():
			state = "vote-mode"
		case len(x.Flags) > 0 || len(x.Hazard) > 0:
			state = "flagged"
		}
		d.Rows = append(d.Rows, []string{x.Name, strconv.Itoa(x.Rev), strconv.Itoa(len(x.Text)), doc.SafeLine(x.UpdatedBy), core.Date(x.Updated), state})
	}
	d.Next = []doc.Action{doc.GET("/v1/s/"+slug+"/d/home", ""), {Method: "PUT", Path: "/v1/s/" + slug + "/d/<name>", Hint: "text body"}}
	return d
}

func revsDoc(slug, name string, revs []DocRev, cur *SpaceDoc) *doc.Doc {
	d := &doc.Doc{Head: fmt.Sprintf("revs %s/%s n=%d current=%d", slug, name, len(revs), cur.Rev), Cols: []string{"rev", "by", "date", "size", "note"}, Budget: 400}
	for _, r := range revs {
		note := "-"
		if r.RevertOf > 0 {
			note = "revert_of=" + strconv.Itoa(r.RevertOf)
		}
		d.Rows = append(d.Rows, []string{strconv.Itoa(r.Rev), doc.SafeLine(r.By), core.Date(r.At), strconv.Itoa(r.Size), note})
	}
	p := "/v1/s/" + slug + "/d/" + name
	d.Next = []doc.Action{doc.GET(p+"?rev=<n>", ""), doc.GET(p+"/diff?from=<a>&to=<b>", "delta")}
	return d
}
