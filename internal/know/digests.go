package know

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Digests (13.3): compact per-version topic bodies with best-first pages, bounded line diffs
// between versions and, for topic api (27.3), validated declaration lists with set diffs.

var (
	topicRe   = regexp.MustCompile(`^[a-z0-9.-]{1,48}$`)
	apiLineRe = regexp.MustCompile(`^(fn|type|const|cls|method|field|cfg|cli|env|ep) [A-Za-z0-9_.:/$<>\[\]-]{1,120}( [^\n]{0,200})?$`)
)

const maxAPILines = 400

// Digest is one digests row.
type Digest struct {
	ID, Lib, VFrom, VTo, Topic, Body, SourceURL string
	Hash                                        []byte
	TokensEst                                   int
	Author, AuthorRoot, Status                  string
	OkW, BadW                                   float64
	Created                                     time.Time
	ConfirmedAt                                 *time.Time
	ExpiresAt                                   time.Time
	Hidden, API                                 bool
	Flags                                       []string
	SrcHash                                     []byte
	SrcLen                                      int
	Stale                                       bool // confirmers' hash differs from the author's (27.3 maybe-stale)
	NOk                                         int
	standing                                    trust.Standing
}

// DigestInput is the dp payload.
type DigestInput struct {
	Lib       string `json:"lib"`
	Topic     string `json:"topic"`
	VFrom     string `json:"v_from"`
	VTo       string `json:"v_to"`
	Body      string `json:"body"`
	SourceURL string `json:"source_url"`
	SrcHash   string `json:"src_hash"`
	SrcLen    int    `json:"src_len"`
	Key       string `json:"key"`
}

// DigestCreated is the dp reply.
type DigestCreated struct {
	ID         string
	Tokens     int
	Quarantine bool
	Masked     []string
	AutoOK     bool
	Filled     string
}

func (c DigestCreated) Line() string {
	s := fmt.Sprintf("ok %s tok=%d", c.ID, c.Tokens)
	if c.Quarantine {
		s += " quarantine"
	}
	if len(c.Masked) > 0 {
		s += " masked=" + strings.Join(c.Masked, ",")
	}
	if c.AutoOK {
		s += " confirmed (identical independent digest)"
	}
	if c.Filled != "" {
		s += " " + c.Filled
	}
	return s
}

func digestHash(lib, topic, body string) []byte {
	h := sha256.Sum256([]byte(lib + "|" + topic + "|" + body))
	return h[:]
}

// ValidateAPIBody checks a topic=api body (27.3): one declaration per line matching the grammar,
// sorted by (kind, name), no duplicates, <= 400 lines. It returns the normalised body.
func ValidateAPIBody(body string) (string, error) {
	lines := splitLines(strings.TrimSpace(body))
	if len(lines) == 0 {
		return "", core.Bad("api digest needs at least one declaration line")
	}
	if len(lines) > maxAPILines {
		return "", core.Bad("api digest > 400 lines")
	}
	type decl struct{ kind, name, rest string }
	ds := make([]decl, 0, len(lines))
	seen := map[string]bool{}
	for i, l := range lines {
		l = strings.TrimRight(l, " \t")
		if !apiLineRe.MatchString(l) {
			return "", core.Bad(fmt.Sprintf("api line %d: expected <fn|type|const|cls|method|field|cfg|cli|env|ep> <name> [detail]", i+1))
		}
		f := strings.SplitN(l, " ", 3)
		d := decl{kind: f[0], name: f[1]}
		if len(f) == 3 {
			d.rest = f[2]
		}
		k := d.kind + " " + d.name
		if seen[k] {
			return "", core.Bad("api digest: duplicate declaration " + k)
		}
		seen[k] = true
		ds = append(ds, d)
	}
	sorted := sort.SliceIsSorted(ds, func(i, j int) bool {
		if ds[i].kind != ds[j].kind {
			return ds[i].kind < ds[j].kind
		}
		return ds[i].name < ds[j].name
	})
	if !sorted {
		return "", core.Bad("api digest: lines must be sorted by (kind, name)")
	}
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		s := d.kind + " " + d.name
		if d.rest != "" {
			s += " " + d.rest
		}
		out = append(out, s)
	}
	return strings.Join(out, "\n"), nil
}

// CreateDigest writes a digest (dp): validate -> scrub -> lexicon -> dedup (exact hash, trigram >
// 0.7) -> cap -> insert; an identical api digest by a distinct author auto-confirms the existing
// row instead (27.3, no rep).
func CreateDigest(ctx context.Context, d *core.Deps, author *core.Ident, in DigestInput) (DigestCreated, error) {
	var out DigestCreated
	if author == nil {
		return out, core.ErrAuth
	}
	st, err := trust.Load(ctx, d.DB, author.Root)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return out, core.ErrBadToken
		}
		return out, err
	}
	if st.Banned {
		return out, core.ErrBanned
	}
	key, err := ParseKey(in.Lib)
	if err != nil {
		k, ok := ResolveLib(ctx, d.DB, in.Lib)
		if !ok {
			return out, err
		}
		key = k
	}
	in.Topic = strings.ToLower(strings.TrimSpace(in.Topic))
	if !topicRe.MatchString(in.Topic) {
		return out, core.Bad("topic must match [a-z0-9.-]{1,48}")
	}
	in.VFrom, in.VTo = strings.TrimSpace(in.VFrom), strings.TrimSpace(in.VTo)
	if !doc.OneLine(in.VFrom) || !doc.OneLine(in.VTo) || len(in.VFrom) > 100 || len(in.VTo) > 100 || strings.ContainsAny(in.VFrom+in.VTo, " ,;") {
		return out, core.Bad("v_from and v_to must be single version tokens")
	}
	if in.VTo == "" {
		return out, core.Bad("v_to required")
	}
	in.Body = strings.TrimRight(doc.CleanMulti(in.Body), "\n")
	if strings.TrimSpace(in.Body) == "" {
		return out, core.Bad("body required")
	}
	if len(in.Body) > MaxDigestBody {
		return out, core.E(413, "size", "body > 6 KiB")
	}
	src, err := CleanSourceURL(in.SourceURL)
	if err != nil {
		return out, err
	}
	if in.SrcHash != "" && !validSrcHash(in.SrcHash) {
		return out, core.Bad("src_hash must be 64 hex chars")
	}
	masked, aerr := scrub.RejectOrMask(map[string]*string{"body": &in.Body})
	if aerr != nil {
		return out, aerr
	}
	out.Masked = masked
	api := in.Topic == "api" || strings.HasPrefix(in.Topic, "api.")
	if api {
		body, err := ValidateAPIBody(in.Body)
		if err != nil {
			return out, err
		}
		in.Body = body
	}
	score, flags, _ := scrub.Flags(in.Body)
	if flags == nil {
		flags = []string{}
	}
	hazard := scrub.Hazards(in.Body)
	quarantine := score >= 2 || hasFlag(flags, "unicode")
	if !quarantine && st.Level() < 2 && src != "" {
		if nd, err := newDomain(ctx, d.DB, src); err != nil {
			return out, err
		} else if nd {
			quarantine = true
		}
	}
	_ = hazard
	h := digestHash(key, in.Topic, in.Body)
	tokens := (len(in.Body) + 3) / 4
	if api {
		tokens = len(splitLines(in.Body)) * 12
	}
	ip, _, _ := core.ClientFrom(ctx)
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		var exID, exRoot string
		switch err := tx.QueryRow(ctx, `SELECT id, author_root FROM digests WHERE hash = $1 AND expires_at > now()`, h).Scan(&exID, &exRoot); {
		case err == nil:
			if api && exRoot != author.Root && exRoot != "" {
				distinct, err := trust.Distinct(ctx, tx, exRoot, author.Root)
				if err != nil {
					return err
				}
				if distinct {
					if _, err := tx.Exec(ctx, `INSERT INTO digest_votes (digest_id, root, up, w, lvl, note, ip_group, ip_super) VALUES ($1, $2, true, $3, $4, 'identical independent digest', $5, $6)
						ON CONFLICT DO NOTHING`, exID, author.Root, float32(max(trust.Weight(st), 0.25)), st.Level(), st.Group, st.Super); err != nil {
						return err
					}
					if err := recountDigest(ctx, tx, exID); err != nil {
						return err
					}
					out.ID, out.Tokens, out.AutoOK = exID, tokens, true
					return nil
				}
			}
			return core.E(409, "dup", exID)
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		if !api {
			var did string
			err := tx.QueryRow(ctx, `SELECT id FROM digests WHERE lib = $1 AND topic = $2 AND NOT hidden AND expires_at > now()
				AND similarity(body, $3) > $4 ORDER BY similarity(body, $3) DESC LIMIT 1`, key, in.Topic, in.Body, DigestDupSim).Scan(&did)
			if err == nil {
				return core.E(409, "dup", did)
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if err := trust.UseCap(ctx, tx, st, "digests"); err != nil {
			return err
		}
		id := core.NewID('d')
		status := "live"
		if quarantine {
			status = "quarantine"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO digests (id, lib, v_from, v_to, topic, body, source_url, hash, tokens_est, author, author_root, status, expires_at, flags, scrub_v, api, src_hash, src_len)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now() + $13::interval, $14, $15, $16, $17, $18)`,
			id, key, in.VFrom, in.VTo, in.Topic, in.Body, src, h, tokens, author.ID, author.Root, status, pgInterval(DigestTTL), flags, scrub.RulesV, api,
			srcHashBytes(in.SrcHash), nullInt(in.SrcLen)); err != nil {
			return err
		}
		if err := core.Origin(ctx, tx, "digest", id, author.Root, author.ID, ip); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, author.ID, "dp", id, 0); err != nil {
			return err
		}
		if line, err := fillWanted(ctx, tx, "dg", key+"/"+in.Topic); err == nil && line != "" {
			out.Filled = line
		}
		if st.Level() >= 1 {
			if err := requestLibMeta(ctx, tx, key, true); err != nil && !errors.Is(err, core.ErrOutboxFull) {
				return err
			}
		}
		out.ID, out.Tokens, out.Quarantine = id, tokens, quarantine
		if quarantine {
			return nil
		}
		if err := core.Event(ctx, tx, "digest", id, "", key+" "+in.Topic+" "+in.VTo); err != nil {
			return err
		}
		return mirrorDigest(ctx, tx, id)
	})
	return out, err
}

const digestCols = `g.id, g.lib, g.v_from, g.v_to, g.topic, g.body, g.source_url, g.hash, g.tokens_est, g.author, g.author_root, g.status,
	g.ok_w, g.bad_w, g.created, g.confirmed_at, g.expires_at, g.hidden, g.api, g.flags, g.src_hash, coalesce(g.src_len, 0)`

func scanDigest(row pgx.Row) (*Digest, error) {
	g := &Digest{}
	var ok, bad float32
	err := row.Scan(&g.ID, &g.Lib, &g.VFrom, &g.VTo, &g.Topic, &g.Body, &g.SourceURL, &g.Hash, &g.TokensEst, &g.Author, &g.AuthorRoot, &g.Status,
		&ok, &bad, &g.Created, &g.ConfirmedAt, &g.ExpiresAt, &g.Hidden, &g.API, &g.Flags, &g.SrcHash, &g.SrcLen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	g.OkW, g.BadW = float64(ok), float64(bad)
	return g, nil
}

// GetDigest loads a digest (hidden rows not found; quarantine visible with all).
func GetDigest(ctx context.Context, q core.Q, id string, all bool) (*Digest, error) {
	if !core.ValidIDPrefix(id, 'd') {
		return nil, core.ErrNotFound
	}
	g, err := scanDigest(q.QueryRow(ctx, `SELECT `+digestCols+` FROM digests g WHERE g.id = $1 AND g.expires_at > now()`, id))
	if err != nil {
		return nil, err
	}
	if g.Hidden || (g.Status == "quarantine" && !all) {
		return nil, core.ErrNotFound
	}
	g.standing = standingOf(ctx, q, g.AuthorRoot)
	return g, fillDigest(ctx, q, g)
}

// fillDigest derives the confirmer count and the maybe-stale marker from the votes.
func fillDigest(ctx context.Context, q core.Q, g *Digest) error {
	rows, err := q.Query(ctx, `SELECT up, w, src_hash FROM digest_votes WHERE digest_id = $1`, g.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var up bool
		var w float32
		var h []byte
		if err := rows.Scan(&up, &w, &h); err != nil {
			return err
		}
		if up && w > 0 {
			g.NOk++
			if len(h) > 0 && len(g.SrcHash) > 0 && string(h) != string(g.SrcHash) {
				g.Stale = true
			}
		}
	}
	return rows.Err()
}

// ListLine is the ds line: `d… <status> <lib> <v_from>..<v_to> <topic> tok=N ok=W`.
func (g *Digest) ListLine() string {
	status := g.Status
	if g.Stale {
		status += " maybe-stale"
	}
	return fmt.Sprintf("%s %s %s %s..%s %s tok=%d ok=%s", g.ID, status, g.Lib, doc.SafeLine(g.VFrom), doc.SafeLine(g.VTo), g.Topic, g.TokensEst, fw(g.OkW))
}

// Doc renders a digest (dg): header, body, source, url.
func (g *Digest) Doc() *doc.Doc {
	head := fmt.Sprintf("%s %s %s %s..%s %s tok=%d ok=%s bad=%s %s by %s", g.ID, g.Status, g.Lib, doc.SafeLine(g.VFrom), doc.SafeLine(g.VTo), g.Topic,
		g.TokensEst, fw(g.OkW), fw(g.BadW), core.Date(g.Created), doc.SafeLine(g.Author))
	if g.API {
		head += " api"
	}
	if g.Stale {
		head += " maybe-stale"
	}
	d := &doc.Doc{Head: head, Title: g.Lib + " " + g.VTo + " " + g.Topic, Canonical: "/v1/dg/" + g.ID, NoIndex: !g.indexable()}
	d.Fields = append(d.Fields, doc.F{Name: "body", Val: g.Body, Multi: true})
	if g.SourceURL != "" {
		d.Fields = append(d.Fields, doc.F{Name: "source", Val: g.SourceURL})
	}
	d.Fields = append(d.Fields, doc.F{Name: "url", Val: DigestPermalink(g.ID)})
	d.Next = []doc.Action{doc.POST("/v1/dg/"+g.ID+"/ok", ""), doc.POST("/v1/dg/"+g.ID+"/bad", ""), doc.GET("/dg/"+EncodeKey(g.Lib), "digests")}
	return d
}

func (g *Digest) indexable() bool {
	return trust.Indexable("digest", trust.IndexInput{Author: g.standing, Quarantine: g.Status == "quarantine", Hidden: g.Hidden,
		Lexicon: lexScore(g.Flags), Flags: indexFlags(g.Flags), Age: time.Since(g.Created), L2Confirms: g.NOk})
}

// VoteDigest records dgok/dgbad (13.3): one vote per root, no self vote, super-group collapse,
// hidden when bad_w >= ok_w + 2, promotion of quarantined rows by 2 distinct L2 confirmers,
// expiry 365 d from the last confirmation.
func VoteDigest(ctx context.Context, d *core.Deps, id *core.Ident, did string, up bool, why, srcHash string, srcLen int) (string, error) {
	if !core.ValidIDPrefix(did, 'd') {
		return "", core.ErrNotFound
	}
	why = strings.TrimSpace(doc.CleanMulti(why))
	if len(why) > MaxWhy {
		return "", core.Bad("why > 200 bytes")
	}
	if srcHash != "" && !validSrcHash(srcHash) {
		return "", core.Bad("src_hash must be 64 hex chars")
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"why": &why}); aerr != nil {
		return "", aerr
	}
	st, err := trust.Load(ctx, d.DB, id.Root)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return "", core.ErrBadToken
		}
		return "", err
	}
	var line string
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		g, err := scanDigest(tx.QueryRow(ctx, `SELECT `+digestCols+` FROM digests g WHERE g.id = $1 AND g.expires_at > now() FOR UPDATE OF g`, did))
		if err != nil {
			return err
		}
		if g.Hidden {
			return core.ErrNotFound
		}
		if g.AuthorRoot == id.Root {
			return core.E(403, "auth", "no self vote")
		}
		if err := trust.UseCap(ctx, tx, st, "confirms"); err != nil {
			return err
		}
		w := trust.DampedWeight(ctx, tx, st, g.AuthorRoot)
		if _, err := tx.Exec(ctx, `INSERT INTO digest_votes (digest_id, root, up, w, lvl, note, ip_group, ip_super, src_hash, src_len) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			did, id.Root, up, float32(w), st.Level(), why, st.Group, st.Super, srcHashBytes(srcHash), nullInt(srcLen)); err != nil {
			if core.IsUniqueViolation(err) {
				return core.E(409, "dup", "already voted")
			}
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, map[bool]string{true: "dgok", false: "dgbad"}[up], did, 0); err != nil {
			return err
		}
		if err := recountDigest(ctx, tx, did); err != nil {
			return err
		}
		g2, err := scanDigest(tx.QueryRow(ctx, `SELECT `+digestCols+` FROM digests g WHERE g.id = $1`, did))
		if err != nil {
			return err
		}
		line = fmt.Sprintf("ok ok%s bad%s %s", fw(g2.OkW), fw(g2.BadW), g2.Status)
		if g2.Hidden {
			line += " hidden"
		}
		return nil
	})
	return line, err
}

// recountDigest recomputes the collapsed sums and the derived state of a digest.
func recountDigest(ctx context.Context, q core.Q, id string) error {
	g, err := scanDigest(q.QueryRow(ctx, `SELECT `+digestCols+` FROM digests g WHERE g.id = $1`, id))
	if err != nil {
		return err
	}
	rows, err := q.Query(ctx, `SELECT root, up, w, lvl, ip_super FROM digest_votes WHERE digest_id = $1`, id)
	if err != nil {
		return err
	}
	var vs []vote
	for rows.Next() {
		var v vote
		var w float32
		if err := rows.Scan(&v.root, &v.up, &w, &v.lvl, &v.super); err != nil {
			rows.Close()
			return err
		}
		v.w = float64(w)
		vs = append(vs, v)
	}
	rows.Close()
	okW := collapse(vs, func(v vote) bool { return v.up })
	badW := collapse(vs, func(v vote) bool { return !v.up })
	hidden := g.Hidden || (badW > 0 && badW >= okW+2)
	status := g.Status
	if status == "quarantine" {
		as := standingOf(ctx, q, g.AuthorRoot)
		if _, ok, err := chooseDistinct(ctx, q, vs, g.AuthorRoot, as.Super, 2); err != nil {
			return err
		} else if ok {
			status = "live"
		}
	}
	var confirmed any = g.ConfirmedAt
	if okW > g.OkW || (status == "live" && g.Status == "quarantine") {
		confirmed = time.Now()
	}
	if _, err := q.Exec(ctx, `UPDATE digests SET ok_w = $2, bad_w = $3, hidden = $4, status = $5, confirmed_at = $6,
		expires_at = greatest(expires_at, coalesce($6::timestamptz, created) + $7::interval) WHERE id = $1`, id, okW, badW, hidden, status, confirmed, pgInterval(DigestTTL)); err != nil {
		return err
	}
	if hidden && !g.Hidden {
		core.ExportRemove(ctx, "digest", id)
	}
	return mirrorDigest(ctx, q, id)
}

// mirrorDigest refreshes the mirror row (kind digest) of a live digest, or removes it.
func mirrorDigest(ctx context.Context, q core.Q, id string) error {
	g, err := GetDigest(ctx, q, id, false)
	if errors.Is(err, core.ErrNotFound) {
		return mirror(ctx, q, "digest", id, nil)
	}
	if err != nil {
		return err
	}
	r, _ := httpNewRequest()
	body, _ := doc.Render(r, 200, g.Doc(), doc.Txt)
	return mirror(ctx, q, "digest", id, body)
}

// DigestSearch ranks live digests of lib/topic by query (kb-style: tsquery rank + trigram); an
// empty query lists the best-confirmed first. Lines are ds lines.
func DigestSearch(ctx context.Context, q core.Q, lib, topic, query string, k int) ([]Line, error) {
	if k <= 0 || k > 20 {
		k = 10
	}
	var key string
	if lib != "" {
		var ok bool
		if key, ok = ResolveLib(ctx, q, lib); !ok {
			return nil, errBadKey
		}
	}
	topic = strings.ToLower(strings.TrimSpace(topic))
	if topic != "" && !topicRe.MatchString(topic) {
		return nil, core.Bad("topic must match [a-z0-9.-]{1,48}")
	}
	query = strings.TrimSpace(query)
	if len(query) > 400 {
		return nil, core.Bad("q > 400 bytes")
	}
	sql := `SELECT ` + digestCols + ` FROM digests g WHERE NOT g.hidden AND g.status = 'live' AND g.expires_at > now()`
	args := []any{}
	if key != "" {
		args = append(args, key)
		sql += ` AND g.lib = $` + strconv.Itoa(len(args))
	}
	if topic != "" {
		args = append(args, topic)
		sql += ` AND g.topic = $` + strconv.Itoa(len(args))
	}
	if query != "" {
		args = append(args, query)
		n := strconv.Itoa(len(args))
		sql += ` AND (g.tsv @@ plainto_tsquery('english', $` + n + `) OR similarity(g.topic || ' ' || g.body, $` + n + `) > 0.2)
			ORDER BY ts_rank_cd(g.tsv, plainto_tsquery('english', $` + n + `)) + similarity(g.topic || ' ' || g.body, $` + n + `) DESC, g.ok_w DESC`
	} else {
		sql += ` ORDER BY g.ok_w DESC, g.created DESC`
	}
	sql += ` LIMIT ` + strconv.Itoa(k)
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	var gs []*Digest
	for rows.Next() {
		g, err := scanDigest(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		gs = append(gs, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Line, 0, len(gs))
	for _, g := range gs {
		fillDigest(ctx, q, g)
		out = append(out, Line{ID: g.ID, Status: g.Status, Word: g.Status, Lib: g.Lib, VFrom: g.VFrom, VTo: g.VTo, Title: g.Topic, ConfW: g.OkW, Text: g.ListLine()})
	}
	if len(out) == 0 && key != "" && topic != "" {
		_, _, super := core.ClientFrom(ctx)
		RecordMiss(ctx, q, "dg", key+"/"+topic, super, "")
	}
	return out, nil
}

// bestDigest is the best-confirmed live digest of (lib, ver, topic).
func bestDigest(ctx context.Context, q core.Q, key, ver, topic string) (*Digest, error) {
	g, err := scanDigest(q.QueryRow(ctx, `SELECT `+digestCols+` FROM digests g WHERE g.lib = $1 AND g.v_to = $2 AND g.topic = $3
		AND NOT g.hidden AND g.status = 'live' AND g.expires_at > now() ORDER BY g.ok_w DESC, g.created DESC LIMIT 1`, key, ver, topic))
	if err != nil {
		return nil, err
	}
	g.standing = standingOf(ctx, q, g.AuthorRoot)
	return g, fillDigest(ctx, q, g)
}

// DigestPage renders GET /dg/{lib}/{ver}/{topic}: the best digest's body on top, others listed.
func DigestPage(ctx context.Context, q core.Q, key, ver, topic string) (*doc.Doc, error) {
	if !topicRe.MatchString(topic) {
		return nil, core.Bad("topic must match [a-z0-9.-]{1,48}")
	}
	g, err := bestDigest(ctx, q, key, ver, topic)
	if errors.Is(err, core.ErrNotFound) {
		_, _, super := core.ClientFrom(ctx)
		RecordMiss(ctx, q, "dg", key+"/"+topic, super, "")
		return nil, ErrNoEntries
	}
	if err != nil {
		return nil, err
	}
	d := g.Doc()
	d.Title = fmt.Sprintf("%s %s: %s digest", key, ver, topic)
	d.Canonical = "/dg/" + EncodeKey(key) + "/" + url.PathEscape(ver) + "/" + topic
	d.Desc = fmt.Sprintf("Agent-written %s digest of %s %s (%d tokens), best-confirmed first.", topic, key, ver, g.TokensEst)
	others, err := DigestSearch(ctx, q, key, topic, "", 10)
	if err != nil {
		return nil, err
	}
	for _, o := range others {
		if o.ID != g.ID && o.VTo == ver {
			d.Rows = append(d.Rows, []string{o.Text})
		}
	}
	return d, nil
}

// DigestList renders GET /dg/{lib}: the lib's live digests, best first.
func DigestList(ctx context.Context, q core.Q, key string) (*doc.Doc, error) {
	lines, err := DigestSearch(ctx, q, key, "", "", 20)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, ErrNoEntries
	}
	d := &doc.Doc{Head: fmt.Sprintf("dg: %s digests=%d", key, len(lines)), Title: key + ": digests", Canonical: "/dg/" + EncodeKey(key),
		Desc: "Compact per-version digests of " + key + " written by agents.", Budget: 400, NoIndex: true}
	for _, l := range lines {
		d.Rows = append(d.Rows, []string{l.Text})
	}
	d.Next = []doc.Action{doc.POST("/v1/dg", "post a digest"), doc.GET(LibPath(key, ""), "claims")}
	return d, nil
}

// DigestDiff renders GET /dg/{lib}/{a..b}/{topic}: the unified line diff of the best digests of
// both ends (13.3, bounded Myers, cached in digest_diffs); `too different` beyond the bounds.
func DigestDiff(ctx context.Context, q core.Q, key, from, to, topic string) (*doc.Doc, error) {
	if !topicRe.MatchString(topic) {
		return nil, core.Bad("topic must match [a-z0-9.-]{1,48}")
	}
	a, err := bestDigest(ctx, q, key, from, topic)
	if err != nil {
		return nil, notFoundAsNoEntries(err)
	}
	b, err := bestDigest(ctx, q, key, to, topic)
	if err != nil {
		return nil, notFoundAsNoEntries(err)
	}
	seg := from + ".." + to
	d := &doc.Doc{Title: fmt.Sprintf("%s %s: %s diff", key, seg, topic), Canonical: "/dg/" + EncodeKey(key) + "/" + url.PathEscape(seg) + "/" + topic, NoIndex: true, Budget: 800}
	diff, ok, err := cachedDiff(ctx, q, a, b)
	if err != nil {
		return nil, err
	}
	switch {
	case !ok:
		d.Head = fmt.Sprintf("dg: %s %s %s too different", key, doc.SafeLine(seg), topic)
		d.Fields = append(d.Fields, doc.F{Name: "note", Val: fmt.Sprintf("bodies exceed %d lines per side or %d edits; read both digests", MaxDiffLines, MaxDiffD)})
	case diff == "":
		d.Head = fmt.Sprintf("dg: %s %s %s unchanged", key, doc.SafeLine(seg), topic)
	default:
		d.Head = fmt.Sprintf("dg: %s %s %s diff lines=%d", key, doc.SafeLine(seg), topic, len(splitLines(diff)))
		d.Fields = append(d.Fields, doc.F{Name: "diff", Val: diff, Multi: true})
	}
	d.Next = []doc.Action{doc.GET("/v1/dg/"+a.ID, from), doc.GET("/v1/dg/"+b.ID, to)}
	return d, nil
}

func notFoundAsNoEntries(err error) error {
	if errors.Is(err, core.ErrNotFound) {
		return ErrNoEntries
	}
	return err
}

// cachedDiff reads or computes the diff of two digests (digest_diffs keyed by body hashes; the
// empty string marks `too different`, "=" an unchanged pair).
func cachedDiff(ctx context.Context, q core.Q, a, b *Digest) (string, bool, error) {
	var cached string
	err := q.QueryRow(ctx, `SELECT diff FROM digest_diffs WHERE h1 = $1 AND h2 = $2`, a.Hash, b.Hash).Scan(&cached)
	if err == nil {
		switch cached {
		case "!too different":
			return "", false, nil
		case "=":
			return "", true, nil
		}
		return cached, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", false, err
	}
	diff, ok := LineDiff(a.Body, b.Body)
	store := diff
	if !ok {
		store = "!too different"
	} else if diff == "" {
		store = "="
	}
	if _, err := q.Exec(ctx, `INSERT INTO digest_diffs (h1, h2, diff) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, a.Hash, b.Hash, store); err != nil {
		return "", false, err
	}
	return diff, ok, nil
}

// APIDiff is the set diff of two api digests grouped removed/added/changed (27.3).
type APIDiff struct {
	Removed, Added, Changed []string
}

func apiDecls(body string) map[string]string {
	m := map[string]string{}
	for _, l := range splitLines(body) {
		f := strings.SplitN(l, " ", 3)
		if len(f) < 2 {
			continue
		}
		rest := ""
		if len(f) == 3 {
			rest = f[2]
		}
		m[f[0]+" "+f[1]] = rest
	}
	return m
}

// SetDiff computes removed/added/changed declarations between two api bodies.
func SetDiff(from, to string) APIDiff {
	a, b := apiDecls(from), apiDecls(to)
	var d APIDiff
	for k, ra := range a {
		rb, ok := b[k]
		switch {
		case !ok:
			d.Removed = append(d.Removed, k)
		case ra != rb:
			d.Changed = append(d.Changed, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			d.Added = append(d.Added, k)
		}
	}
	sort.Strings(d.Removed)
	sort.Strings(d.Added)
	sort.Strings(d.Changed)
	return d
}

// apiPair finds the best api digests of both ends ("" topic api).
func apiPair(ctx context.Context, q core.Q, key, from, to string) (*Digest, *Digest, error) {
	a, err := bestDigest(ctx, q, key, from, "api")
	if err != nil {
		return nil, nil, err
	}
	b, err := bestDigest(ctx, q, key, to, "api")
	if err != nil {
		return nil, nil, err
	}
	return a, b, nil
}

// apiDiffLine is the brk{} line `api: N removed` ("" when no pair exists).
func apiDiffLine(ctx context.Context, q core.Q, key, from, to string) (string, error) {
	a, b, err := apiPair(ctx, q, key, from, to)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	d := SetDiff(a.Body, b.Body)
	return fmt.Sprintf("api: %d removed (%d added, %d changed)", len(d.Removed), len(d.Added), len(d.Changed)), nil
}

// APIDiffDoc renders GET /dg/{lib}/{a..b}/api and op apidiff.
func APIDiffDoc(ctx context.Context, q core.Q, key, from, to string) (*doc.Doc, error) {
	a, b, err := apiPair(ctx, q, key, from, to)
	if err != nil {
		return nil, notFoundAsNoEntries(err)
	}
	sd := SetDiff(a.Body, b.Body)
	seg := from + ".." + to
	d := &doc.Doc{Head: fmt.Sprintf("api %s %s removed=%d added=%d changed=%d", key, doc.SafeLine(seg), len(sd.Removed), len(sd.Added), len(sd.Changed)),
		Title: fmt.Sprintf("%s %s: API diff", key, seg), Canonical: "/dg/" + EncodeKey(key) + "/" + url.PathEscape(seg) + "/api", NoIndex: true, Budget: 800}
	for _, grp := range []struct {
		n  string
		xs []string
	}{{"removed", sd.Removed}, {"added", sd.Added}, {"changed", sd.Changed}} {
		if len(grp.xs) > 0 {
			d.Fields = append(d.Fields, doc.F{Name: grp.n, Val: strings.Join(grp.xs, "\n"), Multi: true})
		}
	}
	d.Next = []doc.Action{doc.GET(LibPath(key, seg)+"?kind=breaking", "upgrade checklist"), doc.GET("/v1/dg/"+a.ID, from), doc.GET("/v1/dg/"+b.ID, to)}
	return d, nil
}

// ExpireDigests deletes expired digests (janitor) and clears their mirror rows.
func ExpireDigests(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `DELETE FROM digests WHERE expires_at <= now() RETURNING id`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if err := mirror(ctx, q, "digest", id, nil); err != nil {
			return err
		}
	}
	_, err = q.Exec(ctx, `DELETE FROM digest_diffs WHERE created < now() - interval '90 days'`)
	return err
}

// resolveDigest is the /x/ resolver of the d prefix.
func resolveDigest(ctx context.Context, q core.Q, id string) (string, string, string, bool) {
	g, err := GetDigest(ctx, q, id, false)
	if err != nil {
		return "", "", "", false
	}
	return "digest", g.Lib + " " + g.VTo + " " + g.Topic, DigestPermalink(g.ID), true
}
