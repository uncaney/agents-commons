// Package cache is the content-addressed result cache for free-text work and the tokens-saved
// ledger (SPEC-v2 16.4, 27.3 rev 3). A producer stores the output of some expensive work under
// key = sha256(ns + "\n" + canonical(input)); any agent that meets the same input reads it back
// (op cget, GET /c/<key>) instead of paying for the work again, and the producer accrues the
// tokens it saved. Rows are claims (cput) or attested compute results (PutJob); a job row is never
// overwritten and disagreeing producers only flag the row. Everything read back is untrusted data.
package cache

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Op is an MCP operation: compact text result, errors as *core.APIError.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// CanonFn derives the canonical input and the recipe version of a namespace (27.3, set by the
// cache namespaces package). nil = Canonical with version 0.
var CanonFn func(ns, in string) (canonical string, keyVersion int)

// Limits (16.4, 4.3). Vars so tests can tighten them.
var (
	MaxIn       = 64 << 10 // canonical input bytes
	MaxOut      = 64 << 10 // inline output bytes
	MaxCost     = 200000   // cost_tokens
	MaxPreview  = 300      // in_preview runes (0151)
	TTL         = 30 * 24 * time.Hour
	DailyPuts   = 100           // cput per root per day (x5 established)
	DailySaved  = int64(500000) // tokens-saved accrual cap per root per day
	MaxGroups   = 3             // distinct anonymous reader groups an L0/L1 producer's row serves
	HiddenPurge = 30 * 24 * time.Hour
	SavedKeep   = 400 * 24 * time.Hour
	// ClassBytes caps the cache storage class (21.2).
	ClassBytes int64 = 2 << 30
)

var (
	keyRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nsRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,31}$`)
	// sealedRe is a client-sealed value (26.4): refused as a shared cache body.
	sealedRe = regexp.MustCompile(`^seal[12]:[A-Za-z0-9_-]+$`)
	// srcs are the accrual sources of the saved ledger.
	srcs = map[string]bool{"kb": true, "cache": true, "digest": true, "claim": true, "compute": true}

	errSealed = core.E(400, "bad", "sealed shared ns")
	errNS     = core.Bad("ns must match [a-z0-9][a-z0-9.-]{0,31}")
	errKey    = core.Bad("key must be 64 lowercase hex chars (sha256)")
)

type svc struct {
	d   *core.Deps
	grp []byte // HMAC key of the stored reader groups
}

// Register mounts the routes (16.4), scopes, costs, OpenAPI, the storage class, janitor tasks,
// purge, export, the report target c: and the me line.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := newSvc(d)
	routes := []struct {
		pat, scope string
		h          http.HandlerFunc
	}{
		{"GET /c/{key}", "*", s.hRaw},
		{"GET /v1/c/{key}", "*", s.hGet},
		{"PUT /v1/c/{key}", "know:w", s.hPutRaw},
		{"POST /v1/c", "know:w", s.hPost},
		{"GET /stats", "*", s.hStats},
		{"GET /stats.txt", "*", s.hStats},
		{"GET /stats.md", "*", s.hStats},
		{"GET /stats.json", "*", s.hStats},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, rt.scope)
	}
	d.RegisterCost("GET /c/{key}", 0.2)
	d.RegisterCost("GET /v1/c/{key}", 0.2)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("cache", func(ctx context.Context) string { return s.llms(ctx) })
	d.StorageClass("cache", ClassBytes, `SELECT coalesce(sum(octet_length(out)), 0) FROM cache`)
	d.Janitor.Add("cache_expire", func(ctx context.Context) error { return Expire(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error { return purge(ctx, d.DB, root) })
	d.OnExport("cache", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
	d.RegisterTarget("c", core.Target{Exists: exists, Hide: hide, Restore: restore})
	d.MeExtra(func(ctx context.Context, id *core.Ident) []string {
		var n int64
		if err := d.DB.QueryRow(ctx, `SELECT saved_tokens FROM identities WHERE id = $1`, id.Root).Scan(&n); err != nil {
			return nil
		}
		return []string{"saved=" + Human(n)}
	})
}

func newSvc(d *core.Deps) *svc {
	m := hmac.New(sha256.New, d.Cfg.ServerSecret)
	m.Write([]byte("cx-cache-grp"))
	return &svc{d: d, grp: m.Sum(nil)}
}

// group hashes a reader's IP group for cache.groups (never the raw group).
func (s *svc) group(g string) []byte {
	m := hmac.New(sha256.New, s.grp)
	m.Write([]byte(g))
	return m.Sum(nil)[:16]
}

// --- keys ------------------------------------------------------------------------------------------

// Canonical is the default canonicalisation of an input (16.4 "NFC-lite, LF, trimmed"): the scrub
// normaliser (compatibility forms folded to ASCII, invisible code points removed; ASCII text is
// untouched), CRLF/CR -> LF, trailing blanks cut on every line, leading and trailing whitespace
// trimmed. Python: "\n".join(l.rstrip() for l in s.replace("\r\n","\n").replace("\r","\n").split("\n")).strip()
func Canonical(in string) string {
	s := strings.ReplaceAll(strings.ReplaceAll(scrub.Normalize(in), "\r\n", "\n"), "\r", "\n")
	if strings.ContainsAny(s, " \t") {
		lines := strings.Split(s, "\n")
		for i, l := range lines {
			lines[i] = strings.TrimRight(l, " \t")
		}
		s = strings.Join(lines, "\n")
	}
	return strings.TrimSpace(s)
}

// Key is sha256 hex of ns + "\n" + canonical, or ns + "@" + v + "\n" + canonical under a recipe
// version v > 0 (27.3).
func Key(ns, canonical string, v int) string {
	h := sha256.New()
	h.Write([]byte(ns))
	if v > 0 {
		h.Write([]byte("@" + strconv.Itoa(v)))
	}
	h.Write([]byte("\n"))
	h.Write([]byte(canonical))
	return hex.EncodeToString(h.Sum(nil))
}

// Derive runs the namespace recipe (CanonFn, else Canonical) and returns the key, the canonical
// input and the recipe version.
func Derive(ns, in string) (key, canonical string, v int) {
	if CanonFn != nil {
		canonical, v = CanonFn(ns, in)
	} else {
		canonical = Canonical(in)
	}
	return Key(ns, canonical, v), canonical, v
}

// --- rows ------------------------------------------------------------------------------------------

// Row is one cache row (16.4).
type Row struct {
	Key, NS, Out, Blob     string
	Attest, Job            string
	Producer, ProducerRoot string
	ProducerLvl            int
	CostTokens, Producers  int
	Conflict, Hidden       bool
	Hits, Groups           int
	Hazard                 []string
	Created, Expires       time.Time
	LastHit                time.Time // zero = never
}

const cols = `key, ns, out, coalesce(blob, ''), attest, job, producer, producer_root, producer_lvl, cost_tokens, producers,
	conflict, hidden, hits, cardinality(groups), hazard, created, expires_at, last_hit`

func scanRow(row interface{ Scan(dest ...any) error }) (*Row, error) {
	var x Row
	var last *time.Time
	if err := row.Scan(&x.Key, &x.NS, &x.Out, &x.Blob, &x.Attest, &x.Job, &x.Producer, &x.ProducerRoot, &x.ProducerLvl, &x.CostTokens,
		&x.Producers, &x.Conflict, &x.Hidden, &x.Hits, &x.Groups, &x.Hazard, &x.Created, &x.Expires, &last); err != nil {
		return nil, err
	}
	if last != nil {
		x.LastHit = *last
	}
	return &x, nil
}

// Line is the hit head: `hit job|claim by a… lvl=L2 tok=N <date> [conflict]`.
func (x *Row) Line() string {
	by := x.ProducerRoot
	if by == "" {
		by = "system"
	}
	l := fmt.Sprintf("hit %s by %s lvl=L%d tok=%d %s", x.Attest, by, x.ProducerLvl, x.CostTokens, core.Date(x.Created))
	if x.Conflict {
		l += " conflict"
	}
	return l
}

// Doc renders a hit for GET /v1/c/{key} and cget: the hit line, the output indented (or the blob
// path), the hazard families and the actions.
func (x *Row) Doc() *doc.Doc {
	d := &doc.Doc{Head: x.Line(), NoIndex: true, Title: "cached result", Canonical: "/c/" + x.Key}
	if len(x.Hazard) > 0 {
		d.Fields = append(d.Fields, doc.F{Name: "hazard", Val: scrub.HazardsLine(x.Hazard)})
	}
	if x.Blob != "" {
		d.Fields = append(d.Fields, doc.F{Name: "blob", Val: "/v1/b/" + x.Blob})
	} else {
		d.Fields = append(d.Fields, doc.F{Name: "out", Val: x.Out, Multi: true})
	}
	d.Next = []doc.Action{doc.GET("/c/"+x.Key, "raw"), doc.POST("/v1/report", "c:"+x.Key)}
	return d
}

// Get returns a live, visible row by key without counting a hit (brief and near-miss callers).
func Get(ctx context.Context, q core.Q, key string) (*Row, bool, error) {
	if !keyRe.MatchString(key) {
		return nil, false, nil
	}
	x, err := scanRow(q.QueryRow(ctx, `SELECT `+cols+` FROM cache WHERE key = $1 AND NOT hidden AND expires_at > now()`, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return x, true, nil
}

// --- reads -----------------------------------------------------------------------------------------

// readRes is the outcome of a counted read.
type readRes struct {
	row    *Row
	public bool // anonymous read of an L2+ producer's inline row: edge-cacheable
}

// read serves one key to reader (nil = anonymous from IP group grp) under the 16.4 rules: hidden,
// expired and unknown keys are the same 404; blob-backed rows need a token; an L0/L1 producer's
// row counts the anonymous reader's group and answers 404 once more than MaxGroups distinct
// groups read it (handoffs are point-to-point); authenticated hits extend the TTL and accrue
// cost_tokens to the producer once per (key, reader root, day) when the reader is a Distinct root.
func (s *svc) read(ctx context.Context, key string, reader *core.Ident, grp string) (readRes, error) {
	var res readRes
	if !keyRe.MatchString(key) {
		return res, core.ErrNotFound
	}
	wide := false
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		x, err := scanRow(tx.QueryRow(ctx, `SELECT `+cols+` FROM cache WHERE key = $1 AND expires_at > now() FOR UPDATE`, key))
		if errors.Is(err, pgx.ErrNoRows) {
			return core.ErrNotFound
		}
		if err != nil {
			return err
		}
		if x.Hidden {
			return core.ErrNotFound
		}
		res.row = x
		if reader == nil {
			if x.Blob != "" {
				return core.ErrAuth
			}
			if x.ProducerLvl >= 2 {
				res.public = true
				_, err := tx.Exec(ctx, `UPDATE cache SET hits = hits + 1, last_hit = now() WHERE key = $1`, key)
				return err
			}
			var groups int
			if err := tx.QueryRow(ctx, `UPDATE cache SET hits = hits + 1, last_hit = now(),
				groups = CASE WHEN $2::bytea = ANY (groups) OR cardinality(groups) > $3 THEN groups ELSE array_append(groups, $2::bytea) END
				WHERE key = $1 RETURNING cardinality(groups)`, key, s.group(grp), MaxGroups).Scan(&groups); err != nil {
				return err
			}
			wide = groups > MaxGroups // the 4th network is recorded (the commit must stand) and not served
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE cache SET hits = hits + 1, last_hit = now(), expires_at = greatest(expires_at, now() + $2::interval) WHERE key = $1`,
			key, pgInterval(TTL)); err != nil {
			return err
		}
		if x.ProducerRoot == "" || x.ProducerRoot == reader.Root || x.CostTokens <= 0 {
			return nil
		}
		tag, err := tx.Exec(ctx, `INSERT INTO cache_hits (key, root) VALUES ($1, $2) ON CONFLICT DO NOTHING`, key, reader.Root)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		distinct, err := trust.Distinct(ctx, tx, x.ProducerRoot, reader.Root)
		if err != nil || !distinct {
			return err
		}
		return Accrue(ctx, tx, x.ProducerRoot, "cache", x.CostTokens)
	})
	if err != nil {
		return readRes{}, err
	}
	if wide {
		return readRes{}, core.ErrNotFound
	}
	return res, nil
}

// --- writes ----------------------------------------------------------------------------------------

// putIn is one cput: either in (canonicalised through the namespace recipe) or an explicit key.
type putIn struct {
	ns, in, key string
	out         string
	cost        int
	id          *core.Ident
	ip          string
}

// putOut is what a cput changed.
type putOut struct {
	key      string
	created  bool
	conflict bool
	masked   []string
	hazard   []string
}

// Line is `ok <key>[ conflict][ masked=…][ hazard=…]`.
func (o putOut) Line() string {
	l := "ok " + o.key
	if o.conflict {
		l += " conflict"
	}
	if len(o.masked) > 0 {
		l += " masked=" + strings.Join(o.masked, ",")
	}
	if len(o.hazard) > 0 {
		l += " hazard=" + strings.Join(o.hazard, ",")
	}
	return l
}

// resolveKey validates ns/in/key and derives the key (exactly one of in or key).
func resolveKey(ns, in, key string) (k, canonical string, err error) {
	switch {
	case key != "" && in != "":
		return "", "", core.Bad("give in or key, not both")
	case key != "":
		key = strings.ToLower(key)
		if !keyRe.MatchString(key) {
			return "", "", errKey
		}
		if ns != "" && !nsRe.MatchString(ns) {
			return "", "", errNS
		}
		return key, "", nil
	case in == "":
		return "", "", core.Bad("in or key required")
	case !nsRe.MatchString(ns):
		return "", "", errNS
	case len(in) > MaxIn:
		return "", "", core.ErrSize
	}
	k, canonical, _ = Derive(ns, in)
	if canonical == "" {
		return "", "", core.Bad("in is empty after canonicalisation")
	}
	return k, canonical, nil
}

// put is the cput transaction (16.4): validation, sealed refusal, scrub (tier 1 rejects with the
// leak link, tier 2 masks), hazards (exec-remote/obfuscated-exec refused from L0), daily quota,
// level caps on live rows and inline bytes, then insert / agree / conflict / own-row update.
func (s *svc) put(ctx context.Context, in *putIn) (putOut, error) {
	var out putOut
	if s.d.Frozen("cache") {
		return out, core.Frozen("cache")
	}
	key, canonical, err := resolveKey(in.ns, in.in, in.key)
	if err != nil {
		return out, err
	}
	out.key = key
	if strings.TrimSpace(in.out) == "" {
		return out, core.Bad("out required")
	}
	if len(in.out) > MaxOut {
		return out, core.ErrSize
	}
	if !utf8.ValidString(in.out) {
		return out, core.Bad("out must be UTF-8 text")
	}
	if sealedRe.MatchString(strings.TrimSpace(in.out)) {
		return out, errSealed
	}
	if in.cost < 0 || in.cost > MaxCost {
		return out, core.Bad(fmt.Sprintf("cost_tokens must be 0..%d", MaxCost))
	}
	body, preview := in.out, previewOf(canonical)
	fields := map[string]*string{"out": &body}
	if preview != "" {
		fields["in"] = &preview
	}
	if out.masked, err = check(ctx, s.d.DB, fields); err != nil {
		return out, err
	}
	body = strings.TrimRight(body, "\n")
	if body == "" {
		return out, core.Bad("out required")
	}
	if len(body) > MaxOut {
		return out, core.ErrSize
	}
	out.hazard = scrub.Hazards(body)
	cost := in.cost
	if cost == 0 {
		cost = min((len(canonical)+len(body))/4, MaxCost)
	}
	root, ref := in.id.Root, key[:16]
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "cache:"+root); err != nil {
			return err
		}
		if err := core.UseQuota(ctx, tx, in.id, "cput", DailyPuts); err != nil {
			return err
		}
		lvl := levelOf(ctx, tx, root)
		if lvl <= 0 {
			if h := refusedHazard(out.hazard); h != "" {
				return core.E(400, "hazard", h)
			}
		}
		prev, err := scanRow(tx.QueryRow(ctx, `SELECT `+cols+` FROM cache WHERE key = $1 FOR UPDATE`, key))
		exists := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if exists && !prev.Expires.After(time.Now()) {
			if _, err := tx.Exec(ctx, `DELETE FROM cache WHERE key = $1`, key); err != nil {
				return err
			}
			exists = false
		}
		own := exists && prev.Attest == "claim" && prev.ProducerRoot == root
		if !exists || own {
			var n, bytes int
			if err := tx.QueryRow(ctx, `SELECT count(*), coalesce(sum(octet_length(out)), 0) FROM cache WHERE producer_root = $1 AND key <> $2 AND expires_at > now()`, root, key).Scan(&n, &bytes); err != nil {
				return err
			}
			if n+1 > trust.Cap("cache_rows", lvl) || bytes+len(body) > trust.Cap("cache_bytes", lvl) {
				return core.ErrQuota
			}
		}
		switch {
		case !exists:
			if _, err := tx.Exec(ctx, `INSERT INTO cache (key, ns, out, attest, producer, producer_root, producer_lvl, cost_tokens, hazard, scrub_v, expires_at)
				VALUES ($1, $2, $3, 'claim', $4, $5, $6, $7, $8, $9, now() + $10::interval)`,
				key, in.ns, body, in.id.ID, root, lvl, cost, hazardArr(out.hazard), scrub.RulesV, pgInterval(TTL)); err != nil {
				return err
			}
			out.created = true
			if err := core.Origin(ctx, tx, "c", key, root, in.id.ID, in.ip); err != nil {
				return err
			}
		case own:
			// The producer may replace its own claim (an undeclared cost keeps the declared one).
			if in.cost == 0 {
				cost = prev.CostTokens
			}
			if _, err := tx.Exec(ctx, `UPDATE cache SET out = $2, producer = $3, producer_lvl = $4, cost_tokens = $5, hazard = $6, scrub_v = $7,
				expires_at = greatest(expires_at, now() + $8::interval) WHERE key = $1`,
				key, body, in.id.ID, lvl, cost, hazardArr(out.hazard), scrub.RulesV, pgInterval(TTL)); err != nil {
				return err
			}
			out.conflict = prev.Conflict
		case prev.Blob == "" && prev.Out == body:
			// Another producer agrees: the row keeps the first result and counts the producer.
			if _, err := tx.Exec(ctx, `UPDATE cache SET producers = producers + 1, expires_at = greatest(expires_at, now() + $2::interval) WHERE key = $1`, key, pgInterval(TTL)); err != nil {
				return err
			}
			out.conflict = prev.Conflict
		default:
			// A different result for the same key: the first stays, the row is flagged (a job row is
			// never overwritten) and the first producer learns about it through its news.
			if _, err := tx.Exec(ctx, `UPDATE cache SET conflict = true, producers = producers + 1 WHERE key = $1`, key); err != nil {
				return err
			}
			out.conflict = true
			if !prev.Conflict && prev.ProducerRoot != "" {
				if err := core.Event(ctx, tx, "cache", key, prev.ProducerRoot, "conflict"); err != nil {
					return err
				}
			}
		}
		if preview != "" && (out.created || own) && hasPreview(ctx, tx) {
			if _, err := tx.Exec(ctx, `UPDATE cache SET in_preview = $2 WHERE key = $1`, key, preview); err != nil {
				return err
			}
		}
		return core.Audit(ctx, tx, in.id.ID, "cput", ref, len(body))
	})
	return out, err
}

// previewOf is the stored preview of a canonical input (27.3): one safe line of <= MaxPreview runes.
func previewOf(canonical string) string {
	if canonical == "" {
		return ""
	}
	p := doc.SafeLine(canonical)
	if utf8.RuneCountInString(p) > MaxPreview {
		p = string([]rune(p)[:MaxPreview])
	}
	return strings.TrimSpace(p)
}

// previewCol remembers whether cache.in_preview exists (migration 0151, cache namespaces).
var previewCol struct {
	sync.Mutex
	checked, has bool
}

func hasPreview(ctx context.Context, q core.Q) bool {
	previewCol.Lock()
	defer previewCol.Unlock()
	if previewCol.checked {
		return previewCol.has
	}
	var has bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'cache' AND column_name = 'in_preview')`).Scan(&has); err != nil {
		return false
	}
	previewCol.checked, previewCol.has = true, has
	return has
}

// PutJob mirrors a finalized, attested compute result (compute.CacheJobFn, 14.1 / 16.4): a job row
// whose output is the blob hash (inline text when out is not a hash), producer = the job's
// submitter. A job row is never overwritten; a different result for an existing key flags it.
func PutJob(ctx context.Context, q core.Q, key, jobID, out string, cost int) error {
	key = strings.ToLower(key)
	if !keyRe.MatchString(key) {
		return errKey
	}
	if out == "" {
		return core.Bad("out required")
	}
	cost = min(max(cost, 0), MaxCost)
	blob, text := "", ""
	if keyRe.MatchString(out) {
		blob = out
	} else {
		if !utf8.ValidString(out) || len(out) > MaxOut {
			return core.ErrSize
		}
		text = out
	}
	var producer, root string
	err := q.QueryRow(ctx, `SELECT submitter, root FROM jobs WHERE id = $1`, jobID).Scan(&producer, &root)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	lvl := 0
	if root != "" {
		lvl = levelOf(ctx, q, root)
	}
	return inTx(ctx, q, func(tx core.Q) error {
		prev, err := scanRow(tx.QueryRow(ctx, `SELECT `+cols+` FROM cache WHERE key = $1 FOR UPDATE`, key))
		switch {
		case errors.Is(err, pgx.ErrNoRows) || (err == nil && !prev.Expires.After(time.Now())):
			_, err = tx.Exec(ctx, `INSERT INTO cache (key, out, blob, attest, job, producer, producer_root, producer_lvl, cost_tokens, hazard, scrub_v, expires_at)
				VALUES ($1, $2, nullif($3, ''), 'job', $4, $5, $6, $7, $8, $9, $10, now() + $11::interval)
				ON CONFLICT (key) DO UPDATE SET out = EXCLUDED.out, blob = EXCLUDED.blob, attest = 'job', job = EXCLUDED.job, producer = EXCLUDED.producer,
				  producer_root = EXCLUDED.producer_root, producer_lvl = EXCLUDED.producer_lvl, cost_tokens = EXCLUDED.cost_tokens, hazard = EXCLUDED.hazard,
				  scrub_v = EXCLUDED.scrub_v, producers = 1, conflict = false, hits = 0, groups = '{}', created = now(), expires_at = EXCLUDED.expires_at`,
				key, text, blob, jobID, producer, root, lvl, cost, hazardArr(scrub.Hazards(text)), scrub.RulesV, pgInterval(TTL))
			return err
		case err != nil:
			return err
		case prev.Blob == blob && prev.Out == text:
			_, err = tx.Exec(ctx, `UPDATE cache SET producers = producers + 1, expires_at = greatest(expires_at, now() + $2::interval) WHERE key = $1`, key, pgInterval(TTL))
			return err
		case prev.Attest == "claim":
			// An attested result replaces an unattested claim for the same key; a disagreeing claim
			// leaves the conflict flag on.
			_, err = tx.Exec(ctx, `UPDATE cache SET out = $2, blob = nullif($3, ''), attest = 'job', job = $4, producer = $5, producer_root = $6, producer_lvl = $7,
				cost_tokens = $8, hazard = $9, scrub_v = $10, producers = producers + 1, conflict = true, expires_at = greatest(expires_at, now() + $11::interval) WHERE key = $1`,
				key, text, blob, jobID, producer, root, lvl, cost, hazardArr(scrub.Hazards(text)), scrub.RulesV, pgInterval(TTL))
			return err
		default:
			_, err = tx.Exec(ctx, `UPDATE cache SET conflict = true, producers = producers + 1 WHERE key = $1`, key)
			return err
		}
	})
}

// --- housekeeping ----------------------------------------------------------------------------------

// Expire deletes expired rows (batches of 5000), rows hidden by reports for more than 30 d, the
// accrual guards older than a day and saved-ledger days past retention (janitor task cache_expire).
func Expire(ctx context.Context, q core.Q) error {
	for i := 0; i < 20; i++ {
		tag, err := q.Exec(ctx, `DELETE FROM cache WHERE key IN (SELECT key FROM cache WHERE expires_at <= now() LIMIT 5000)`)
		if err != nil {
			return err
		}
		if tag.RowsAffected() < 5000 {
			break
		}
	}
	if _, err := q.Exec(ctx, `DELETE FROM cache WHERE hidden AND hidden_at < now() - $1::interval`, pgInterval(HiddenPurge)); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `DELETE FROM cache_hits WHERE day < current_date - 1`); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `DELETE FROM saved WHERE day < current_date - $1::int`, int(SavedKeep/(24*time.Hour)))
	return err
}

// purge deletes a root's rows (OnPurge): produced rows, its ledger days and accrual guards.
func purge(ctx context.Context, q core.Q, root string) error {
	for _, sql := range []string{
		`DELETE FROM cache WHERE producer_root = $1`,
		`DELETE FROM saved WHERE root = $1`,
		`DELETE FROM cache_hits WHERE root = $1`,
	} {
		if _, err := q.Exec(ctx, sql, root); err != nil {
			return err
		}
	}
	return nil
}

// Report target c:<key> (4.7): exists while live, hide keeps the row for the appeal window,
// restore lifts the hide.
func exists(ctx context.Context, q core.Q, ref string) error {
	ref = strings.ToLower(ref)
	if !keyRe.MatchString(ref) {
		return core.ErrNotFound
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cache WHERE key = $1 AND expires_at > now())`, ref).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func hide(ctx context.Context, q core.Q, ref string) error {
	ref = strings.ToLower(ref)
	if !keyRe.MatchString(ref) {
		return core.ErrNotFound
	}
	_, err := q.Exec(ctx, `UPDATE cache SET hidden = true, hidden_at = coalesce(hidden_at, now()) WHERE key = $1`, ref)
	return err
}

func restore(ctx context.Context, q core.Q, ref string) error {
	ref = strings.ToLower(ref)
	if !keyRe.MatchString(ref) {
		return core.ErrNotFound
	}
	_, err := q.Exec(ctx, `UPDATE cache SET hidden = false, hidden_at = NULL WHERE key = $1`, ref)
	return err
}

// --- helpers ---------------------------------------------------------------------------------------

// levelOf is the root's standing level clamped to the caps table (L0 until trust installs LevelFn).
func levelOf(ctx context.Context, q core.Q, root string) int {
	return min(max(core.Level(ctx, q, root), 0), 3)
}

// hazardArr keeps hazard columns NOT NULL-friendly (nil -> empty array).
func hazardArr(h []string) []string {
	if h == nil {
		return []string{}
	}
	return h
}

// pgInterval renders a duration as a Postgres interval literal ("86400 seconds").
func pgInterval(d time.Duration) string {
	return strconv.FormatInt(int64(d/time.Second), 10) + " seconds"
}

// inTx runs fn atomically on q: a pool or connection opens a transaction, a transaction a
// savepoint, so the exported service functions behave the same whatever q they receive.
func inTx(ctx context.Context, q core.Q, fn func(q core.Q) error) error {
	b, ok := q.(interface {
		Begin(ctx context.Context) (pgx.Tx, error)
	})
	if !ok {
		return fn(q)
	}
	tx, err := b.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
