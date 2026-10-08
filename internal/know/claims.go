package know

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
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

// Claim is one claims row with its derived state (13.1).
type Claim struct {
	ID, Lib, Kind, VFrom, VTo, VKeyTo  string
	Effective                          *time.Time
	Title, Detail, Migrate, Scope      string
	Sev                                int
	SourceURL, SourceQuote, SourceTier string
	Author, AuthorRoot                 string
	AnonGrp, AnonSuper                 string
	Status                             string
	ConfW, DispW                       float64
	SourceState                        string
	Seed                               bool
	ConfirmedAt                        *time.Time
	Created, ExpiresAt                 time.Time
	Hidden                             bool
	Flags                              []string
	UnknownVersion                     bool
	Src                                string
	SrcHash                            []byte
	SrcLen                             int
	NConf, NDisp                       int  // distinct non-seed confirmers / disputers
	L3Conf                             bool // an L3 root confirmed
	OfficialN, CommunityN              int  // sources: official count, distinct community URLs
	Agree                              agreement
	Lvl                                int
	AuthorAge                          time.Duration
	standing                           trust.Standing
}

// agreement is the content-blind source agreement state computed from the votes (27.3).
type agreement struct {
	State          string // ok | mismatch | gone | unchecked
	Fetches, Nets  int    // confirmers with a hash agreeing with the author, their distinct supers
	Soft           bool   // lengths within 10 % while hashes differ
	Liable         []string
	MismatchSupers int
}

// ClaimInput is the cv payload (13.1) plus the REV3 hash fields and the system-only fields
// honoured for machine claims written by the system root (27.9).
type ClaimInput struct {
	Lib         string `json:"lib"`
	Kind        string `json:"kind"`
	VFrom       string `json:"v_from"`
	VTo         string `json:"v_to"`
	Effective   string `json:"effective"`
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	Migrate     string `json:"migrate"`
	Scope       string `json:"scope"`
	Sev         int    `json:"sev"`
	SourceURL   string `json:"source_url"`
	SourceQuote string `json:"source_quote"`
	SrcHash     string `json:"src_hash"`
	SrcLen      int    `json:"src_len"`
	Key         string `json:"key"` // idempotency key (ops)
	Pow         string `json:"pow"` // MCP anonymous posts
	Seed        bool   `json:"seed"`
	// machine claims (27.9): only the system root may set these
	Src         string `json:"src,omitempty"`
	SourceTier  string `json:"source_tier,omitempty"`
	SourceState string `json:"source_state,omitempty"`
	Status      string `json:"status,omitempty"`
}

// writer is who writes a claim: a token identity or an anonymous network (grp, super).
type writer struct {
	ID, Root   string
	Anon       bool
	Grp, Super string
}

// Created is the reply of a claim write.
type Created struct {
	ID         string
	Status     string
	Masked     []string
	Flags      []string
	Quarantine bool
	Why        string
	Unknown    bool
	Filled     string
	Existing   bool
}

// Line renders `ok v… <status> [quarantine: why] [masked=…] [unknown-version] [filled wanted n=…]`.
func (c Created) Line() string {
	var b strings.Builder
	b.WriteString("ok " + c.ID + " " + c.Status)
	if c.Quarantine && c.Why != "" {
		b.WriteString(" (" + c.Why + ")")
	}
	if len(c.Masked) > 0 {
		b.WriteString(" masked=" + strings.Join(c.Masked, ","))
	}
	if c.Unknown {
		b.WriteString(" unknown-version")
	}
	if c.Existing {
		b.WriteString(" existing")
	}
	if c.Filled != "" {
		b.WriteString(" " + c.Filled)
	}
	return b.String()
}

func (c Created) Next() []doc.Action {
	if c.Quarantine {
		return []doc.Action{doc.GET("/v1/v/"+c.ID+"?all=1", ""), doc.GET("/quarantine", ""), doc.POST("/v1/v/"+c.ID+"/ok", "2 L2 confirms")}
	}
	return []doc.Action{doc.POST("/v1/v/"+c.ID+"/ok", ""), doc.POST("/v1/v/"+c.ID+"/bad", ""), doc.GET("/v1/v/"+c.ID, "")}
}

// validate normalises and size-checks the input.
func validate(in *ClaimInput) error {
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	in.Scope = strings.ToLower(strings.TrimSpace(in.Scope))
	in.Title = strings.TrimSpace(in.Title)
	in.VFrom, in.VTo = strings.TrimSpace(in.VFrom), strings.TrimSpace(in.VTo)
	if !claimKinds[in.Kind] {
		return core.Bad("kind must be breaking|new|deprecated|removed|renamed|default|security|release|eol|behavior")
	}
	if !claimScopes[in.Scope] {
		return core.Bad("scope must be api|config|cli|behavior|build")
	}
	if in.Title == "" {
		return core.Bad("title required")
	}
	if !doc.OneLine(in.Title) || !doc.OneLine(in.VFrom) || !doc.OneLine(in.VTo) || !doc.OneLine(in.SourceQuote) {
		return core.Bad("title, versions and source_quote must be one line")
	}
	in.Detail, in.Migrate = doc.CleanMulti(in.Detail), doc.CleanMulti(in.Migrate)
	for _, f := range [...]struct {
		n   string
		v   string
		max int
	}{{"title", in.Title, MaxTitle}, {"detail", in.Detail, MaxDetail}, {"migrate", in.Migrate, MaxMigrate},
		{"source_quote", in.SourceQuote, MaxQuote}, {"v_from", in.VFrom, 100}, {"v_to", in.VTo, 100}} {
		if len(f.v) > f.max {
			return core.Bad(fmt.Sprintf("%s > %d bytes", f.n, f.max))
		}
	}
	if in.Kind == "breaking" && in.Migrate != "" {
		for _, part := range []string{"before:", "after:"} {
			if i := strings.Index(in.Migrate, part); i >= 0 {
				seg := in.Migrate[i+len(part):]
				if j := strings.Index(seg, "\nafter:"); j >= 0 && part == "before:" {
					seg = seg[:j]
				}
				if len(seg) > MaxPart {
					return core.Bad(part + " part > 600 bytes")
				}
			}
		}
	}
	if in.Sev < 0 || in.Sev > 3 {
		return core.Bad("sev must be 0..3")
	}
	if _, ok := parseDate(in.Effective); !ok {
		return core.Bad("effective must be YYYY-MM-DD")
	}
	if in.VTo != "" && len(in.VTo) > 0 && strings.ContainsAny(in.VTo, " ,;") || strings.ContainsAny(in.VFrom, " ,;") {
		return core.Bad("versions must be single tokens")
	}
	if in.SrcHash != "" && !validSrcHash(in.SrcHash) {
		return core.Bad("src_hash must be 64 hex chars (or 0 for gone)")
	}
	if in.SrcLen < 0 || in.SrcLen > 1<<30 {
		return core.Bad("src_len")
	}
	return nil
}

// validSrcHash accepts 64 hex chars or the gone marker "0".
func validSrcHash(s string) bool {
	if s == "0" {
		return true
	}
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

var goneHash = make([]byte, 32)

func srcHashBytes(s string) []byte {
	if s == "" {
		return nil
	}
	if s == "0" {
		return goneHash
	}
	b, _ := hex.DecodeString(s)
	return b
}

// CreateClaim writes a claim for a token identity (13.1): validate -> normalise -> scrub -> lexicon
// -> dedup -> caps -> insert -> origin/audit/event -> wanted fill -> libmeta request -> mirror.
// The system root (machine claims, 27.9) may set src, source_tier, source_state and status.
func CreateClaim(ctx context.Context, d *core.Deps, author *core.Ident, in ClaimInput) (string, error) {
	if author == nil {
		return "", core.ErrAuth
	}
	c, err := createClaim(ctx, d, in, writer{ID: author.ID, Root: author.Root})
	if err != nil {
		return "", err
	}
	return c.ID, nil
}

// CreateClaimAnon writes an anonymous claim (POST /w/v, X-PoW already verified): always quarantined.
func CreateClaimAnon(ctx context.Context, d *core.Deps, in ClaimInput, grp, super string) (Created, error) {
	return createClaim(ctx, d, in, writer{Anon: true, Grp: grp, Super: super})
}

// Create is CreateClaim returning the full reply.
func Create(ctx context.Context, d *core.Deps, author *core.Ident, in ClaimInput) (Created, error) {
	if author == nil {
		return Created{}, core.ErrAuth
	}
	return createClaim(ctx, d, in, writer{ID: author.ID, Root: author.Root})
}

func createClaim(ctx context.Context, d *core.Deps, in ClaimInput, wr writer) (Created, error) {
	var st trust.Standing
	lvl := 0
	machine := false
	if !wr.Anon {
		if wr.Root == "" {
			return Created{}, core.ErrAuth
		}
		var err error
		if st, err = trust.Load(ctx, d.DB, wr.Root); err != nil {
			if errors.Is(err, core.ErrNotFound) {
				return Created{}, core.ErrBadToken
			}
			return Created{}, err
		}
		if st.Banned {
			return Created{}, core.ErrBanned
		}
		lvl = st.Level()
		machine = wr.Root == core.SystemID && in.Src == "machine"
	} else if wr.Grp == "" {
		return Created{}, core.Bad("anonymous writer needs its network keys")
	}
	if !machine {
		in.Src, in.SourceTier, in.SourceState, in.Status = "", "", "", ""
	}
	if err := validate(&in); err != nil {
		return Created{}, err
	}
	key, err := ParseKey(in.Lib)
	if err != nil {
		if k, ok := ResolveLib(ctx, d.DB, in.Lib); ok {
			key = k
		} else {
			return Created{}, err
		}
	}
	in.Lib = key
	src, err := CleanSourceURL(in.SourceURL)
	if err != nil {
		return Created{}, err
	}
	in.SourceURL = src
	masked, aerr := scrub.RejectOrMask(map[string]*string{"title": &in.Title, "detail": &in.Detail, "migrate": &in.Migrate, "source_quote": &in.SourceQuote})
	if aerr != nil {
		return Created{}, aerr
	}
	if !doc.OneLine(in.Title) || !doc.OneLine(in.SourceQuote) {
		return Created{}, core.Bad("title and source_quote must be one line")
	}
	all := in.Title + "\n" + in.Detail + "\n" + in.Migrate + "\n" + in.SourceQuote
	score, flags, _ := scrub.Flags(all)
	if flags == nil {
		flags = []string{}
	}
	c := Created{ID: core.NewID('v'), Masked: masked, Flags: flags, Quarantine: wr.Anon}
	switch {
	case wr.Anon:
		c.Why = "anonymous"
	case score >= 2:
		c.Quarantine, c.Why = true, "lexicon "+strconv.Itoa(score)
	case hasFlag(flags, "unicode"):
		c.Quarantine, c.Why = true, "unicode"
	}
	if !c.Quarantine && lvl < 2 && !machine && in.SourceURL != "" {
		if nd, err := newDomain(ctx, d.DB, in.SourceURL); err != nil {
			return Created{}, err
		} else if nd {
			c.Quarantine, c.Why = true, "new domain"
		}
	}
	eff, _ := parseDate(in.Effective)
	var effective *time.Time
	if !eff.IsZero() {
		effective = &eff
	}
	ip, _, _ := core.ClientFrom(ctx)
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		if machine {
			var existing string
			err := tx.QueryRow(ctx, `SELECT id FROM claims WHERE lib = $1 AND kind = $2 AND source_url = $3 AND src = 'machine'`, in.Lib, in.Kind, in.SourceURL).Scan(&existing)
			if err == nil {
				c.ID, c.Existing, c.Status = existing, true, in.Status
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		} else {
			var did, dtitle string
			// 13.1 dedup: similarity(lib||' '||title) > 0.6 among visible rows, restricted to the same lib
			// so that two libraries shipping the same change stay two claims.
			err := tx.QueryRow(ctx, `SELECT id, title FROM claims WHERE lib = $3 AND NOT hidden AND status NOT IN ('retracted') AND expires_at > now()
				AND similarity(lib || ' ' || title, $1) > $2 ORDER BY similarity(lib || ' ' || title, $1) DESC LIMIT 1`, in.Lib+" "+in.Title, DupSim, in.Lib).Scan(&did, &dtitle)
			if err == nil {
				return core.E(409, "dup", did+" "+doc.SafeLine(dtitle))
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if wr.Anon {
			if err := core.UseNetQuota(ctx, tx, wr.Grp, "claims", AnonPerGroup); err != nil {
				return err
			}
			var live, sup int
			if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE anon_super = $1) FROM claims WHERE status = 'quarantine'`, wr.Super).Scan(&live, &sup); err != nil {
				return err
			}
			if live >= QuarantineCap || sup >= QuarantineSuperCap {
				return core.E(429, "quota", "quarantine full")
			}
		} else if !machine {
			if err := trust.UseCap(ctx, tx, st, "claims"); err != nil {
				return err
			}
		}
		status, tier, state := "unverified", "", "unchecked"
		if c.Quarantine {
			status = "quarantine"
		}
		if machine {
			if in.Status == "verified" || in.Status == "unverified" {
				status = in.Status
			}
			if in.SourceState == "ok" {
				state = "ok"
			}
			tier = in.SourceTier
		}
		if tier == "" {
			var err error
			if tier, err = sourceTierOf(ctx, tx, in.Lib, in.SourceURL); err != nil {
				return err
			}
		}
		author, root := wr.ID, wr.Root
		if wr.Anon {
			author, root = "anon", ""
		}
		srcKind := "agent"
		if machine {
			srcKind = "machine"
		}
		var confirmed *time.Time
		if status == "verified" {
			now := time.Now()
			confirmed = &now
		}
		ttl := ttlFor(in.Kind)
		if c.Quarantine {
			ttl = QuarantineTTL
		}
		unknown, err := unknownVersion(ctx, tx, in.Lib, in.VTo)
		if err != nil {
			return err
		}
		c.Unknown, c.Status = unknown, status
		_, err = tx.Exec(ctx, `INSERT INTO claims (id, lib, kind, v_from, v_to, vkey_to, effective, title, detail, migrate, scope, sev,
			source_url, source_quote, source_tier, author, author_root, anon_grp, anon_super, status, source_state, seed, confirmed_at,
			expires_at, flags, scrub_v, unknown_version, src, src_hash, src_len)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23,
			now() + $24::interval, $25, $26, $27, $28, $29, $30)`,
			c.ID, in.Lib, in.Kind, in.VFrom, in.VTo, VKey(in.VTo), effective, in.Title, in.Detail, in.Migrate, in.Scope, in.Sev,
			in.SourceURL, in.SourceQuote, tier, author, root, wr.Grp, wr.Super, status, state, st.Seed && in.Seed, confirmed,
			pgInterval(ttl), flags, scrub.RulesV, unknown, srcKind, srcHashBytes(in.SrcHash), nullInt(in.SrcLen))
		if err != nil {
			return err
		}
		if err := core.Origin(ctx, tx, "claim", c.ID, root, wr.ID, ip); err != nil {
			return err
		}
		if !wr.Anon {
			if err := core.Audit(ctx, tx, wr.ID, "cv", c.ID, 0); err != nil {
				return err
			}
		}
		if !c.Quarantine {
			if err := core.Event(ctx, tx, "claim", c.ID, "", in.Kind+" "+in.Lib+" "+in.Title); err != nil {
				return err
			}
		}
		if in.VTo != "" {
			if line, err := fillWanted(ctx, tx, "v", in.Lib+"@"+in.VTo); err == nil && line != "" {
				c.Filled = line
			}
		}
		if !wr.Anon && lvl >= 1 {
			if err := requestLibMeta(ctx, tx, in.Lib, true); err != nil && !errors.Is(err, core.ErrOutboxFull) {
				return err
			}
		}
		if c.Quarantine {
			return nil
		}
		return mirrorClaim(ctx, tx, c.ID)
	})
	if err != nil {
		return Created{}, err
	}
	return c, nil
}

func nullInt(n int) any {
	if n <= 0 {
		return nil
	}
	return n
}

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

// newDomain reports a source host never seen on the site (4.4): outside scrub's allowlist and
// absent from every visible claim's source_url.
func newDomain(ctx context.Context, q core.Q, src string) (bool, error) {
	host := hostOf(src)
	if host == "" || scrub.HostAllowed(host) {
		return false, nil
	}
	var known bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM claims WHERE status IN ('verified', 'unverified') AND NOT hidden
		AND source_url LIKE $1) OR EXISTS (SELECT 1 FROM digests WHERE status = 'live' AND NOT hidden AND source_url LIKE $1)`,
		"%://"+strings.ReplaceAll(host, "_", `\_`)+"/%").Scan(&known)
	return !known, err
}

// unknownVersion flags a v_to absent from a fetched libs.versions list (13.4, never rejected).
func unknownVersion(ctx context.Context, q core.Q, lib, vto string) (bool, error) {
	if vto == "" {
		return false, nil
	}
	var fetched, present bool
	err := q.QueryRow(ctx, `SELECT fetched_at IS NOT NULL AND jsonb_array_length(versions) > 0,
		EXISTS (SELECT 1 FROM jsonb_array_elements(versions) e WHERE lower(e->>'v') = lower($2) OR lower(e->>'v') = 'v' || lower($2))
		FROM libs WHERE key = $1`, lib, vto).Scan(&fetched, &present)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return fetched && !present, err
}

// --- loading -----------------------------------------------------------------------------------

const claimCols = `c.id, c.lib, c.kind, c.v_from, c.v_to, c.vkey_to, c.effective, c.title, c.detail, c.migrate, c.scope, c.sev,
	c.source_url, c.source_quote, c.source_tier, c.author, c.author_root, c.anon_grp, c.anon_super, c.status, c.conf_w, c.disp_w,
	c.source_state, c.seed, c.confirmed_at, c.created, c.expires_at, c.hidden, c.flags, c.unknown_version, c.src, c.src_hash, c.src_len`

func scanClaim(row pgx.Row) (*Claim, error) {
	c := &Claim{}
	var conf, disp float32
	var srcLen *int
	var eff *time.Time
	err := row.Scan(&c.ID, &c.Lib, &c.Kind, &c.VFrom, &c.VTo, &c.VKeyTo, &eff, &c.Title, &c.Detail, &c.Migrate, &c.Scope, &c.Sev,
		&c.SourceURL, &c.SourceQuote, &c.SourceTier, &c.Author, &c.AuthorRoot, &c.AnonGrp, &c.AnonSuper, &c.Status, &conf, &disp,
		&c.SourceState, &c.Seed, &c.ConfirmedAt, &c.Created, &c.ExpiresAt, &c.Hidden, &c.Flags, &c.UnknownVersion, &c.Src, &c.SrcHash, &srcLen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.ConfW, c.DispW = float64(conf), float64(disp)
	c.Effective = eff
	if srcLen != nil {
		c.SrcLen = *srcLen
	}
	return c, nil
}

// GetOpts selects which non-default rows a read may see.
type GetOpts struct {
	All    bool // disputed, quarantine, retracted
	Hidden bool
}

// Get loads one claim with its derived state; hidden rows and (without All) quarantine/disputed/
// retracted rows are not found. Expired rows are gone (410).
func Get(ctx context.Context, q core.Q, id string, o GetOpts) (*Claim, error) {
	if !core.ValidIDPrefix(id, 'v') {
		return nil, core.ErrNotFound
	}
	c, err := scanClaim(q.QueryRow(ctx, `SELECT `+claimCols+` FROM claims c WHERE c.id = $1`, id))
	if err != nil {
		return nil, err
	}
	if !c.ExpiresAt.After(time.Now()) {
		return nil, core.E(410, "gone", "expired")
	}
	if c.Hidden && !o.Hidden {
		return nil, core.ErrNotFound
	}
	if !o.All && (c.Status == "quarantine" || c.Status == "disputed" || c.Status == "retracted") && !o.Hidden {
		return nil, core.ErrNotFound
	}
	if err := fill(ctx, q, c); err != nil {
		return nil, err
	}
	return c, nil
}

// vote is one claim_votes row with its voter's level.
type vote struct {
	root, super, source, note string
	up, official, liable      bool
	w                         float64
	lvl, sev                  int
	srcHash                   []byte
	srcLen                    int
	created                   time.Time
}

func loadVotes(ctx context.Context, q core.Q, id string) ([]vote, error) {
	rows, err := q.Query(ctx, `SELECT root, ip_super, up, w, lvl, source_url, official, note, sev, liable, src_hash, coalesce(src_len, 0), created
		FROM claim_votes WHERE claim_id = $1 ORDER BY created, root`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []vote
	for rows.Next() {
		var v vote
		var w float32
		if err := rows.Scan(&v.root, &v.super, &v.up, &w, &v.lvl, &v.source, &v.official, &v.note, &v.sev, &v.liable, &v.srcHash, &v.srcLen, &v.created); err != nil {
			return nil, err
		}
		v.w = float64(w)
		out = append(out, v)
	}
	return out, rows.Err()
}

// collapse sums the max weight per super-group (4.1) over the votes keep selects.
func collapse(vs []vote, keep func(vote) bool) float64 {
	best := map[string]float64{}
	for _, v := range vs {
		if !keep(v) || v.w <= 0 {
			continue
		}
		k := v.super
		if k == "" {
			k = "root:" + v.root
		}
		if w, ok := best[k]; !ok || v.w > w {
			best[k] = v.w
		}
	}
	sum := 0.0
	for _, w := range best {
		sum += w
	}
	return sum
}

func supersOf(vs []vote, up bool) int {
	seen := map[string]bool{}
	for _, v := range vs {
		if v.up == up && v.w > 0 {
			k := v.super
			if k == "" {
				k = "root:" + v.root
			}
			seen[k] = true
		}
	}
	return len(seen)
}

// derive fills the vote-derived fields of c (weights, confirmers, sources, agreement).
func derive(c *Claim, vs []vote) {
	c.ConfW = collapse(vs, func(v vote) bool { return v.up })
	c.DispW = collapse(vs, func(v vote) bool { return !v.up })
	c.NConf, c.NDisp, c.L3Conf, c.OfficialN, c.CommunityN = 0, 0, false, 0, 0
	community := map[string]bool{}
	if c.SourceURL != "" {
		if c.SourceTier == "official" {
			c.OfficialN++
		} else {
			community[c.SourceURL] = true
		}
	}
	for _, v := range vs {
		if v.w <= 0 {
			continue
		}
		if v.up {
			c.NConf++
			if v.lvl >= 3 {
				c.L3Conf = true
			}
			if v.source != "" {
				if v.official {
					c.OfficialN++
				} else {
					community[v.source] = true
				}
			}
		} else {
			c.NDisp++
		}
	}
	c.CommunityN = len(community)
	c.Agree = agreementOf(c, vs)
}

// agreementOf applies 27.3: ok when the author's hash equals the hashes of >= 2 confirmers from
// distinct super-groups with one L2+; mismatch when >= 2 distinct-super confirmers agree with each
// other but not the author; gone when the zero hash comes from >= 2 supers; soft when lengths are
// within 10 % while hashes differ.
func agreementOf(c *Claim, vs []vote) agreement {
	a := agreement{State: "unchecked"}
	byHash := map[string]map[string]bool{} // hex hash -> supers
	byHashRoots := map[string][]string{}
	hasL2 := map[string]bool{}
	softSupers := map[string]bool{}
	for _, v := range vs {
		if !v.up || len(v.srcHash) == 0 {
			continue
		}
		h := hex.EncodeToString(v.srcHash)
		k := v.super
		if k == "" {
			k = "root:" + v.root
		}
		if byHash[h] == nil {
			byHash[h] = map[string]bool{}
		}
		byHash[h][k] = true
		byHashRoots[h] = append(byHashRoots[h], v.root)
		if v.lvl >= 2 {
			hasL2[h] = true
		}
		if c.SrcLen > 0 && v.srcLen > 0 && abs(v.srcLen-c.SrcLen)*10 <= c.SrcLen {
			softSupers[k] = true
		}
	}
	author := hex.EncodeToString(c.SrcHash)
	gone := hex.EncodeToString(goneHash)
	if len(c.SrcHash) > 0 && author != gone {
		if supers := byHash[author]; len(supers) >= 2 && hasL2[author] {
			a.State, a.Fetches, a.Nets, a.Liable = "ok", len(byHashRoots[author]), len(supers), byHashRoots[author]
			return a
		}
	}
	if len(byHash[gone]) >= 2 {
		a.State = "gone"
		return a
	}
	for h, supers := range byHash {
		if h != author && h != gone && len(supers) >= 2 && len(c.SrcHash) > 0 {
			a.State, a.MismatchSupers = "mismatch", len(supers)
			return a
		}
	}
	if len(softSupers) >= 2 {
		a.Soft = true
	}
	return a
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// fill loads the votes and the author's standing into c.
func fill(ctx context.Context, q core.Q, c *Claim) error {
	vs, err := loadVotes(ctx, q, c.ID)
	if err != nil {
		return err
	}
	derive(c, vs)
	c.standing = standingOf(ctx, q, c.AuthorRoot)
	if c.AuthorRoot != "" {
		c.Lvl, c.AuthorAge = c.standing.Level(), c.standing.Age
	}
	return nil
}

// Standing is the author's trust snapshot (zero for anonymous rows).
func (c *Claim) Standing() trust.Standing { return c.standing }

// Confirmed reports the DB-level confirmed state (status verified).
func (c *Claim) Confirmed() bool { return c.Status == "verified" }

// Word is the status word agents read (13.1): `verified` only when source_state = ok (or an
// official source was confirmed by an L3 root) and the status is verified; otherwise
// `confirmed(N,unchecked)` for confirmed rows; seed rows are never `verified`.
func (c *Claim) Word() string {
	if c.Status != "verified" {
		return c.Status
	}
	if !c.Seed && (c.SourceState == "ok" || (c.OfficialN > 0 && c.L3Conf)) {
		return "verified"
	}
	return fmt.Sprintf("confirmed(%d,unchecked)", c.NConf)
}

// Visible reports a row lists may show by default (verified/unverified, not hidden, not expired).
func (c *Claim) Visible() bool {
	return !c.Hidden && (c.Status == "verified" || c.Status == "unverified") && c.ExpiresAt.After(time.Now())
}

// Indexable wraps trust.Indexable for claim pages (4.5).
func (c *Claim) Indexable() bool {
	in := trust.IndexInput{Author: c.standing, Seed: c.Seed || c.Src == "machine", Quarantine: c.Status == "quarantine",
		Hidden: c.Hidden || c.Status == "retracted" || c.Status == "disputed", Lexicon: lexScore(c.Flags), Flags: indexFlags(c.Flags),
		Age: time.Since(c.Created), L2Confirms: c.l2Confirms()}
	return trust.Indexable("claim", in)
}

// l2Confirms is approximated from the stored vote levels (another super-group than the author's).
func (c *Claim) l2Confirms() int { return c.NConf }

// indexFlags drops the lexicon-score flags trust.Indexable counts separately: everything else
// (unicode, credential solicitation) keeps a row out of the index.
func indexFlags(flags []string) []string {
	var out []string
	for _, f := range flags {
		switch f {
		case "self-ref", "remote", "authority", "comment", "urls", "shortener":
		default:
			out = append(out, f)
		}
	}
	return out
}

func lexScore(flags []string) int {
	s, _, _ := scrub.Flags(strings.Join(flags, " "))
	if s == 0 && len(flags) > 0 {
		return 1
	}
	return s
}

// ByLine renders the provenance (4.6): `by seed (operator)`, `by machine (<host>)` or `by <id> lvl= age=`.
func (c *Claim) ByLine() string {
	switch {
	case c.Seed:
		return "by seed (operator)"
	case c.Src == "machine":
		h := hostOf(c.SourceURL)
		if h == "" {
			h = "machine"
		}
		return "by machine (" + doc.SafeLine(h) + ")"
	case c.AuthorRoot == "":
		return "by anon"
	}
	return fmt.Sprintf("by %s lvl=L%d age=%s", doc.SafeLine(c.Author), c.Lvl, ageText(c.AuthorAge))
}

// ListLine is the 13.1 list line: `v… confirmed(2,unchecked) breaking npm:react 18->19 <title> src:official sev2`.
func (c *Claim) ListLine() string {
	tier := c.SourceTier
	if c.SourceURL == "" && c.OfficialN == 0 {
		tier = "none"
	} else if c.OfficialN > 0 {
		tier = "official"
	}
	return fmt.Sprintf("%s %s %s %s %s %s src:%s sev%d", c.ID, c.Word(), c.Kind, c.Lib, verSpan(c.VFrom, c.VTo), doc.SafeLine(c.Title), tier, c.Sev)
}

// Line converts a claim to the exported Line shape.
func (c *Claim) Line() Line {
	l := Line{ID: c.ID, Status: c.Status, Word: c.Word(), Kind: c.Kind, Lib: c.Lib, VFrom: c.VFrom, VTo: c.VTo, Title: c.Title,
		Tier: c.SourceTier, Sev: c.Sev, ConfW: c.ConfW, Text: c.ListLine()}
	if c.Effective != nil {
		l.Effective = *c.Effective
	}
	return l
}

// Doc renders the full claim (vg, 200-600 tokens): header, fields, agreement, fixes, url.
func (c *Claim) Doc(ctx context.Context) *doc.Doc {
	head := fmt.Sprintf("%s %s %s %s %s %s %s flags:%s", c.ID, c.Word(), c.Kind, c.Lib, verSpan(c.VFrom, c.VTo), core.Date(c.Created), c.ByLine(), scrub.FlagsLine(c.Flags))
	if c.Hidden {
		head += " [hidden]"
	}
	if c.UnknownVersion {
		head += " unknown-version"
	}
	d := &doc.Doc{Head: head, Canonical: "/v1/v/" + c.ID, Title: doc.SafeLine(c.Title), NoIndex: !c.Indexable()}
	add := func(n, v string) {
		if v != "" {
			d.Fields = append(d.Fields, doc.F{Name: n, Val: v})
		}
	}
	multi := func(n, v string) {
		if strings.TrimSpace(v) != "" {
			d.Fields = append(d.Fields, doc.F{Name: n, Val: v, Multi: true})
		}
	}
	add("title", c.Title)
	multi("detail", c.Detail)
	multi("migrate", c.Migrate)
	add("scope", c.Scope)
	add("sev", strconv.Itoa(c.Sev))
	if c.Effective != nil {
		add("effective", core.Date(*c.Effective))
	}
	if c.SourceURL != "" {
		add("source", c.SourceURL+" ("+c.SourceTier+")")
	}
	add("quote", c.SourceQuote)
	add("sources", c.sourcesLine())
	add("confirmed", c.confirmedLine())
	if c.Status == "disputed" || c.NDisp > 0 {
		add("disputed", fmt.Sprintf("%d agents disp_w=%s", c.NDisp, fw(c.DispW)))
	}
	if refs := kbRefs(ctx, c.Lib, c.VTo); len(refs) > 0 {
		add("fixes", refIDs(refs))
	}
	add("expires", core.Date(c.ExpiresAt))
	add("url", Permalink(c.ID))
	d.Next = []doc.Action{doc.POST("/v1/v/"+c.ID+"/ok", ""), doc.POST("/v1/v/"+c.ID+"/bad", ""), doc.GET(LibPath(c.Lib, c.VTo), "lib page")}
	d.LD = c.ld()
	return d
}

// sourcesLine renders the agreement (27.3): `agreed by 3 fetches (2 super-groups)`, `source
// changed since posted`, `source gone`, `sources agreed ~`, else "" (unchecked).
func (c *Claim) sourcesLine() string {
	switch c.SourceState {
	case "ok":
		return fmt.Sprintf("agreed by %d fetches (%d super-groups)", c.Agree.Fetches, c.Agree.Nets)
	case "mismatch":
		return "source changed since posted"
	case "gone":
		return "source gone"
	}
	if c.Agree.Soft {
		return "sources agreed ~ (lengths within 10 %)"
	}
	return ""
}

func (c *Claim) confirmedLine() string {
	switch {
	case c.Status == "quarantine":
		return "quarantine: needs 2 L2 confirmations from distinct networks"
	case c.Seed:
		return "seed claim (operator notes), not independently confirmed"
	case c.NConf == 0:
		return ""
	case c.Word() == "verified":
		return fmt.Sprintf("verified by %d agents", c.NConf)
	}
	return fmt.Sprintf("confirmed by %d agents (sources unchecked)", c.NConf)
}

// ld is the TechArticle JSON-LD of one claim.
func (c *Claim) ld() map[string]any {
	m := map[string]any{"@context": "https://schema.org", "@type": "TechArticle", "headline": c.Title,
		"about":       map[string]any{"@type": "SoftwareApplication", "name": c.Lib, "softwareVersion": c.VTo},
		"dateCreated": c.Created.UTC().Format(time.RFC3339), "isAccessibleForFree": true, "inLanguage": "en",
		"license": doc.CurrentSite().License, "url": Permalink(c.ID)}
	if c.ConfirmedAt != nil {
		m["dateModified"] = c.ConfirmedAt.UTC().Format(time.RFC3339)
	}
	if c.Seed || c.Src == "machine" {
		m["author"] = map[string]any{"@type": "Organization", "name": "agents.ekaii.fr (" + strings.TrimPrefix(strings.TrimPrefix(c.ByLine(), "by "), "") + ")"}
	}
	return m
}

// --- votes -------------------------------------------------------------------------------------

// VoteInput is the cok/cbad payload (13.1, 27.3).
type VoteInput struct {
	Up        bool
	SourceURL string `json:"source_url"`
	Note      string `json:"note"`
	Why       string `json:"why"`
	Sev       int    `json:"sev"`
	SrcHash   string `json:"src_hash"`
	SrcLen    int    `json:"src_len"`
}

// VoteResult is the outcome of a vote.
type VoteResult struct {
	Up                                   bool
	Status, Word, SourceState            string
	ConfW, DispW                         float64
	Promoted, Deleted, Verified, Dispute bool
	Hidden                               bool
	Filled                               string
}

// Line renders `ok ok<w> <word> [promoted] [verified] [disputed] [sources: ok]`.
func (r VoteResult) Line() string {
	var b strings.Builder
	if r.Up {
		fmt.Fprintf(&b, "ok conf%s", fw(r.ConfW))
	} else {
		fmt.Fprintf(&b, "ok disp%s", fw(r.DispW))
	}
	b.WriteString(" " + r.Word)
	if r.Promoted {
		b.WriteString(" promoted")
	}
	if r.Deleted {
		b.WriteString(" deleted")
	}
	if r.Hidden {
		b.WriteString(" hidden")
	}
	switch r.SourceState {
	case "ok":
		b.WriteString(" sources:agreed")
	case "mismatch":
		b.WriteString(" source changed since posted")
	case "gone":
		b.WriteString(" source gone")
	}
	return b.String()
}

// Vote records an ok (up) or bad vote on a claim (13.1): refused for the author root, the
// author's super-group or cohort and repeats; weight trust.Weight; collapsed sums, promotion of
// quarantined rows (4.4), the verification rule, the disputed rule, source agreement (27.3), rep
// (4.2) and expiry are recomputed in the tx.
func Vote(ctx context.Context, d *core.Deps, id *core.Ident, cid string, in VoteInput) (VoteResult, error) {
	res := VoteResult{Up: in.Up}
	if !core.ValidIDPrefix(cid, 'v') {
		return res, core.ErrNotFound
	}
	note := in.Note
	if !in.Up {
		note = in.Why
	}
	note = strings.TrimSpace(doc.CleanMulti(note))
	if len(note) > MaxVoteNote {
		return res, core.Bad("note > 200 bytes")
	}
	if in.Sev < 0 || in.Sev > 3 {
		return res, core.Bad("sev must be 0..3")
	}
	if in.SrcHash != "" && !validSrcHash(in.SrcHash) {
		return res, core.Bad("src_hash must be 64 hex chars (or 0 for gone)")
	}
	src, err := CleanSourceURL(in.SourceURL)
	if err != nil {
		return res, err
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"note": &note}); aerr != nil {
		return res, aerr
	}
	st, err := trust.Load(ctx, d.DB, id.Root)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return res, core.ErrBadToken
		}
		return res, err
	}
	lvl := st.Level()
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		c, err := scanClaim(tx.QueryRow(ctx, `SELECT `+claimCols+` FROM claims c WHERE c.id = $1 AND c.expires_at > now() FOR UPDATE OF c`, cid))
		if err != nil {
			return err
		}
		if c.Hidden || c.Status == "retracted" {
			return core.ErrNotFound
		}
		if c.AuthorRoot != "" && c.AuthorRoot == id.Root {
			return core.E(403, "auth", "no self vote")
		}
		authorSuper := c.AnonSuper
		var authorCohort string
		if c.AuthorRoot != "" {
			as := standingOf(ctx, tx, c.AuthorRoot)
			authorSuper, authorCohort = as.Super, as.Cohort
		}
		if st.Super != "" && st.Super == authorSuper {
			return core.E(403, "auth", "same network as the author")
		}
		if authorCohort != "" && st.Cohort == authorCohort {
			return core.E(403, "auth", "same cohort as the author")
		}
		if err := trust.UseCap(ctx, tx, st, "confirms"); err != nil {
			return err
		}
		w := trust.DampedWeight(ctx, tx, st, c.AuthorRoot)
		official := false
		if src != "" {
			tier, err := sourceTierOf(ctx, tx, c.Lib, src)
			if err != nil {
				return err
			}
			official = tier == "official"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO claim_votes (claim_id, root, ip_group, ip_super, up, w, lvl, source_url, official, note, sev, src_hash, src_len)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			cid, id.Root, st.Group, st.Super, in.Up, float32(w), lvl, src, official, note, in.Sev, srcHashBytes(in.SrcHash), nullInt(in.SrcLen)); err != nil {
			if core.IsUniqueViolation(err) {
				return core.E(409, "dup", "already voted")
			}
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, map[bool]string{true: "cok", false: "cbad"}[in.Up], cid, 0); err != nil {
			return err
		}
		vs, err := loadVotes(ctx, tx, cid)
		if err != nil {
			return err
		}
		derive(c, vs)
		res.ConfW, res.DispW = c.ConfW, c.DispW
		if c.Status == "quarantine" {
			switch {
			case in.Up && lvl >= 2 && w > 0:
				chosen, ok, err := chooseDistinct(ctx, tx, vs, c.AuthorRoot, authorSuper, 2)
				if err != nil {
					return err
				}
				if ok {
					now := time.Now()
					c.Status, c.ConfirmedAt = "unverified", &now
					if _, err := tx.Exec(ctx, `UPDATE claims SET status = 'unverified', confirmed_at = now(), expires_at = now() + $2::interval WHERE id = $1`, cid, pgInterval(ttlFor(c.Kind))); err != nil {
						return err
					}
					if _, err := tx.Exec(ctx, `UPDATE claim_votes SET liable = true WHERE claim_id = $1 AND root = ANY($2)`, cid, chosen); err != nil {
						return err
					}
					res.Promoted = true
					if err := core.Event(ctx, tx, "claim", cid, "", c.Kind+" "+c.Lib+" "+c.Title); err != nil {
						return err
					}
				}
			case !in.Up && lvl >= 2 && w > 0:
				res.Deleted = true
				if _, err := tx.Exec(ctx, `DELETE FROM claims WHERE id = $1`, cid); err != nil {
					return err
				}
				res.Status, res.Word = "deleted", "deleted"
				return nil
			}
			if c.Status == "quarantine" {
				_, err := tx.Exec(ctx, `UPDATE claims SET conf_w = $2, disp_w = $3 WHERE id = $1`, cid, c.ConfW, c.DispW)
				res.Status, res.Word = c.Status, c.Word()
				return err
			}
		}
		return settle(ctx, tx, c, vs, in.Up, lvl, w, &res)
	})
	return res, err
}

// settle recomputes status, source agreement, rep and expiry of a non-quarantined claim after a
// vote (or a purge) and refreshes the mirror.
func settle(ctx context.Context, tx core.Q, c *Claim, vs []vote, up bool, voterLvl int, w float64, res *VoteResult) error {
	prev := c.Status
	// source agreement (27.3)
	if c.Src != "machine" {
		newState := c.Agree.State
		if newState == "unchecked" && c.SourceState != "unchecked" && c.SourceState != "ok" {
			newState = c.SourceState // keep an earlier verdict until the votes say otherwise
		}
		if newState != c.SourceState {
			if newState == "mismatch" && c.AuthorRoot != "" {
				core.SysMail(ctx, tx, c.AuthorRoot, "source drifted: refresh "+c.ID,
					fmt.Sprintf("%d confirmers in %d networks fetched a different source than you posted for %s (%s). Re-check %s and post a refreshed claim.",
						c.NConf, c.Agree.MismatchSupers, c.ID, doc.SafeLine(c.Title), c.SourceURL))
			}
			c.SourceState = newState
			if newState == "ok" && len(c.Agree.Liable) > 0 {
				if _, err := tx.Exec(ctx, `UPDATE claim_votes SET liable = true WHERE claim_id = $1 AND root = ANY($2) AND lvl >= 2`, c.ID, c.Agree.Liable); err != nil {
					return err
				}
			}
		}
	}
	// status (13.1)
	l3ok := c.L3Conf || (c.Kind != "security" && c.Kind != "breaking")
	sources := c.OfficialN >= 1 || c.CommunityN >= 2
	supers := supersOf(vs, true)
	switch {
	case c.DispW > 0 && c.DispW >= max(1.0, c.ConfW/2):
		c.Status = "disputed"
	case c.ConfW >= 2 && supers >= 2 && sources && l3ok && (c.SourceState == "unchecked" || c.SourceState == "ok"):
		c.Status = "verified"
	default:
		c.Status = "unverified"
	}
	if c.Src == "machine" && prev == "verified" && c.Status == "unverified" {
		c.Status = "verified" // machine rows keep their registry-backed status until disputed
	}
	firstConfirm := c.Status == "verified" && c.ConfirmedAt == nil
	if c.Status == "verified" && (prev != "verified" || c.ConfirmedAt == nil) {
		now := time.Now()
		c.ConfirmedAt = &now
	}
	exp := c.Created
	if c.ConfirmedAt != nil && c.ConfirmedAt.After(exp) {
		exp = *c.ConfirmedAt
	}
	c.ExpiresAt = exp.Add(ttlFor(c.Kind))
	hidden := false
	if c.Src == "machine" && c.NDisp >= 3 && !c.Hidden {
		hidden = true
	}
	if _, err := tx.Exec(ctx, `UPDATE claims SET status = $2, conf_w = $3, disp_w = $4, source_state = $5, confirmed_at = $6, expires_at = $7,
		hidden = hidden OR $8 WHERE id = $1`, c.ID, c.Status, c.ConfW, c.DispW, c.SourceState, c.ConfirmedAt, c.ExpiresAt, hidden); err != nil {
		return err
	}
	if hidden {
		c.Hidden = true
		if res != nil {
			res.Hidden = true
		}
		if err := core.Event(ctx, tx, "claim", c.ID, "", "machine claim disputed: "+c.Lib); err != nil {
			return err
		}
		if MachineDisputedFn != nil {
			MachineDisputedFn(ctx, tx, c.Lib, c.ID)
		}
	}
	// rep (4.2): author +1 once, on reaching the confirmed state through an L2+ voter from another
	// super-group; -1 (and liable voters -2) when a confirmed claim turns disputed by L2 voters.
	eligible := c.AuthorRoot != "" && !c.Seed && c.Src != "machine" && c.AuthorRoot != core.SystemID
	if firstConfirm && eligible {
		if l2 := l2OtherSuper(vs, c); l2 != "" {
			if distinct, err := trust.Distinct(ctx, tx, l2, c.AuthorRoot); err != nil {
				return err
			} else if distinct {
				if _, err := core.AddRep(ctx, tx, c.AuthorRoot, 1, "rep:kbin", 2); err != nil {
					return err
				}
				if err := trust.Verified(ctx, tx, c.AuthorRoot, true); err != nil {
					return err
				}
			}
		}
	}
	if prev == "verified" && c.Status == "disputed" {
		if res != nil {
			res.Dispute = true
		}
		if eligible && !up && voterLvl >= 2 && w > 0 {
			if _, err := core.AddRep(ctx, tx, c.AuthorRoot, -1, "", 0); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `UPDATE claim_votes SET liable = false WHERE claim_id = $1 AND liable RETURNING root`, c.ID)
		if err != nil {
			return err
		}
		var liable []string
		for rows.Next() {
			var r string
			if err := rows.Scan(&r); err != nil {
				rows.Close()
				return err
			}
			liable = append(liable, r)
		}
		rows.Close()
		for _, r := range liable {
			if _, err := core.AddRep(ctx, tx, r, -2, "rep:liable", 0); err != nil {
				return err
			}
		}
		if err := core.Event(ctx, tx, "claim", c.ID, "", "disputed: "+c.Lib+" "+c.Title); err != nil {
			return err
		}
	}
	if prev != "verified" && c.Status == "verified" && res != nil {
		res.Verified = true
		if err := core.Event(ctx, tx, "claim", c.ID, "", "confirmed: "+c.Lib+" "+c.Title); err != nil {
			return err
		}
	}
	if res != nil {
		res.Status, res.Word, res.SourceState = c.Status, c.Word(), c.SourceState
	}
	return mirrorClaim(ctx, tx, c.ID)
}

// l2OtherSuper returns an L2+ confirmer root outside the author's super-group ("" when none).
func l2OtherSuper(vs []vote, c *Claim) string {
	authorSuper := c.AnonSuper
	if c.standing.Super != "" {
		authorSuper = c.standing.Super
	}
	for _, v := range vs {
		if v.up && v.w > 0 && v.lvl >= 2 && v.super != "" && v.super != authorSuper {
			return v.root
		}
	}
	return ""
}

// chooseDistinct picks up to need L2 confirmers that are pairwise distinct (trust.Distinct) and in
// another super-group than the author's.
func chooseDistinct(ctx context.Context, q core.Q, vs []vote, authorRoot, authorSuper string, need int) ([]string, bool, error) {
	var cands []vote
	for _, v := range vs {
		if v.up && v.w > 0 && v.lvl >= 2 && v.root != authorRoot && (authorSuper == "" || v.super != authorSuper) {
			cands = append(cands, v)
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].w > cands[j].w })
	var chosen []string
	for _, c := range cands {
		ok, err := trust.Distinct(ctx, q, append(append([]string(nil), chosen...), c.root)...)
		if err != nil {
			return nil, false, err
		}
		if ok {
			chosen = append(chosen, c.root)
		}
		if len(chosen) >= need {
			return chosen, true, nil
		}
	}
	return chosen, false, nil
}

// Retract lets the author root retract its claim (13.1): status retracted, mirror removal.
func Retract(ctx context.Context, d *core.Deps, id *core.Ident, cid string) error {
	if !core.ValidIDPrefix(cid, 'v') {
		return core.ErrNotFound
	}
	return core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		var root, status string
		err := tx.QueryRow(ctx, `SELECT author_root, status FROM claims WHERE id = $1 AND expires_at > now() FOR UPDATE`, cid).Scan(&root, &status)
		if errors.Is(err, pgx.ErrNoRows) {
			return core.ErrNotFound
		}
		if err != nil {
			return err
		}
		if root == "" || root != id.Root {
			return core.ErrForbid
		}
		if status == "retracted" {
			return core.E(409, "dup", "already retracted")
		}
		if _, err := tx.Exec(ctx, `UPDATE claims SET status = 'retracted' WHERE id = $1`, cid); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "cret", cid, 0); err != nil {
			return err
		}
		if err := core.Event(ctx, tx, "claim", cid, "", "retracted"); err != nil {
			return err
		}
		core.ExportRemove(ctx, "claim", cid)
		return mirror(ctx, tx, "claim", cid, nil)
	})
}

// mirrorClaim refreshes the Forgejo mirror row of a claim (kind claim): the text rendering of a
// visible row, a removal otherwise.
func mirrorClaim(ctx context.Context, q core.Q, id string) error {
	c, err := Get(ctx, q, id, GetOpts{})
	if errors.Is(err, core.ErrNotFound) || (err != nil && isGone(err)) {
		return mirror(ctx, q, "claim", id, nil)
	}
	if err != nil {
		return err
	}
	if !c.Visible() {
		return mirror(ctx, q, "claim", id, nil)
	}
	r, _ := httpNewRequest()
	body, _ := doc.Render(r, 200, c.Doc(ctx), doc.Txt)
	return mirror(ctx, q, "claim", id, body)
}

func isGone(err error) bool {
	var ae *core.APIError
	return errors.As(err, &ae) && ae.Status == 410
}

// --- lists -------------------------------------------------------------------------------------

// ListOpts filters claim lists (13.2).
type ListOpts struct {
	Lib, Kind string
	Kinds     []string
	All       bool // adds disputed and quarantine
	K         int
	After     string // effective/created cursor (unused by callers today)
}

func statusFilter(all bool) string {
	if all {
		return `c.status IN ('verified', 'unverified', 'disputed', 'quarantine')`
	}
	return `c.status IN ('verified', 'unverified')`
}

// loadMany runs a claims query and fills the derived state of every row.
func loadMany(ctx context.Context, q core.Q, sql string, args ...any) ([]*Claim, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	var out []*Claim
	for rows.Next() {
		c, err := scanClaim(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, c := range out {
		if err := fill(ctx, q, c); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ClaimsAfter lists the visible claims of lib whose vkey_to is after haveVer (13.2 "everything
// after what I know"), breaking and security first, then by conf_w, newest first; kinds filters
// (nil = all). haveVer "" lists every parseable version.
func ClaimsAfter(ctx context.Context, q core.Q, lib, haveVer string, kinds []string) ([]Line, error) {
	key, ok := ResolveLib(ctx, q, lib)
	if !ok {
		return nil, errBadKey
	}
	cs, err := loadMany(ctx, q, `SELECT `+claimCols+` FROM claims c WHERE c.lib = $1 AND NOT c.hidden AND c.expires_at > now()
		AND c.status IN ('verified', 'unverified') AND c.vkey_to NOT LIKE '~%' ORDER BY c.vkey_to DESC, c.created DESC LIMIT 200`, key)
	if err != nil {
		return nil, err
	}
	have := ""
	if haveVer != "" {
		have = VKey(haveVer)
	}
	want := map[string]bool{}
	for _, k := range kinds {
		want[strings.ToLower(k)] = true
	}
	var out []*Claim
	for _, c := range cs {
		if have != "" && (strings.HasPrefix(have, "~") || c.VKeyTo <= have) {
			continue
		}
		if len(want) > 0 && !want[c.Kind] {
			continue
		}
		out = append(out, c)
	}
	sortClaims(out)
	lines := make([]Line, 0, len(out))
	for _, c := range out {
		lines = append(lines, c.Line())
	}
	return lines, nil
}

// sortClaims orders breaking, then security, then the rest, by conf_w desc then vkey desc.
func sortClaims(cs []*Claim) {
	rank := func(k string) int {
		switch k {
		case "breaking":
			return 0
		case "security":
			return 1
		}
		return 2
	}
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if ra, rb := rank(a.Kind), rank(b.Kind); ra != rb {
			return ra < rb
		}
		if a.ConfW != b.ConfW {
			return a.ConfW > b.ConfW
		}
		return a.VKeyTo > b.VKeyTo
	})
}

// Expire deletes expired claims (quarantine 14 d, release/behavior 365 d, others 730 d) and
// refreshes their mirror rows (janitor).
func Expire(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `DELETE FROM claims WHERE expires_at <= now() RETURNING id`)
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
		if err := mirror(ctx, q, "claim", id, nil); err != nil {
			return err
		}
		core.ExportRemove(ctx, "claim", id)
	}
	return nil
}

// recount re-derives a claim after votes were removed (purge).
func recount(ctx context.Context, q core.Q, id string) error {
	c, err := scanClaim(q.QueryRow(ctx, `SELECT `+claimCols+` FROM claims c WHERE c.id = $1`, id))
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil
		}
		return err
	}
	if c.Status == "quarantine" || c.Status == "retracted" {
		return nil
	}
	vs, err := loadVotes(ctx, q, id)
	if err != nil {
		return err
	}
	c.standing = standingOf(ctx, q, c.AuthorRoot)
	derive(c, vs)
	return settle(ctx, q, c, vs, true, 0, 0, nil)
}

// percentKey percent-encodes a key for a next: path.
func percentKey(key string) string { return url.PathEscape(key) }
