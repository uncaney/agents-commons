package core

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Ident is the authenticated identity attached to a request.
type Ident struct {
	ID      string
	Name    string
	Root    string
	Parent  string // empty for roots
	Credits int64
	Earned  int64 // transferable part of Credits (0 until migration 0042 adds the column)
	Rep     int   // root's reputation
	Banned  bool
	Exp     time.Time // zero = never
	Created time.Time // root's registration time
	Scopes  []string  // nil = every scope (full token)
	Seed    bool      // root is an operator seed root
	Class   string    // token_class: full|scoped|oauth|url|ui
}

// EstablishedAge is the root age an established identity needs (SPEC-v2 0).
const EstablishedAge = 72 * time.Hour

// Age is the time since the root registered (a zero Created counts as ancient).
func (i *Ident) Age() time.Duration { return time.Since(i.Created) }

// Established: rep >= 5 and root age >= 72 h, or a seed root.
func (i *Ident) Established() bool {
	return i.Seed || (i.Rep >= 5 && i.Age() >= EstablishedAge)
}

type ctxKey int

const (
	identKey ctxKey = 1
	depsKey  ctxKey = 2
)

type authResult struct {
	id  *Ident
	err error
}

// resolveAuth looks the bearer token up once per request and stashes the result (and the Deps,
// for the package-level seams) in the context.
func (d *Deps) resolveAuth(r *http.Request) *http.Request {
	tok := bearer(r.Header.Get("Authorization"))
	res := &authResult{}
	switch {
	case tok == "":
		res.err = ErrAuth
	case len(tok) != 46 || tok[:3] != "cx_":
		res.err = ErrBadToken
	default:
		id, err := d.LookupToken(r.Context(), tok)
		if err != nil {
			res.err = err
		} else {
			res.id = id
		}
	}
	ctx := context.WithValue(r.Context(), identKey, res)
	return r.WithContext(context.WithValue(ctx, depsKey, d))
}

func identFrom(r *http.Request) *Ident { return identFromCtx(r.Context()) }

func identFromCtx(ctx context.Context) *Ident {
	if res, ok := ctx.Value(identKey).(*authResult); ok {
		return res.id
	}
	return nil
}

// earnedCol remembers whether identities.earned exists (migration 0042, econ) so LookupToken
// works on a 0041 database and fills Ident.Earned once the column is there.
var earnedCol struct {
	sync.Mutex
	checked, has bool
}

func hasEarned(ctx context.Context, q Q) bool {
	earnedCol.Lock()
	defer earnedCol.Unlock()
	if earnedCol.checked {
		return earnedCol.has
	}
	var has bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'identities' AND column_name = 'earned')`).Scan(&has); err != nil {
		return false
	}
	earnedCol.checked, earnedCol.has = true, has
	return has
}

// LookupToken resolves a bearer token to a live identity (not revoked, not expired). A hash
// rotated out less than 60 s ago still resolves (3.4).
func (d *Deps) LookupToken(ctx context.Context, tok string) (*Ident, error) {
	var id Ident
	var parent *string
	var expT *time.Time
	earned := "0::bigint"
	if hasEarned(ctx, d.DB) {
		earned = "i.earned"
	}
	err := d.DB.QueryRow(ctx, `SELECT i.id, i.name, i.root, i.parent, i.credits, i.expires_at, i.scopes, i.token_class,
		r.rep, r.created, r.seed, `+earned+`
		FROM identities i JOIN identities r ON r.id = i.root
		WHERE (i.token_hash = $1 OR (i.token_hash_prev = $1 AND i.rotated_at > now() - interval '60 seconds'))
		  AND i.revoked_at IS NULL AND r.revoked_at IS NULL
		  AND (i.expires_at IS NULL OR i.expires_at > now())`, HashToken(tok)).
		Scan(&id.ID, &id.Name, &id.Root, &parent, &id.Credits, &expT, &id.Scopes, &id.Class, &id.Rep, &id.Created, &id.Seed, &id.Earned)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrBadToken
	}
	if err != nil {
		return nil, err
	}
	if parent != nil {
		id.Parent = *parent
	}
	if expT != nil {
		id.Exp = *expT
	}
	if id.Class == "" {
		id.Class = "full"
	}
	id.Banned = id.Rep <= -10
	return &id, nil
}

// Auth returns the request identity or an auth error (token required). A scoped token must hold
// the scope registered for the matched route (3.5): unregistered routes need a full token.
func (d *Deps) Auth(r *http.Request) (*Ident, error) {
	res, ok := r.Context().Value(identKey).(*authResult)
	if !ok {
		// Handler() middleware not in the chain (tests); resolve now.
		res = d.resolveAuth(r).Context().Value(identKey).(*authResult)
	}
	if res.err != nil {
		return nil, res.err
	}
	if res.id != nil && res.id.Scopes != nil {
		if err := d.checkScope(r.Pattern, res.id); err != nil {
			return nil, err
		}
	}
	return res.id, nil
}

// checkScope compares the route's registered scope with a scoped token's set. The registered
// value "*" means the route checks per operation itself (MCP, A2A).
func (d *Deps) checkScope(pattern string, id *Ident) error {
	need, ok := d.ScopeOf(pattern)
	switch {
	case !ok || need == "":
		need = "full"
	case need == "*":
		return nil
	case ScopeAllowed(id.Scopes, need):
		return nil
	}
	return E(403, "scope", need)
}

// AuthOpt allows anonymous: (nil, nil) when no token; error only for a bad token.
func (d *Deps) AuthOpt(r *http.Request) (*Ident, error) {
	id, err := d.Auth(r)
	if err == ErrAuth {
		return nil, nil
	}
	return id, err
}

// AuthWrite is Auth + refuses banned identities and the global write freeze.
func (d *Deps) AuthWrite(r *http.Request) (*Ident, error) {
	id, err := d.Auth(r)
	if err != nil {
		return nil, err
	}
	if id.Banned {
		return nil, ErrBanned
	}
	if d.Frozen("write") {
		return nil, Frozen("write")
	}
	return id, nil
}

// Scopes (3.5). Fixed names plus kv:<ns-glob> and wq:<name-glob>; a glob is a name prefix ending
// in '*'. Url-class tokens may carry the read scopes cp:r kv:r mb:env ev:r me:r (27.2).
var (
	scopeFixed = map[string]bool{
		"kb:r": true, "kb:w": true, "t:r": true, "t:w": true, "n:w": true, "j": true, "w": true, "lk": true,
		"br": true, "rv": true, "ps:r": true, "ps:w": true, "mb:r": true, "mb:w": true, "bt": true,
		"pr:req": true, "pr:answer": true, "cp": true, "know:w": true, "svc": true, "sub": true, "gov": true,
		"sp": true, "room": true, "hook": true, "cp:r": true, "kv:r": true, "mb:env": true, "ev:r": true, "me:r": true,
		"g:r": true, "g:w": true, "env:r": true, "env:w": true,
	}
	scopeGlobRe = regexp.MustCompile(`^(kv|wq):([A-Za-z0-9_.:/-]{1,40}\*?|\*)$`)

	// URLReadScopes is the default scope set of a url-class subkey (27.2).
	URLReadScopes = []string{"cp:r", "ev:r", "kv:r", "mb:env", "me:r"}

	tokenClasses = map[string]bool{"full": true, "scoped": true, "oauth": true, "url": true, "ui": true}
)

// MaxScopes caps the scopes of one token.
const MaxScopes = 32

// ValidScope reports whether s is in the scope vocabulary.
func ValidScope(s string) bool { return scopeFixed[s] || scopeGlobRe.MatchString(s) }

// scopeCovers reports whether holding `have` grants `need`: equal names, a bare name covering its
// sub-scopes ("cp" covers "cp:r"), or a glob prefix covering a name or a narrower glob.
func scopeCovers(have, need string) bool {
	if have == need {
		return true
	}
	if i := strings.IndexByte(need, ':'); i > 0 && have == need[:i] && scopeFixed[have] {
		return true
	}
	if pre, ok := strings.CutSuffix(have, "*"); ok {
		return strings.HasPrefix(strings.TrimSuffix(need, "*"), pre)
	}
	return false
}

// ScopeAllowed reports whether a token's scope set (nil = all) grants need.
func ScopeAllowed(scopes []string, need string) bool {
	if scopes == nil {
		return true
	}
	for _, s := range scopes {
		if scopeCovers(s, need) {
			return true
		}
	}
	return false
}

// ScopesSubset reports whether every child scope is covered by the parent's set (nil = all).
func ScopesSubset(parent, child []string) bool {
	for _, c := range child {
		if !ScopeAllowed(parent, c) {
			return false
		}
	}
	return true
}

// normScopes validates, dedupes and sorts a scope list.
func normScopes(in []string) ([]string, error) {
	if len(in) > MaxScopes {
		return nil, Bad("too many scopes")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !ValidScope(s) {
			return nil, Bad("unknown scope")
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}

// IsAncestor reports whether anc is id itself or one of its ancestors.
func IsAncestor(ctx context.Context, q Q, anc, id string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `WITH RECURSIVE up AS (
		SELECT id, parent FROM identities WHERE id = $2
		UNION ALL SELECT i.id, i.parent FROM identities i JOIN up ON i.id = up.parent)
		SELECT EXISTS (SELECT 1 FROM up WHERE id = $1)`, anc, id).Scan(&ok)
	return ok, err
}

// Descendants returns id and every identity below it.
func Descendants(ctx context.Context, q Q, id string) ([]string, error) {
	rows, err := q.Query(ctx, `WITH RECURSIVE down AS (
		SELECT id FROM identities WHERE id = $1
		UNION ALL SELECT i.id FROM identities i JOIN down ON i.parent = down.id)
		SELECT id FROM down`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// CreateRoot inserts a new root identity with 100 credits; returns id and token (v1 shape).
func CreateRoot(ctx context.Context, q Q, name, ip string) (id, token string, err error) {
	id, token, _, err = createRoot(ctx, q, rootSpec{id: NewID('a'), name: name, ip: ip, credits: 100})
	return id, token, err
}

type rootSpec struct {
	id, name, ip, cohort, ipClass string
	asn                           int64
	credits                       int64
}

// createRoot inserts a root row plus its recovery code (returned once, hash stored).
func createRoot(ctx context.Context, q Q, s rootSpec) (id, token, recovery string, err error) {
	token, h := NewToken()
	recovery, rh := NewRecoveryCode()
	_, err = q.Exec(ctx, `INSERT INTO identities (id, name, parent, root, token_hash, credits, reg_ip, cohort, ip_class, asn, recovery_hash)
		VALUES ($1, $2, NULL, $1, $3, $4, $5, $6, $7, $8, $9)`, s.id, s.name, h, s.credits, s.ip, s.cohort, s.ipClass, s.asn, rh)
	if IsUniqueViolation(err) {
		return "", "", "", E(409, "retry", "id collision, request a new challenge")
	}
	return s.id, token, recovery, err
}

// MaxLiveSubkeys caps live (unrevoked, unexpired) subkeys per root.
const MaxLiveSubkeys = 100

// SubkeyOpts describes a subkey to create (3.5, 27.2).
type SubkeyOpts struct {
	Name    string
	Credits int64
	Exp     time.Time
	Scopes  []string // nil = inherit the parent's set (never wider)
	Class   string   // "" = parent's class ("scoped" once scopes are set)
}

// CreateSubkey creates a child of parent, moving credits from the parent, expiring at exp.
// ErrQuota once the root has MaxLiveSubkeys live subkeys.
func CreateSubkey(ctx context.Context, q Q, parent *Ident, name string, credits int64, exp time.Time) (id, token string, err error) {
	id, token, _, _, err = createSubkey(ctx, q, parent, SubkeyOpts{Name: name, Credits: credits, Exp: exp})
	return id, token, err
}

// CreateSubkeyV2 is CreateSubkey with scopes and a token class: scopes must be a subset of the
// parent's (`err bad scope widening`), url-class tokens carry no credits.
func CreateSubkeyV2(ctx context.Context, q Q, parent *Ident, o SubkeyOpts) (id, token string, err error) {
	id, token, _, _, err = createSubkey(ctx, q, parent, o)
	return id, token, err
}

func createSubkey(ctx context.Context, q Q, parent *Ident, o SubkeyOpts) (id, token string, scopes []string, class string, err error) {
	class = o.Class
	if class == "" {
		class = parent.Class
	}
	if class == "" {
		class = "full"
	}
	if !tokenClasses[class] {
		return "", "", nil, "", Bad("class must be full|scoped|oauth|url|ui")
	}
	scopes = o.Scopes
	if scopes == nil && parent.Scopes != nil {
		scopes = parent.Scopes
	}
	if scopes != nil {
		if scopes, err = normScopes(scopes); err != nil {
			return "", "", nil, "", err
		}
		if !ScopesSubset(parent.Scopes, scopes) {
			return "", "", nil, "", Bad("scope widening")
		}
		if class == "full" {
			class = "scoped"
		}
	}
	switch class {
	case "scoped":
		if scopes == nil {
			return "", "", nil, "", Bad("scoped class needs scopes")
		}
	case "url":
		if scopes == nil {
			scopes = append([]string(nil), URLReadScopes...)
		}
		if o.Credits != 0 {
			return "", "", nil, "", Bad("url class carries no credits")
		}
	}
	var n int
	// Lock the root row so concurrent creations serialise on the count.
	if err = q.QueryRow(ctx, `SELECT (SELECT count(*) FROM identities WHERE root = r.id AND parent IS NOT NULL
		AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()))
		FROM identities r WHERE r.id = $1 FOR UPDATE`, parent.Root).Scan(&n); err != nil {
		return "", "", nil, "", err
	}
	if n >= MaxLiveSubkeys {
		return "", "", nil, "", ErrQuota
	}
	if err = Reserve(ctx, q, parent.ID, o.Credits); err != nil {
		return "", "", nil, "", err
	}
	id = NewID('a')
	token, h := NewToken()
	_, err = q.Exec(ctx, `INSERT INTO identities (id, name, parent, root, token_hash, credits, expires_at, scopes, token_class)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, id, o.Name, parent.ID, parent.Root, h, o.Credits, o.Exp, scopes, class)
	return id, token, scopes, class, err
}

// RevokeTree revokes id and all descendants; their remaining credits go to refundTo (if non-empty).
// Rows are locked FOR UPDATE before the update so the refund is exactly what the rows held at
// that moment (a plain UPDATE ... FROM self-join returns the pre-wait tuple under READ COMMITTED).
// Returns the number of identities revoked.
func RevokeTree(ctx context.Context, q Q, id, refundTo string) (int64, error) {
	var n, credits int64
	err := q.QueryRow(ctx, `WITH RECURSIVE down AS (
		SELECT id FROM identities WHERE id = $1
		UNION ALL SELECT i.id FROM identities i JOIN down ON i.parent = down.id),
		old AS (SELECT id, credits FROM identities WHERE id IN (SELECT id FROM down) AND revoked_at IS NULL FOR UPDATE),
		r AS (UPDATE identities i SET revoked_at = now(), credits = 0 FROM old WHERE i.id = old.id RETURNING old.credits)
		SELECT count(*), coalesce(sum(credits), 0) FROM r`, id).Scan(&n, &credits)
	if err != nil {
		return 0, err
	}
	if refundTo != "" && credits > 0 {
		if err := Earn(ctx, q, refundTo, credits); err != nil {
			return n, err
		}
	}
	return n, nil
}

// RevokeChildren revokes every live subkey below id (not id itself), refunding to id.
func RevokeChildren(ctx context.Context, q Q, id string) (int64, error) {
	rows, err := q.Query(ctx, `SELECT id FROM identities WHERE parent = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return 0, err
	}
	var kids []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return 0, err
		}
		kids = append(kids, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	var total int64
	for _, k := range kids {
		n, err := RevokeTree(ctx, q, k, id)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// RevokeExpired revokes expired subkeys and returns their credits to their parents. Leaves first
// (an expired row with a live child waits for the next round), so a parent never receives and
// loses credits in the same statement. Returns the number of identities revoked.
func RevokeExpired(ctx context.Context, q Q) (int64, error) {
	var total int64
	for round := 0; round < 16; round++ {
		var n int64
		err := q.QueryRow(ctx, `WITH old AS (
			SELECT id, parent, credits FROM identities i
			WHERE revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at < now()
			  AND NOT EXISTS (SELECT 1 FROM identities c WHERE c.parent = i.id AND c.revoked_at IS NULL)
			FOR UPDATE),
			r AS (UPDATE identities i SET revoked_at = now(), credits = 0 FROM old WHERE i.id = old.id
			      RETURNING old.parent, old.credits AS c),
			p AS (UPDATE identities i SET credits = i.credits + s.c
			      FROM (SELECT parent, sum(c) c FROM r WHERE parent IS NOT NULL GROUP BY parent) s
			      WHERE i.id = s.parent AND i.revoked_at IS NULL)
			SELECT count(*) FROM r`).Scan(&n)
		if err != nil {
			return total, err
		}
		total += n
		if n == 0 {
			break
		}
	}
	return total, nil
}
