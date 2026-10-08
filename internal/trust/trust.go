package trust

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// Standing is one root's trust snapshot (SPEC-v2 4.1), loaded by Load.
type Standing struct {
	Root               string
	Rep                int
	Age                time.Duration
	Created            time.Time
	Seed, Trusted      bool
	Vouched, Banned    bool
	Group, Super       string // core.IPGroup / core.IPSuper of reg_ip
	Cohort             string
	ASN                int // 0 = unknown (27.8)
	VerifiedContrib    int
	VerifiedNonCompute int
	LastVerified       time.Time // identities.last_verified_at (zero = never)
	Upheld             int       // upheld reports in 30 d (UpheldReportsFn, 0 when unset)
}

// Level thresholds (4.1, 17.3, 4.2).
const (
	l1Age, l2Age, l3Age = 24 * time.Hour, 72 * time.Hour, 30 * 24 * time.Hour
	l2Rep, l3Rep        = 5, 20
	govAge              = 7 * 24 * time.Hour
	govRecent           = 60 * 24 * time.Hour
	vouchRep            = 10
	vouchAge            = 14 * 24 * time.Hour
	maxLiveVouches      = 3
	vouchLiability      = 30 * 24 * time.Hour
	decayEvery          = 14 * 24 * time.Hour
	entropyWindow       = 90 * 24 * time.Hour
	bannedRep           = -10
)

// Cross-package seams (nil-safe).
var (
	// UpheldReportsFn counts a root's upheld reports in the last 30 d (4.1 L3); nil = none.
	UpheldReportsFn func(ctx context.Context, q core.Q, root string) (int, error)
	// PairDampFn damps a voter's weight toward one author (27.4, graph.PairDamp); nil = 1.0.
	PairDampFn func(ctx context.Context, q core.Q, voter, author string) float64
	// ConfirmerEntropyFn replaces the built-in kb-only entropy count (graph fills it); nil = built-in.
	ConfirmerEntropyFn func(ctx context.Context, q core.Q, voter string) (bool, error)
)

// asnMode mirrors TRUST_ASN (27.8): Register sets it from the config; the env seeds it so SQL
// built before Register (package-level consts in owners) agrees with the running mode.
var asnMode atomic.Bool

func init() { asnMode.Store(os.Getenv("TRUST_ASN") == "1") }

// SetASN switches the ASN-aware network keys on or off (tests and Register).
func SetASN(on bool) { asnMode.Store(on) }

// ASN reports whether the ASN-aware network keys are active.
func ASN() bool { return asnMode.Load() }

const standingCols = `r.id, r.rep, r.created, r.reg_ip, r.seed, r.trusted, r.cohort, coalesce(r.asn, 0),
	r.verified_contrib, r.verified_noncompute, r.last_verified_at, r.revoked_at,
	EXISTS (SELECT 1 FROM vouches v JOIN identities vr ON vr.id = v.voucher WHERE v.vouchee = r.id AND vr.revoked_at IS NULL)`

// Load reads the standing of root (any id of the tree resolves to its root). A missing identity
// is core.ErrNotFound; a revoked root is L0 and banned.
func Load(ctx context.Context, q core.Q, root string) (Standing, error) {
	var s Standing
	var regIP string
	var lastVerified, revoked *time.Time
	err := q.QueryRow(ctx, `SELECT `+standingCols+` FROM identities i JOIN identities r ON r.id = i.root WHERE i.id = $1`, root).
		Scan(&s.Root, &s.Rep, &s.Created, &regIP, &s.Seed, &s.Trusted, &s.Cohort, &s.ASN,
			&s.VerifiedContrib, &s.VerifiedNonCompute, &lastVerified, &revoked, &s.Vouched)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, core.ErrNotFound
	}
	if err != nil {
		return s, err
	}
	s.Age = time.Since(s.Created)
	if regIP != "" {
		s.Group, s.Super = core.IPGroup(regIP), core.IPSuper(regIP)
	}
	if lastVerified != nil {
		s.LastVerified = *lastVerified
	}
	s.Banned = s.Rep <= bannedRep || revoked != nil
	if !s.Banned && !s.Seed && s.Rep >= l3Rep && s.Age >= l3Age && UpheldReportsFn != nil {
		if s.Upheld, err = UpheldReportsFn(ctx, q, s.Root); err != nil {
			return s, err
		}
	}
	return s, nil
}

// Level is the standing level (4.1): L0 fresh; L1 age >= 24 h AND (rep >= 1 OR vouched); L2 rep >= 5
// AND age >= 72 h AND verified_noncompute >= 1, or seed; L3 L2 AND rep >= 20 AND age >= 30 d AND
// no upheld report in 30 d. Levels nest: compute-only rep never reaches L2 or L3. Banned = L0.
func (s Standing) Level() int {
	if s.Banned {
		return 0
	}
	lvl := 0
	if s.Age >= l1Age && (s.Rep >= 1 || s.Vouched) {
		lvl = 1
	}
	if s.Seed || (s.Rep >= l2Rep && s.Age >= l2Age && s.VerifiedNonCompute >= 1) {
		lvl = 2
	}
	if lvl == 2 && s.Rep >= l3Rep && s.Age >= l3Age && s.Upheld == 0 {
		lvl = 3
	}
	return lvl
}

// CapLevel is the column of the caps table a root uses: its level, or L1 for a vouched L0 (17.3).
func (s Standing) CapLevel() int {
	if l := s.Level(); l > 0 || !s.Vouched || s.Banned {
		return l
	}
	return 1
}

// LevelOf is the core.LevelFn implementation: the root's level, 0 on any error.
func LevelOf(ctx context.Context, q core.Q, root string) int {
	s, err := Load(ctx, q, root)
	if err != nil {
		return 0
	}
	return s.Level()
}

// Weight is the vote/report weight (4.1): L0 0.25, vouched L0 0.5, else core.VoteWeight(rep);
// seed roots weigh 0 (they never vote, 22) and so do banned ones.
func Weight(s Standing) float64 {
	switch l := s.Level(); {
	case s.Seed || s.Banned:
		return 0
	case l == 0 && s.Vouched:
		return 0.5
	case l == 0:
		return 0.25
	}
	return core.VoteWeight(s.Rep)
}

// Damp returns PairDampFn(voter, author) clamped to 0..1, or 1.0 when the seam is unset.
func Damp(ctx context.Context, q core.Q, voter, author string) float64 {
	if PairDampFn == nil || voter == "" || author == "" {
		return 1
	}
	d := PairDampFn(ctx, q, voter, author)
	switch {
	case d < 0 || d != d:
		return 0
	case d > 1:
		return 1
	}
	return d
}

// DampedWeight is Weight(voter) x Damp(voter, author): the value owners use for rep sources 1 and
// 3, promotion, hiding and restore (27.4).
func DampedWeight(ctx context.Context, q core.Q, voter Standing, author string) float64 {
	return Weight(voter) * Damp(ctx, q, voter.Root, author)
}

// GovWeight is the governance vote weight (4.1, 27.4): 0 unless age >= 7 d AND rep >= 5 AND not
// banned AND not seed AND a verified contribution within 60 d AND, when minMemberH > 0, a space
// member since at least that many hours; else 1 + min(rep, 30)/15 (1.0..3.0).
func GovWeight(s Standing, memberSince time.Time, minMemberH int) float64 {
	if s.Banned || s.Seed || s.Age < govAge || s.Rep < 5 {
		return 0
	}
	if s.LastVerified.IsZero() || time.Since(s.LastVerified) > govRecent {
		return 0
	}
	if minMemberH > 0 && (memberSince.IsZero() || time.Since(memberSince) < time.Duration(minMemberH)*time.Hour) {
		return 0
	}
	return 1 + float64(min(s.Rep, 30))/15
}

// Verified records a verified contribution of root (4.2): verified_contrib += 1, verified_noncompute
// += 1 when the source is not compute, last_verified_at = now(). Seed roots are left untouched.
func Verified(ctx context.Context, q core.Q, root string, noncompute bool) error {
	nc := 0
	if noncompute {
		nc = 1
	}
	_, err := q.Exec(ctx, `UPDATE identities SET verified_contrib = verified_contrib + 1,
		verified_noncompute = verified_noncompute + $2, last_verified_at = now()
		WHERE id = $1 AND parent IS NULL AND NOT seed`, root, nc)
	return err
}

// ConfirmerEntropy reports whether voter confirmed >= 3 distinct author roots in 90 d (27.4): a
// confirmation counts toward the author's verified_noncompute only then. Built-in: kb ok votes;
// ConfirmerEntropyFn (graph) replaces it when set.
func ConfirmerEntropy(ctx context.Context, q core.Q, voter string) (bool, error) {
	if ConfirmerEntropyFn != nil {
		return ConfirmerEntropyFn(ctx, q, voter)
	}
	var n int
	err := q.QueryRow(ctx, `SELECT count(DISTINCT k.author_root) FROM kb_votes v JOIN kb k ON k.id = v.kb_id
		WHERE v.root = $1 AND v.up AND v.created > now() - $2::interval AND k.author_root <> $1`,
		voter, entropyWindow.String()).Scan(&n)
	return n >= 3, err
}

// netKey is the anti-sybil key of one root: its super-group, prefixed by the ASN for hosting
// classes in ASN mode (27.8).
type netKey struct {
	key     string
	asn     int
	hosting bool
}

// Distinct reports whether roots are pairwise distinct (4.1): different root, different
// super-group (or ASN-aware net key, 27.8) and different cohort. Unknown roots, missing reg_ip or
// subkeys make the set non-distinct; in ASN mode at most 3 roots of one hosting ASN count.
func Distinct(ctx context.Context, q core.Q, roots ...string) (bool, error) {
	if len(roots) < 2 {
		return true, nil
	}
	seenRoot := map[string]bool{}
	for _, r := range roots {
		if seenRoot[r] {
			return false, nil
		}
		seenRoot[r] = true
	}
	sql := `SELECT i.id, i.reg_ip, i.cohort, coalesce(i.asn, 0), false FROM identities i WHERE i.id = ANY($1) AND i.parent IS NULL`
	if ASN() {
		sql = `SELECT i.id, i.reg_ip, i.cohort, coalesce(i.asn, 0), coalesce(ap.class = 'hosting', false)
			FROM identities i LEFT JOIN asn_policy ap ON ap.asn = i.asn WHERE i.id = ANY($1) AND i.parent IS NULL`
	}
	rows, err := q.Query(ctx, sql, roots)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	keys := map[string]netKey{}
	cohorts := map[string]string{}
	for rows.Next() {
		var id, ip, cohort string
		var asn int
		var hosting bool
		if err := rows.Scan(&id, &ip, &cohort, &asn, &hosting); err != nil {
			return false, err
		}
		if ip == "" {
			return false, nil
		}
		k := netKey{key: core.IPSuper(ip), asn: asn, hosting: hosting}
		if hosting && asn > 0 {
			k.key = "asn:" + itoa(asn) + "|" + k.key
		}
		keys[id] = k
		cohorts[id] = cohort
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	seenKey, seenCohort, perASN := map[string]bool{}, map[string]bool{}, map[int]int{}
	for _, r := range roots {
		k, ok := keys[r]
		if !ok || seenKey[k.key] {
			return false, nil
		}
		seenKey[k.key] = true
		if c := cohorts[r]; c != "" {
			if seenCohort[c] {
				return false, nil
			}
			seenCohort[c] = true
		}
		if k.hosting && k.asn > 0 {
			perASN[k.asn]++
			if perASN[k.asn] > 3 {
				return false, nil
			}
		}
	}
	return true, nil
}

// NetKeySQL is the SQL expression of a vote row's network key, alias being the votes relation
// (columns ip_super and root): the super-group, or in ASN mode 'asn:<asn>|<super>' when the
// voter's ASN is classed hosting in asn_policy (27.8).
func NetKeySQL(alias string) string {
	if !ASN() {
		return alias + ".ip_super"
	}
	return `coalesce((SELECT 'asn:' || i.asn::text || '|' || ` + alias + `.ip_super FROM identities i JOIN asn_policy ap ON ap.asn = i.asn WHERE i.id = ` + alias + `.root AND ap.class = 'hosting'), ` + alias + `.ip_super)`
}

// sideSQL maps a side keyword to its boolean filter; anything else is used verbatim.
func sideSQL(side string) string {
	switch strings.ToLower(side) {
	case "":
		return "true"
	case "up", "ok", "yes", "true":
		return "up"
	case "down", "bad", "no", "false":
		return "NOT up"
	}
	return "(" + side + ")"
}

// CollapseSQL builds the super-group collapse (4.1): one row per network key, the max-weight voter,
// read from votesTable (a table, CTE or alias restricted to one target, with columns ip_super, w,
// root and up when a side is given). side is up|down (or "" / a boolean expression). The result
// has exactly the columns of votesTable, so owners wrap it: `SELECT coalesce(sum(w), 0) FROM (` +
// CollapseSQL("v", "up") + `) c`. In ASN mode the collapse is DISTINCT ON (net_key) and at most 3
// net keys per hosting ASN count (27.8); with TRUST_ASN=0 the output is the plain collapse.
func CollapseSQL(votesTable, side string) string {
	return CollapseSQLWhere(votesTable, side, "")
}

// CollapseSQLWhere is CollapseSQL with an extra filter on the votes rows (e.g. "kb_id = $1").
func CollapseSQLWhere(votesTable, side, where string) string {
	cond := sideSQL(side)
	if where != "" {
		cond += " AND (" + where + ")"
	}
	if !ASN() {
		return `SELECT DISTINCT ON (ip_super) * FROM ` + votesTable + ` WHERE ` + cond + ` ORDER BY ip_super, w DESC`
	}
	return `SELECT (c.v).* FROM (
		SELECT c.v, row_number() OVER (PARTITION BY c.part ORDER BY (c.v).w DESC) AS rn FROM (
			SELECT DISTINCT ON (k.net_key) k.v, k.net_key,
				CASE WHEN k.net_key LIKE 'asn:%' THEN split_part(k.net_key, '|', 1) ELSE 'nk:' || k.net_key END AS part
			FROM (SELECT v, ` + NetKeySQL("v") + ` AS net_key FROM ` + votesTable + ` v WHERE ` + cond + `) k
			ORDER BY k.net_key, (k.v).w DESC) c) c
	WHERE c.rn <= 3`
}

// RecordRep is the core.RepLogger implementation: one rep_log row per change (4.2).
func RecordRep(ctx context.Context, q core.Q, root string, delta int, kind, ref string) error {
	if delta == 0 {
		return nil
	}
	_, err := q.Exec(ctx, `INSERT INTO rep_log (root, delta, kind, ref) VALUES ($1, $2, $3, $4)`,
		root, delta, safeField(kind, 32), safeField(ref, 200))
	return err
}

// safeField makes s a single trimmed line of at most max runes (control chars -> space).
func safeField(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s))
	if utf8.RuneCountInString(s) > max {
		s = strings.TrimSpace(string([]rune(s)[:max]))
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
