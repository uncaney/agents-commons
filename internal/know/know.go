// Package know is the knowledge layer of SPEC-v2 13 (post-cutoff claims, breaking-change
// checklists, digests, library identity and registry metadata), 8.4 (demand: wanted) and the
// revision 3 additions of 27.3 (content-blind source agreement, API-surface digests) and 27.9
// (machine-sourced claim rendering). Everything agents write here is data, never instructions.
package know

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// Ref is a cross-link to a KB entry (13.2 `fixes:` lines).
type Ref struct {
	ID, Title, URL string
}

// Line is one claim as a list line plus the fields consumers (brief, libwatch, env drift) rank on.
type Line struct {
	ID, Status, Word, Kind, Lib, VFrom, VTo, Title, Tier string
	Sev                                                  int
	Effective                                            time.Time
	ConfW                                                float64
	Text                                                 string
}

// Release is one registry version (13.4 libs.versions).
type Release struct {
	V          string    `json:"v"`
	At         time.Time `json:"at,omitempty"`
	Yanked     bool      `json:"yanked,omitempty"`
	Deprecated bool      `json:"deprecated,omitempty"`
	Pre        bool      `json:"pre,omitempty"`
}

// Cross-package seams, every one nil-safe.
var (
	// KBForLib lists the KB entries whose versions match lib@ver (ver "" = any), for the `fixes:`
	// lines and the hub pages (13.2); set by the integration package to kb's lookup.
	KBForLib func(ctx context.Context, lib, ver string) []Ref
	// WantedExtraFn appends lines to GET /wanted (27.1 demand block).
	WantedExtraFn func(ctx context.Context, q core.Q) []string
	// LibMetaHookFn sees every applied libmeta result (27.9: release/deprecated claims by machineclaims).
	LibMetaHookFn func(ctx context.Context, q core.Q, key string, meta json.RawMessage) error
	// MachineDisputedFn is told when a machine claim is hidden by 3 disputes (27.9: pause the product).
	MachineDisputedFn func(ctx context.Context, q core.Q, lib, id string)

	kbCache = core.NewByteLRU(1 << 20)
)

// Limits (13.1, 13.3, 8.4). Vars so tests can tighten them.
var (
	MaxTitle, MaxDetail, MaxMigrate, MaxPart       = 160, 2000, 1200, 600
	MaxQuote, MaxVoteNote, MaxWhy                  = 300, 200, 200
	MaxDigestBody                                  = 6 << 10
	MaxBody                                        = 32 << 10
	DupSim                                         = 0.6
	DigestDupSim                                   = 0.7
	ReleaseTTL                                     = 365 * 24 * time.Hour
	ClaimTTL                                       = 730 * 24 * time.Hour
	DigestTTL                                      = 365 * 24 * time.Hour
	QuarantineTTL                                  = 14 * 24 * time.Hour
	AnonPerGroup                                   = 5    // anonymous claims per IP group per day (4.3)
	QuarantineCap                                  = 5000 // live quarantine rows (4.3)
	QuarantineSuperCap                             = 100  // 2 % of the quarantine per super-group (4.3 rev 3)
	WantedPerKind                                  = 500
	WantedMaxRows                                  = 20000
	WantedGroups                                   = 16
	LibMetaRefresh                                 = 7 * 24 * time.Hour
	StorageCap                               int64 = 2 << 30
	kbCacheTTL                                     = 300 * time.Second
)

var claimKinds = map[string]bool{"breaking": true, "new": true, "deprecated": true, "removed": true, "renamed": true,
	"default": true, "security": true, "release": true, "eol": true, "behavior": true}

var claimScopes = map[string]bool{"": true, "api": true, "config": true, "cli": true, "behavior": true, "build": true}

// Permalink is the readable URL of a claim (negotiable through doc).
func Permalink(id string) string { return doc.Base() + "/v1/v/" + id }

// DigestPermalink is the readable URL of a digest.
func DigestPermalink(id string) string { return doc.Base() + "/v1/dg/" + id }

func fw(w float64) string { return strconv.FormatFloat(w, 'g', 3, 64) }

func ageText(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < 24*time.Hour {
		return strconv.Itoa(int(d/time.Hour)) + "h"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + "d"
}

func ttlFor(kind string) time.Duration {
	if kind == "release" || kind == "behavior" {
		return ReleaseTTL
	}
	return ClaimTTL
}

// cutRunes cuts s to n runes.
func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// hostOf returns the host of a URL ("" when unparseable).
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
}

// verSpan renders `<from>-><to>` (`<to>` alone without from, `-` when both are empty).
func verSpan(from, to string) string {
	switch {
	case from != "" && to != "":
		return doc.SafeLine(from) + "->" + doc.SafeLine(to)
	case to != "":
		return doc.SafeLine(to)
	case from != "":
		return doc.SafeLine(from) + "->?"
	}
	return "-"
}

// standingOf loads a root's standing; anonymous and unknown roots are a zero standing.
func standingOf(ctx context.Context, q core.Q, root string) trust.Standing {
	if root == "" {
		return trust.Standing{}
	}
	st, err := trust.Load(ctx, q, root)
	if err != nil {
		return trust.Standing{Root: root}
	}
	return st
}

// inTx runs fn atomically on q: a pool or connection opens a transaction, a transaction a savepoint.
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

// writeOK mirrors core.AuthWrite for ops and service calls.
func writeOK(d *core.Deps, id *core.Ident) error {
	switch {
	case id == nil:
		return core.ErrAuth
	case id.Banned:
		return core.ErrBanned
	case d.Frozen("write"):
		return core.Frozen("write")
	case d.Frozen("know"):
		return core.Frozen("know")
	}
	return nil
}

// kbRefs is KBForLib behind a 300 s byte-bounded cache (13.2 render-time cross-links).
func kbRefs(ctx context.Context, lib, ver string) []Ref {
	if KBForLib == nil {
		return nil
	}
	key := lib + "|" + ver
	if b, ok := kbCache.Get(key); ok {
		var refs []Ref
		if json.Unmarshal(b, &refs) == nil {
			return refs
		}
	}
	refs := KBForLib(ctx, lib, ver)
	if len(refs) > 10 {
		refs = refs[:10]
	}
	if b, err := json.Marshal(refs); err == nil {
		kbCache.Put(key, b, kbCacheTTL)
	}
	return refs
}

func refIDs(refs []Ref) string {
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		if core.ValidID(r.ID) {
			ids = append(ids, r.ID)
		}
	}
	return strings.Join(ids, ",")
}

// mirror coalesces a forge_outbox row per (kind, ref) the way forge.Enqueue does (7.3); an empty
// payload removes the object from the mirror.
func mirror(ctx context.Context, q core.Q, kind, ref string, payload []byte) error {
	if payload == nil {
		payload = []byte{}
	}
	tag, err := q.Exec(ctx, `UPDATE forge_outbox SET payload = $3, next_at = greatest(next_at, now() + interval '1 hour')
		WHERE kind = $1 AND ref = $2`, kind, ref, payload)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	_, err = q.Exec(ctx, `INSERT INTO forge_outbox (kind, ref, payload) VALUES ($1, $2, $3)`, kind, ref, payload)
	return err
}

// parseDate accepts YYYY-MM-DD (or YYYY-MM, first of the month).
func parseDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, true
	}
	for _, layout := range []string{"2006-01-02", "2006-01"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func dateOrDash(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	return core.Date(*t)
}

// pgDays renders a duration as a Postgres interval literal.
func pgInterval(d time.Duration) string {
	return fmt.Sprintf("%d seconds", int64(d/time.Second))
}
