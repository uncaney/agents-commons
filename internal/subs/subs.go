// Package subs adds server-side topic subscriptions and reactive functions (SPEC-v2 27.4): a sub
// binds a topic to a sink (work queue, mailbox, KV namespace, or a catalog service function) with
// an optional prefix/RE2 filter and an each-or-digest mode. A delivery goroutine pulls the new
// messages of each live sub after its cursor, filters them in Go, and writes them to the sink while
// advancing the cursor in one transaction, so delivery is exactly-once. Function sinks run the
// message through a verified service and write the output back to a topic, mailbox or KV as the
// subscriber, with a hop counter that bounds reactive loops; messages a sub publishes carry via=sub
// and are never re-matched. Sink authorisation is rechecked at creation and on every delivery, and
// a sub pauses itself after repeated refusals or when the subscriber runs out of credits.
package subs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/core"
)

// Tunables (vars so tests can tighten the windows). SPEC-v2 27.4 fixes the production defaults.
var (
	maxPerRoot     = 20               // subs per root (L0: maxPerRootL0)
	maxPerRootL0   = 5                //
	maxPerTopic    = 200              // subs per topic
	firePerDayRoot = 200              // sink firings per day per root
	firePerHourAll = 2000             // sink firings per hour, globally
	pauseAfterErr  = 100              // consecutive refusals that pause a sub
	hopMaxDefault  = 2                // default hop ceiling
	maxCreditsDay  = 50               // default fn credit budget per day
	digestEvery    = 10 * time.Minute // one digest mail at most this often
	digestMaxLines = 20               // envelope lines per digest mail
	pullBatch      = 100              // messages pulled per sub per pass (swarm ceiling)
	fnWait         = 20               // seconds catalog.Call waits for a fn result
	fnOutTopicMax  = 4096             // fn output written to a topic/mail
	fnOutKVMax     = 4096             // fn output to KV (mem.MaxKVValue is 4 KiB)
	listLimit      = 50
)

// callService runs a catalog service function for a fn sink (seam for tests). It returns the job
// status and the inline stdout text.
var callService = func(ctx context.Context, d *core.Deps, id *core.Ident, nameAtVer, inText string, wait int) (status, out string, err error) {
	v, text, err := catalog.Call(ctx, d, id, nameAtVer, "", inText, "", wait)
	if err != nil {
		return "", "", err
	}
	return v.Status, text, nil
}

// Sub is one subscription row.
type Sub struct {
	ID, Root, Topic       string
	SinkKind, Sink        string
	ToKind, ToKey         string
	Filter, Mode          string
	LastSeq               int64
	Errors                int
	Paused                bool
	HopMax, MaxCreditsDay int
	Until, DigestAt       *time.Time
}

// Service holds the Deps; one per Deps.
type Service struct {
	d  *core.Deps
	mu sync.Mutex
	re map[string]*regexp.Regexp // compiled RE2 filters, by filter string (compiled once)
}

var (
	svcMu sync.Mutex
	svcs  = map[*core.Deps]*Service{}
)

func svc(d *core.Deps) *Service {
	svcMu.Lock()
	defer svcMu.Unlock()
	if s, ok := svcs[d]; ok {
		return s
	}
	s := &Service{d: d, re: map[string]*regexp.Regexp{}}
	svcs[d] = s
	d.Janitor.Add("subs", s.deliverAll)
	d.OnPurge(s.purge)
	return s
}

// OpMeta describes every subs op for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"sub":       {Scope: "ps:w", Cost: 1, Mutating: true},
	"subg":      {Scope: "ps:r", Cost: 0.2},
	"unsub":     {Scope: "ps:w", Cost: 1, Mutating: true},
	"subresume": {Scope: "ps:w", Cost: 1, Mutating: true},
}

// --- filter ---------------------------------------------------------------------------------

const maxFilter = 120
const maxRE = 64

// compileFilter validates a filter string: "" (match all), "prefix:<text>" or "re:<RE2>".
func (s *Service) compileFilter(filter string) error {
	switch {
	case filter == "":
		return nil
	case strings.HasPrefix(filter, "prefix:"):
		return nil
	case strings.HasPrefix(filter, "re:"):
		src := filter[len("re:"):]
		if len(src) > maxRE {
			return core.Bad(fmt.Sprintf("re must be <= %d chars", maxRE))
		}
		re, err := regexp.Compile(src)
		if err != nil {
			return core.Bad("re: " + err.Error())
		}
		s.mu.Lock()
		s.re[filter] = re
		s.mu.Unlock()
		return nil
	default:
		return core.Bad("filter must be prefix:<text> or re:<RE2>")
	}
}

// matches reports whether a message text passes the filter.
func (s *Service) matches(filter, text string) bool {
	switch {
	case filter == "":
		return true
	case strings.HasPrefix(filter, "prefix:"):
		return strings.HasPrefix(text, filter[len("prefix:"):])
	case strings.HasPrefix(filter, "re:"):
		s.mu.Lock()
		re := s.re[filter]
		s.mu.Unlock()
		if re == nil { // compile once, lazily, after a restart
			var err error
			if re, err = regexp.Compile(filter[len("re:"):]); err != nil {
				return false
			}
			s.mu.Lock()
			s.re[filter] = re
			s.mu.Unlock()
		}
		return re.MatchString(text)
	}
	return false
}

// --- sink / to parsing ----------------------------------------------------------------------

// parseSink splits a sink string into (kind, rest). Kinds: wq, mb, kv, fn.
func parseSink(sink string) (kind, rest string, err error) {
	k, r, ok := strings.Cut(sink, ":")
	if !ok || r == "" {
		return "", "", core.Bad("sink must be wq:<name>|mb:me|kv:<ns>/<k>|fn:<svc>@<ver>")
	}
	switch k {
	case "wq", "mb", "kv", "fn":
		return k, r, nil
	}
	return "", "", core.Bad("sink kind must be wq, mb, kv or fn")
}

// parseTo splits a fn `to` string ("topic:<name>"|"mail:me"|"kv:<ns>/<k>") into (kind, key).
func parseTo(to string) (kind, key string, err error) {
	k, r, ok := strings.Cut(to, ":")
	if !ok || r == "" {
		return "", "", core.Bad("to must be topic:<name>|mail:me|kv:<ns>/<k>")
	}
	switch k {
	case "topic", "mail", "kv":
		return k, r, nil
	}
	return "", "", core.Bad("to kind must be topic, mail or kv")
}

// kvRef splits an "<ns>/<k>" KV reference.
func kvRef(ref string) (ns, k string, err error) {
	i := strings.LastIndexByte(ref, '/')
	if i <= 0 || i == len(ref)-1 {
		return "", "", core.Bad("kv ref must be <ns>/<key>")
	}
	return ref[:i], ref[i+1:], nil
}

// --- helpers ---------------------------------------------------------------------------------

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// loadIdent builds an Ident for a root id from its identity row (fn sinks call as the subscriber).
func loadIdent(ctx context.Context, q core.Q, root string) (*core.Ident, error) {
	id := &core.Ident{}
	err := q.QueryRow(ctx, `SELECT id, name, root, credits, earned, rep, created
		FROM identities WHERE id = $1 AND parent IS NULL AND revoked_at IS NULL`, root).Scan(
		&id.ID, &id.Name, &id.Root, &id.Credits, &id.Earned, &id.Rep, &id.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	id.Banned = id.Rep <= -10
	return id, nil
}

// scanSub reads a sub row (column order fixed by subCols).
const subCols = `id, root, topic, sink_kind, sink, to_kind, to_key, filter, mode, last_seq, errors, paused, hop_max, max_credits_day, until, digest_at`

func scanSub(row pgx.Row) (*Sub, error) {
	var sub Sub
	if err := row.Scan(&sub.ID, &sub.Root, &sub.Topic, &sub.SinkKind, &sub.Sink, &sub.ToKind, &sub.ToKey,
		&sub.Filter, &sub.Mode, &sub.LastSeq, &sub.Errors, &sub.Paused, &sub.HopMax, &sub.MaxCreditsDay,
		&sub.Until, &sub.DigestAt); err != nil {
		return nil, err
	}
	return &sub, nil
}

// hopOf parses a leading `hop=<n>` header line from a message text (0 when absent).
func hopOf(text string) int {
	line := text
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		line = text[:i]
	}
	if !strings.HasPrefix(line, "hop=") {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[len("hop="):]))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// withHop prepends a `hop=<n>` header to a text body.
func withHop(n int, text string) string { return "hop=" + strconv.Itoa(n) + "\n" + text }

// bumpCounter adds 1 to a counter scope/kind for today and returns the new value.
func bumpCounter(ctx context.Context, q core.Q, scope, kind string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, 1)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + 1 RETURNING n`, scope, kind).Scan(&n)
	return n, err
}

// readCounter reads the current value of a counter scope/kind for today (0 when absent).
func readCounter(ctx context.Context, q core.Q, scope, kind string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT n FROM counters WHERE scope = $1 AND kind = $2 AND day = current_date`, scope, kind).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

func hourKind() string { return "sub_fire_h" + strconv.Itoa(time.Now().UTC().Hour()) }
