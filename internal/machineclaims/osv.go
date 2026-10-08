package machineclaims

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/know"
)

// OSV ingestion (27.9): the courier posts api.osv.dev/v1/querybatch and returns the matched
// vulnerabilities per queried (lib, version); each becomes one verified `security` claim whose
// version span is the OSV affected range (introduced -> fixed) and whose source_url is the
// canonical osv.dev permalink used as the dedup key.

// osvIDRe validates an OSV id before it enters a title or a URL: an uppercase prefix, a dash, then
// alphanumerics and dashes (GHSA ids are lowercase after the prefix). Anything else is dropped.
var osvIDRe = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,19}-[A-Za-z0-9][A-Za-z0-9-]{0,98}$`)

const (
	osvTitleMax  = 140
	osvDetailMax = 2000
)

// osvQuery is one querybatch entry as this package builds it and the courier consumes it.
type osvQuery struct {
	Lib     string `json:"lib"` // commons key eco:name (echoed back in the result)
	Eco     string `json:"eco"` // OSV ecosystem (PyPI, npm, Go, …)
	Name    string `json:"name"`
	Version string `json:"version"`
}

// osvPayload is the osv job payload.
type osvPayload struct {
	Queries []osvQuery `json:"queries"`
}

// osvResult is the courier ack: the vulnerabilities OSV returned for each queried (lib, version).
type osvResult struct {
	Fetched string    `json:"fetched"`
	Items   []osvItem `json:"items"`
}

type osvItem struct {
	Lib   string    `json:"lib"`
	V     string    `json:"v"`
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Affected []osvAffected `json:"affected"`
}

type osvAffected struct {
	Package osvPkg     `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

type osvPkg struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

// osvQueries builds the querybatch entries for one key from the registry versions already in
// libs.versions (27.9: validated keys and known versions only). Ecosystems OSV does not index and
// versions that are not single tokens are skipped; the result is capped at maxOSVQueries.
func osvQueries(key string, rels []know.Release) []osvQuery {
	eco, name := know.Eco(key)
	osvEco := osvEcosystem[eco]
	if osvEco == "" || name == "" {
		return nil
	}
	out := make([]osvQuery, 0, len(rels))
	seen := map[string]bool{}
	for _, r := range rels {
		v := strings.TrimSpace(r.V)
		if !versionToken(v) || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, osvQuery{Lib: key, Eco: osvEco, Name: name, Version: v})
		if len(out) >= maxOSVQueries {
			break
		}
	}
	return out
}

// versionToken reports whether v is a usable single-token version (<= 100 bytes, no whitespace or
// separators the claim layer refuses).
func versionToken(v string) bool {
	if v == "" || len(v) > 100 || !utf8.ValidString(v) {
		return false
	}
	return !strings.ContainsAny(v, " \t\r\n,;")
}

// EnqueueOSV enqueues one osv job per due, unpaused, eligible lib (seeded or referenced, with known
// versions), newest-stale first, within the daily cap. A per-key machine_state row keeps the janitor
// from re-enqueuing before the weekly window or while the lib is paused.
func EnqueueOSV(ctx context.Context, d *core.Deps) error {
	budget, err := dailyRemaining(ctx, d.DB, "osv")
	if err != nil || budget == 0 {
		return err
	}
	if budget > enqueueBatch {
		budget = enqueueBatch
	}
	rows, err := d.DB.Query(ctx, `SELECT l.key FROM libs l
		LEFT JOIN machine_state m ON m.kind = 'osv' AND m.key = l.key
		WHERE jsonb_array_length(l.versions) > 0
		  AND (l.referenced OR EXISTS (SELECT 1 FROM lib_alias a WHERE a.key = l.key AND a.seeded))
		  AND (m.paused_until IS NULL OR m.paused_until <= now())
		  AND (m.fetched_at IS NULL OR m.fetched_at < now() - $1::interval)
		ORDER BY m.fetched_at NULLS FIRST, l.key LIMIT $2`, pgInterval(Refresh), budget)
	if err != nil {
		return err
	}
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	rows.Close()
	for _, key := range keys {
		rels, err := know.Releases(ctx, d.DB, key)
		if err != nil {
			return err
		}
		qs := osvQueries(key, rels)
		if len(qs) == 0 {
			if err := markFetched(ctx, d.DB, "osv", key); err != nil {
				return err
			}
			continue
		}
		payload, err := json.Marshal(osvPayload{Queries: qs})
		if err != nil {
			return err
		}
		if err := core.Egress(ctx, d.DB, "osv", json.RawMessage(payload)); err != nil {
			if err == core.ErrOutboxFull {
				return nil
			}
			return err
		}
		if err := markFetched(ctx, d.DB, "osv", key); err != nil {
			return err
		}
	}
	return nil
}

// IngestOSV is egress.ResultFn["osv"]: it writes a verified security claim per matched vulnerability
// and marks every queried lib fetched (so a lib with no vulnerabilities is not re-enqueued until the
// weekly window). payload and result are courier-produced and fully re-validated here.
func IngestOSV(ctx context.Context, d *core.Deps, q core.Q, payload, result json.RawMessage) error {
	var res osvResult
	if len(result) > 0 {
		if err := json.Unmarshal(result, &res); err != nil {
			return core.Bad("osv result: " + err.Error())
		}
	}
	for _, it := range res.Items {
		key, err := know.ParseKey(it.Lib)
		if err != nil {
			continue
		}
		for i := range it.Vulns {
			if err := ingestOSVVuln(ctx, d, key, &it.Vulns[i]); err != nil {
				return err
			}
		}
	}
	// Mark every queried lib fetched, even those OSV found nothing for.
	var p osvPayload
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &p)
	}
	done := map[string]bool{}
	for _, qy := range p.Queries {
		if key, err := know.ParseKey(qy.Lib); err == nil && !done[key] {
			done[key] = true
			if err := markFetched(ctx, q, "osv", key); err != nil {
				return err
			}
		}
	}
	return nil
}

// ingestOSVVuln writes one security claim for a validated vulnerability. A bad id, an empty title or
// a claim-layer rejection (lexicon, duplicate) is skipped; only database errors propagate.
func ingestOSVVuln(ctx context.Context, d *core.Deps, key string, v *osvVuln) error {
	id := strings.TrimSpace(v.ID)
	if !osvIDRe.MatchString(id) {
		return nil
	}
	from, to := osvSpan(v, key)
	summary := oneLine(v.Summary, osvTitleMax)
	title := id
	if summary != "" {
		title = id + ": " + summary
	}
	in := know.ClaimInput{
		Lib: key, Kind: "security", VFrom: from, VTo: to,
		Title:       cut(title, know.MaxTitle),
		Detail:      cut(oneLine(v.Details, osvDetailMax), know.MaxDetail),
		SourceURL:   "https://osv.dev/vulnerability/" + id,
		Src:         "machine",
		SourceTier:  "official",
		SourceState: "ok",
		Status:      "verified",
	}
	if _, err := know.CreateClaim(ctx, d, systemAuthor(), in); err != nil && !skippable(err) {
		return err
	}
	return nil
}

// osvSpan picks the affected range for key and returns (introduced, fixed). An affected entry whose
// package name matches the queried lib is preferred; "0" introduced (from the beginning) renders as
// no lower bound. last_affected is a fallback upper bound when no fixed version is listed.
func osvSpan(v *osvVuln, key string) (from, to string) {
	_, name := know.Eco(key)
	fold := foldName(name)
	pick := func(match bool) (string, string) {
		for _, a := range v.Affected {
			if match && foldName(a.Package.Name) != fold {
				continue
			}
			for _, r := range a.Ranges {
				if r.Type != "ECOSYSTEM" && r.Type != "SEMVER" {
					continue
				}
				var fr, t string
				for _, e := range r.Events {
					if fr == "" && e.Introduced != "" && e.Introduced != "0" && versionToken(e.Introduced) {
						fr = e.Introduced
					}
					if e.Fixed != "" && versionToken(e.Fixed) {
						t = e.Fixed
					} else if t == "" && e.LastAffected != "" && versionToken(e.LastAffected) {
						t = e.LastAffected
					}
				}
				if fr != "" || t != "" {
					return fr, t
				}
			}
		}
		return "", ""
	}
	if from, to = pick(true); from != "" || to != "" {
		return from, to
	}
	return pick(false)
}

// foldName lowercases and PEP 503-folds a package name for a loose, ecosystem-agnostic comparison.
func foldName(s string) string {
	return strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(strings.TrimSpace(s)))
}
