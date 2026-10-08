package machineclaims

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/know"
)

// endoflife.date ingestion (27.9): the courier GETs /api/<product>.json and returns the normalised
// cycles; each cycle yields a verified `release` claim (its release date) and, once the cycle has a
// known end-of-life date, a verified `eol` claim. Claims of one product are kept distinct by a
// ?cycle= query on the endoflife.date permalink so the (lib, kind, source_url) index does not fold
// them together.

// eolProductRe guards the product name before it enters a URL path or a lib lookup.
const eolTitleMax = 140

// eolPayload is the eol job payload.
type eolPayload struct {
	Product string `json:"product"`
	Lib     string `json:"lib"`
}

// eolResult is the courier ack: the product's lib key and its normalised cycles.
type eolResult struct {
	Product string     `json:"product"`
	Lib     string     `json:"lib"`
	Fetched string     `json:"fetched"`
	Cycles  []eolCycle `json:"cycles"`
}

// eolCycle is one normalised endoflife.date cycle. EOL is "" (not end-of-life or unknown), a
// YYYY-MM-DD date, or the marker "eol" when the cycle is already past end-of-life without a date.
type eolCycle struct {
	Cycle       string `json:"cycle"`
	ReleaseDate string `json:"release_date"`
	EOL         string `json:"eol"`
	Latest      string `json:"latest"`
}

// Products lists the endoflife.date products P117 tracks (sorted; for tests and the enqueue).
func Products() []string {
	out := make([]string, 0, len(productMap))
	for p := range productMap {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// EnqueueEOL enqueues one eol job per tracked product that is due and not paused, within the daily
// cap. machine_state keys eol state by the product's lib key, so a dispute pause on that lib pauses
// the product here too.
func EnqueueEOL(ctx context.Context, d *core.Deps) error {
	budget, err := dailyRemaining(ctx, d.DB, "eol")
	if err != nil || budget == 0 {
		return err
	}
	for _, product := range Products() {
		if budget == 0 {
			return nil
		}
		lib := productMap[product]
		var due bool
		err := d.DB.QueryRow(ctx, `SELECT coalesce((SELECT (paused_until IS NULL OR paused_until <= now())
			AND (fetched_at IS NULL OR fetched_at < now() - $1::interval) FROM machine_state WHERE kind = 'eol' AND key = $2), true)`,
			pgInterval(Refresh), lib).Scan(&due)
		if err != nil {
			return err
		}
		if !due {
			continue
		}
		payload, err := json.Marshal(eolPayload{Product: product, Lib: lib})
		if err != nil {
			return err
		}
		if err := core.Egress(ctx, d.DB, "eol", json.RawMessage(payload)); err != nil {
			if err == core.ErrOutboxFull {
				return nil
			}
			return err
		}
		if err := markFetched(ctx, d.DB, "eol", lib); err != nil {
			return err
		}
		budget--
	}
	return nil
}

// IngestEOL is egress.ResultFn["eol"]: it writes the release and eol claims of a product's cycles
// and marks the product fetched. The result's lib is trusted only after it parses as a known key
// bound to the result's product.
func IngestEOL(ctx context.Context, d *core.Deps, q core.Q, payload, result json.RawMessage) error {
	var res eolResult
	if len(result) > 0 {
		if err := json.Unmarshal(result, &res); err != nil {
			return core.Bad("eol result: " + err.Error())
		}
	}
	product := strings.ToLower(strings.TrimSpace(res.Product))
	want, ok := productMap[product]
	if !ok {
		return nil
	}
	key, err := know.ParseKey(res.Lib)
	if err != nil || key != want {
		key = want
	}
	for i := range res.Cycles {
		if err := ingestEOLCycle(ctx, d, product, key, &res.Cycles[i]); err != nil {
			return err
		}
	}
	return markFetched(ctx, q, "eol", key)
}

// ingestEOLCycle writes the release and (when dated) eol claim for one cycle.
func ingestEOLCycle(ctx context.Context, d *core.Deps, product, key string, c *eolCycle) error {
	cycle := oneLine(c.Cycle, 60)
	if cycle == "" {
		return nil
	}
	src := "https://endoflife.date/" + product + "?cycle=" + cycle
	latest := ""
	if versionToken(c.Latest) {
		latest = c.Latest
	}
	// release claim: the cycle's first release.
	relTitle := product + " " + cycle + " released"
	if latest != "" {
		relTitle += " (" + latest + ")"
	}
	rel := know.ClaimInput{
		Lib: key, Kind: "release", VTo: firstNonEmpty(latest, cycle), Effective: eolDate(c.ReleaseDate),
		Title: cut(relTitle, know.MaxTitle), SourceURL: src,
		Src: "machine", SourceTier: "official", SourceState: "ok", Status: "verified",
	}
	if _, err := know.CreateClaim(ctx, d, systemAuthor(), rel); err != nil && !skippable(err) {
		return err
	}
	// eol claim: only once the cycle has reached (or is dated for) end-of-life.
	eff, dated := eolEffective(c.EOL)
	if !dated {
		return nil
	}
	eolTitle := product + " " + cycle + " end-of-life"
	if eff != "" {
		eolTitle += " " + eff
	}
	eol := know.ClaimInput{
		Lib: key, Kind: "eol", VTo: firstNonEmpty(latest, cycle), Effective: eff,
		Title: cut(eolTitle, know.MaxTitle), SourceURL: src,
		Src: "machine", SourceTier: "official", SourceState: "ok", Status: "verified",
	}
	if _, err := know.CreateClaim(ctx, d, systemAuthor(), eol); err != nil && !skippable(err) {
		return err
	}
	return nil
}

// eolEffective interprets a normalised EOL field: a date returns (date, true); the "eol" marker
// returns ("", true) (end-of-life reached, no date); anything else returns ("", false).
func eolEffective(s string) (string, bool) {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || s == "false":
		return "", false
	case s == "eol" || s == "true":
		return "", true
	default:
		if d := eolDate(s); d != "" {
			return d, true
		}
		return "", false
	}
}

// eolDate keeps a YYYY-MM-DD (or YYYY-MM) date and drops anything else (the claim layer re-checks).
func eolDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 10 {
		s = s[:10]
	}
	for _, layout := range []string{"2006-01-02", "2006-01"} {
		if _, err := time.Parse(layout, s); err == nil {
			return s
		}
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
