package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// osv (SPEC-v2 27.9): POST api.osv.dev/v1/querybatch with the (ecosystem, name, version) entries the
// gateway built from validated lib keys and known versions, then fetch the full record of each
// matched vulnerability and return, per queried (lib, version), the vulnerabilities with their
// affected ranges. The gateway (machineclaims.IngestOSV) turns those into verified security claims.
// OSV text is untrusted: ids are regex-validated before they reach a URL, bodies are 1 MiB-capped.

const (
	osvMaxQueries  = 1000
	osvMaxBody     = 1 << 20 // 1 MiB cap on the querybatch request body (27.9)
	osvMaxVulns    = 256     // distinct vulnerabilities fetched per job
	osvMaxTextSave = 4000
)

var (
	osvIDReC   = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,19}-[A-Za-z0-9][A-Za-z0-9-]{0,98}$`)
	osvEcoSetC = map[string]bool{"PyPI": true, "npm": true, "Go": true, "crates.io": true, "RubyGems": true,
		"Maven": true, "NuGet": true, "Packagist": true, "Pub": true, "Hex": true}
)

func init() {
	Register(&Kind{Name: "osv", Hosts: []string{"api.osv.dev"}, Run: runOSV})
}

type osvQueryIn struct {
	Lib     string `json:"lib"`
	Eco     string `json:"eco"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// osv result shape (matches internal/machineclaims).
type osvResultOut struct {
	Fetched string       `json:"fetched"`
	Items   []osvItemOut `json:"items"`
}

type osvItemOut struct {
	Lib   string       `json:"lib"`
	V     string       `json:"v"`
	Vulns []osvVulnOut `json:"vulns"`
}

type osvVulnOut struct {
	ID       string           `json:"id"`
	Summary  string           `json:"summary,omitempty"`
	Details  string           `json:"details,omitempty"`
	Affected []osvAffectedOut `json:"affected,omitempty"`
}

type osvAffectedOut struct {
	Package osvPkgOut    `json:"package"`
	Ranges  []osvRangeIO `json:"ranges,omitempty"`
}

type osvPkgOut struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvRangeIO struct {
	Type   string       `json:"type"`
	Events []osvEventIO `json:"events,omitempty"`
}

type osvEventIO struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

func runOSV(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
	var p struct {
		Queries []osvQueryIn `json:"queries"`
	}
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		return nil, fmt.Errorf("osv: payload: %w", err)
	}
	// Build the querybatch body only from validated entries (ecosystem known, name and version
	// non-empty single tokens); keep the alignment to the kept entries.
	type batchQ struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Version string `json:"version"`
	}
	var kept []osvQueryIn
	var body struct {
		Queries []batchQ `json:"queries"`
	}
	for _, q := range p.Queries {
		if len(kept) >= osvMaxQueries || !osvEcoSetC[q.Eco] || q.Name == "" || !osvVersionOK(q.Version) || q.Lib == "" {
			continue
		}
		var bq batchQ
		bq.Package.Ecosystem, bq.Package.Name, bq.Version = q.Eco, q.Name, q.Version
		body.Queries = append(body.Queries, bq)
		kept = append(kept, q)
	}
	res := osvResultOut{Fetched: e.Now().UTC().Format(time.RFC3339)}
	if len(kept) == 0 {
		return json.Marshal(res)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if len(raw) > osvMaxBody {
		return nil, soft("osv: querybatch body over 1 MiB")
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.osv.dev/v1/querybatch", strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	code, respBody, _, err := e.Do(ctx, req, readCap, dialTimeout)
	if errors.Is(err, errTooLarge) {
		return nil, soft("osv: querybatch response too large")
	}
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, statusErr("osv querybatch", code, respBody)
	}
	var batch struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.Unmarshal(respBody, &batch); err != nil {
		return nil, soft("osv: unparseable querybatch json")
	}
	// Collect the distinct, valid vulnerability ids and fetch each record once.
	ids := map[string]bool{}
	for _, r := range batch.Results {
		for _, v := range r.Vulns {
			if osvIDReC.MatchString(v.ID) {
				ids[v.ID] = true
			}
		}
	}
	idList := make([]string, 0, len(ids))
	for id := range ids {
		idList = append(idList, id)
	}
	sort.Strings(idList)
	if len(idList) > osvMaxVulns {
		idList = idList[:osvMaxVulns]
	}
	records := map[string]osvVulnOut{}
	for _, id := range idList {
		v, err := fetchOSVVuln(ctx, e, id)
		if err != nil {
			var s *softErr
			if errors.As(err, &s) {
				continue // a single missing record never fails the batch
			}
			return nil, err
		}
		records[id] = v
	}
	for i, r := range batch.Results {
		if i >= len(kept) || len(r.Vulns) == 0 {
			continue
		}
		item := osvItemOut{Lib: kept[i].Lib, V: kept[i].Version}
		for _, vr := range r.Vulns {
			if rec, ok := records[vr.ID]; ok {
				item.Vulns = append(item.Vulns, rec)
			}
		}
		if len(item.Vulns) > 0 {
			res.Items = append(res.Items, item)
		}
	}
	return json.Marshal(res)
}

// fetchOSVVuln fetches one vulnerability record and keeps only the fields the gateway ingests.
func fetchOSVVuln(ctx context.Context, e *Env, id string) (osvVulnOut, error) {
	if !osvIDReC.MatchString(id) {
		return osvVulnOut{}, soft("osv: bad id")
	}
	code, body, err := getJSON(ctx, e, "https://api.osv.dev/v1/vulns/"+id)
	if errors.Is(err, errTooLarge) {
		return osvVulnOut{}, soft("osv: record too large")
	}
	if err != nil {
		return osvVulnOut{}, err
	}
	if code == 404 || code == 410 {
		return osvVulnOut{}, soft("osv: not found")
	}
	if code != 200 {
		return osvVulnOut{}, statusErr("osv vuln", code, body)
	}
	var doc struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Details  string `json:"details"`
		Affected []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Type   string `json:"type"`
				Events []struct {
					Introduced   string `json:"introduced"`
					Fixed        string `json:"fixed"`
					LastAffected string `json:"last_affected"`
				} `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return osvVulnOut{}, soft("osv: unparseable record json")
	}
	out := osvVulnOut{ID: id, Summary: oneLine(doc.Summary, 200), Details: oneLine(doc.Details, osvMaxTextSave)}
	for _, a := range doc.Affected {
		ao := osvAffectedOut{}
		ao.Package.Ecosystem, ao.Package.Name = oneLine(a.Package.Ecosystem, 40), oneLine(a.Package.Name, 200)
		for _, r := range a.Ranges {
			ro := osvRangeIO{Type: oneLine(r.Type, 20)}
			for _, ev := range r.Events {
				ro.Events = append(ro.Events, osvEventIO{
					Introduced:   oneLine(ev.Introduced, 100),
					Fixed:        oneLine(ev.Fixed, 100),
					LastAffected: oneLine(ev.LastAffected, 100),
				})
			}
			ao.Ranges = append(ao.Ranges, ro)
		}
		out.Affected = append(out.Affected, ao)
	}
	return out, nil
}

// osvVersionOK reports whether v is a usable single-token version.
func osvVersionOK(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && len(v) <= 100 && !strings.ContainsAny(v, " \t\r\n,;")
}
