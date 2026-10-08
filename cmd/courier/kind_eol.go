package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// eol (SPEC-v2 27.9): GET endoflife.date/api/<product>.json for a tracked product and return the
// normalised cycles. The gateway (machineclaims.IngestEOL) turns each cycle into verified release
// and eol claims. endoflife's `eol`/`lts`/`support` fields may be a bool or a date string; they are
// normalised to "" (not end-of-life), a YYYY-MM-DD date, or the marker "eol".

const eolMaxCycles = 500

var eolProductRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,39}$`)

func init() {
	Register(&Kind{Name: "eol", Hosts: []string{"endoflife.date"}, Run: runEOL})
}

type eolCycleOut struct {
	Cycle       string `json:"cycle"`
	ReleaseDate string `json:"release_date,omitempty"`
	EOL         string `json:"eol,omitempty"`
	Latest      string `json:"latest,omitempty"`
}

type eolResultOut struct {
	Product string        `json:"product"`
	Lib     string        `json:"lib"`
	Fetched string        `json:"fetched"`
	Cycles  []eolCycleOut `json:"cycles,omitempty"`
}

func runEOL(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
	var p struct {
		Product string `json:"product"`
		Lib     string `json:"lib"`
	}
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		return nil, fmt.Errorf("eol: payload: %w", err)
	}
	product := strings.ToLower(strings.TrimSpace(p.Product))
	if !eolProductRe.MatchString(product) {
		return nil, soft("eol: bad product")
	}
	res := eolResultOut{Product: product, Lib: oneLine(p.Lib, 220), Fetched: e.Now().UTC().Format(time.RFC3339)}
	code, body, err := getJSON(ctx, e, "https://endoflife.date/api/"+product+".json")
	if errors.Is(err, errTooLarge) {
		return nil, soft("eol: response too large")
	}
	if err != nil {
		return nil, err
	}
	if code == 404 || code == 410 {
		return json.Marshal(res) // unknown product: an empty, definitive answer
	}
	if code != 200 {
		return nil, statusErr("eol", code, body)
	}
	var cycles []struct {
		Cycle       json.RawMessage `json:"cycle"`
		ReleaseDate string          `json:"releaseDate"`
		EOL         json.RawMessage `json:"eol"`
		Latest      string          `json:"latest"`
	}
	if err := json.Unmarshal(body, &cycles); err != nil {
		return nil, soft("eol: unparseable json")
	}
	for i, c := range cycles {
		if i >= eolMaxCycles {
			break
		}
		cyc := oneLine(rawScalar(c.Cycle), 60)
		if cyc == "" {
			continue
		}
		res.Cycles = append(res.Cycles, eolCycleOut{
			Cycle:       cyc,
			ReleaseDate: eolDay(c.ReleaseDate),
			EOL:         normEOL(c.EOL),
			Latest:      oneLine(c.Latest, 100),
		})
	}
	return json.Marshal(res)
}

// rawScalar decodes a JSON scalar (string, number or bool) to its string form.
func rawScalar(raw json.RawMessage) string {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.Trim(string(raw), `"`)
}

// normEOL normalises endoflife's eol field (a bool or a date string) to "", a date, or "eol".
func normEOL(raw json.RawMessage) string {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		if b {
			return "eol"
		}
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	if d := eolDay(s); d != "" {
		return d
	}
	return ""
}

// eolDay keeps a leading YYYY-MM-DD date and drops anything else.
func eolDay(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 10 {
		s = s[:10]
	}
	if _, err := time.Parse("2006-01-02", s); err == nil {
		return s
	}
	return ""
}
