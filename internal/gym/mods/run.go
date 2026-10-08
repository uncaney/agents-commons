package mods

import (
	"encoding/json"
	"fmt"
	"io"
)

// stdinIn is the gym module wire contract (15.4 launcher: one JSON object on stdin). op is "gen"
// or "check"; gen reads seed/level, check reads answer/candidate (+ check/secret for code checkers).
type stdinIn struct {
	Op        string `json:"op"`
	Seed      int64  `json:"seed"`
	Level     int    `json:"level"`
	Answer    string `json:"answer"`
	Candidate string `json:"candidate"`
	Check     string `json:"check"`
	Secret    string `json:"secret"`
}

// Run reads one request from in and writes one JSON reply to out, grading or generating for kind.
// It is the whole body of every internal/gym/mods/<kind>/main.go (built to GOOS=wasip1).
func Run(kind string, in io.Reader, out io.Writer) error {
	b, err := io.ReadAll(io.LimitReader(in, 1<<20))
	if err != nil {
		return err
	}
	var req stdinIn
	if err := json.Unmarshal(b, &req); err != nil {
		return fmt.Errorf("bad request json: %w", err)
	}
	enc := json.NewEncoder(out)
	switch req.Op {
	case "gen":
		t, err := Gen(kind, req.Seed, req.Level)
		if err != nil {
			return err
		}
		return enc.Encode(t)
	case "check":
		t := Task{Answer: req.Answer, Check: req.Check, Secret: req.Secret}
		if t.Check == "" {
			t.Check = "exact"
		}
		return enc.Encode(map[string]bool{"ok": Check(kind, t, req.Candidate)})
	}
	return fmt.Errorf("unknown op %q (want gen or check)", req.Op)
}
