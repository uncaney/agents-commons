package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is read from the environment (see SPEC "Worker", SPEC-v2 14.4 and 27.6).
type Config struct {
	URL       string
	Token     string
	MaxMs     int
	MaxMb     int
	Parallel  int
	Hours     Window
	CacheDir  string
	MemLimit  int  // MiB; Go soft memory limit (MEM_LIMIT_MB, default 400), also the compile child's GOMEMLIMIT
	PinMaxMb  int  // PIN_MAX_MB: largest pinned module warmed and accepted (0 = v1 behaviour: no pins)
	CompileMs int  // COMPILE_MS: budget of the child-process compile (default 10 s)
	AcceptNew bool // ACCEPT_NEW=1: run modules under probation (cap new)
	AcceptL0  bool // ACCEPT_L0=1: run jobs of L0 submitters (cap l0)
}

func loadConfig(getenv func(string) string) (Config, error) {
	c := Config{URL: "https://agents.ekaii.fr", MaxMs: 30000, MaxMb: 256, Parallel: 1, MemLimit: 400, CompileMs: 10000}
	if v := getenv("CX_URL"); v != "" {
		c.URL = strings.TrimRight(v, "/")
	}
	tf := getenv("CX_TOKEN_FILE")
	if tf == "" {
		return c, errors.New("CX_TOKEN_FILE is required")
	}
	b, err := os.ReadFile(tf)
	if err != nil {
		return c, fmt.Errorf("token file: %w", err)
	}
	c.Token = strings.TrimSpace(string(b))
	if c.Token == "" {
		return c, errors.New("token file is empty")
	}
	if c.MaxMs, err = envInt(getenv, "MAX_MS", c.MaxMs, 100, 30000); err != nil {
		return c, err
	}
	if c.MaxMb, err = envInt(getenv, "MAX_MB", c.MaxMb, 1, 256); err != nil {
		return c, err
	}
	if c.Parallel, err = envInt(getenv, "PARALLEL", c.Parallel, 1, 64); err != nil {
		return c, err
	}
	if c.MemLimit, err = envInt(getenv, "MEM_LIMIT_MB", c.MemLimit, 64, 1<<20); err != nil {
		return c, err
	}
	if c.PinMaxMb, err = envInt(getenv, "PIN_MAX_MB", 0, 0, 1024); err != nil {
		return c, err
	}
	if c.CompileMs, err = envInt(getenv, "COMPILE_MS", c.CompileMs, 100, 600000); err != nil {
		return c, err
	}
	if c.Hours, err = ParseWindow(getenv("HOURS")); err != nil {
		return c, err
	}
	c.CacheDir = getenv("CACHE_DIR")
	if c.PinMaxMb > 0 && c.CacheDir == "" {
		return c, errors.New("PIN_MAX_MB needs CACHE_DIR (pinned modules are warmed on disk)")
	}
	c.AcceptNew, c.AcceptL0 = getenv("ACCEPT_NEW") == "1", getenv("ACCEPT_L0") == "1"
	return c, nil
}

func envInt(getenv func(string) string, key string, def, min, max int) (int, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s: want integer in [%d,%d], got %q", key, min, max, v)
	}
	return n, nil
}

// Window is a daily local-time window [Start, End) in minutes from midnight.
// Start == End (including the zero value) means always active; Start > End
// wraps past midnight (e.g. 22-07).
type Window struct{ Start, End int }

// ParseWindow accepts "", "HH-HH" or "HH:MM-HH:MM" (24h clock, 24 allowed as end).
func ParseWindow(s string) (Window, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Window{}, nil
	}
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return Window{}, fmt.Errorf("HOURS: want HH-HH, got %q", s)
	}
	start, err := parseHM(a)
	if err != nil {
		return Window{}, fmt.Errorf("HOURS: %w", err)
	}
	end, err := parseHM(b)
	if err != nil {
		return Window{}, fmt.Errorf("HOURS: %w", err)
	}
	return Window{start % 1440, end % 1440}, nil
}

func parseHM(s string) (int, error) {
	h, m, _ := strings.Cut(strings.TrimSpace(s), ":")
	hh, err := strconv.Atoi(h)
	if err != nil || hh < 0 || hh > 24 {
		return 0, fmt.Errorf("bad hour %q", s)
	}
	mm := 0
	if m != "" {
		if mm, err = strconv.Atoi(m); err != nil || mm < 0 || mm > 59 {
			return 0, fmt.Errorf("bad minute %q", s)
		}
	}
	return hh*60 + mm, nil
}

// Always reports whether the window covers the whole day.
func (w Window) Always() bool { return w.Start == w.End }

// Contains reports whether t (local time) is inside the window.
func (w Window) Contains(t time.Time) bool {
	if w.Always() {
		return true
	}
	m := t.Hour()*60 + t.Minute()
	if w.Start < w.End {
		return m >= w.Start && m < w.End
	}
	return m >= w.Start || m < w.End
}

// Until returns how long to wait from t until the window is active (0 if it is).
func (w Window) Until(t time.Time) time.Duration {
	if w.Contains(t) {
		return 0
	}
	next := time.Date(t.Year(), t.Month(), t.Day(), w.Start/60, w.Start%60, 0, 0, t.Location())
	if !next.After(t) {
		next = next.Add(24 * time.Hour)
	}
	return next.Sub(t)
}

func (w Window) String() string {
	if w.Always() {
		return "always"
	}
	return fmt.Sprintf("%02d:%02d-%02d:%02d", w.Start/60, w.Start%60, w.End/60, w.End%60)
}
