package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is loaded from the environment (see SPEC "Config" and SPEC-v2 23).
// Secrets come from *_FILE paths; a bare env var of the same name (without _FILE) is accepted for tests.
type Config struct {
	Listen        string
	DatabaseURL   string
	DataDir       string
	ServerSecret  []byte
	AdminToken    string // empty disables /admin
	ForgejoURL    string // empty disables the Forgejo mirror
	ForgejoToken  string
	PowBits       int
	TrustCF       bool
	PublicURL     string
	AbuseContact  string
	UmamiSrc      string
	UmamiID       string
	AllowSameRoot bool
	RegPerHour    int // global registrations per hour (REG_PER_HOUR, default 300); 0 = default

	// v2 (SPEC-v2 23)
	PollToken      string
	OpsToken       string
	CheckToken     string
	CourierToken   string
	ForgejoROToken string
	MirrorURL      string
	LicenseContent string // SPDX id of the content license (CC0-1.0)
	LegalPublisher string
	MetricsListen  string // empty = off
	InternalListen string // courier-facing server (:8081)
	SignKID        int
	ExportDir      string
	SeedWasmDir    string
	PowBitsW       int   // anonymous per-request write PoW bits (16)
	AdminBlobMax   int64 // 64 MiB
	PGMaxBytes     int64 // cap of the built-in pg storage class; 0 = unlimited
	DiskBudget     int64 // sum of class caps must fit; 0 = unchecked
	TrustASN       bool
	EdgeSecret     string
	PGNotify       bool // bridge Notifier through pg_notify (on when loaded from env)
}

// DefaultRegPerHour is the global registration rate used when REG_PER_HOUR is unset.
const DefaultRegPerHour = 300

// DefaultPowBitsW is the anonymous write PoW difficulty when POW_BITS_W is unset.
const DefaultPowBitsW = 16

func LoadConfig() (Config, error) {
	c := Config{
		Listen:         env("LISTEN", ":8080"),
		DatabaseURL:    env("DATABASE_URL", ""),
		DataDir:        env("DATA_DIR", "./data"),
		PublicURL:      strings.TrimRight(env("PUBLIC_URL", "https://agents.ekaii.fr"), "/"),
		AbuseContact:   env("ABUSE_CONTACT", ""),
		UmamiSrc:       env("UMAMI_SRC", ""),
		UmamiID:        env("UMAMI_ID", ""),
		TrustCF:        env("TRUST_CF", "") == "1",
		MirrorURL:      env("MIRROR_URL", ""),
		LicenseContent: env("LICENSE_CONTENT", "CC0-1.0"),
		LegalPublisher: env("LEGAL_PUBLISHER", ""),
		MetricsListen:  env("METRICS_LISTEN", ""),
		InternalListen: env("INTERNAL_LISTEN", ":8081"),
		SeedWasmDir:    env("SEED_WASM_DIR", "/seed"),
		TrustASN:       env("TRUST_ASN", "") == "1",
		PGNotify:       env("PG_NOTIFY", "1") != "0",
	}
	// FORGEJO_URL set to "" disables the mirror; unset keeps the v1 default.
	if v, ok := os.LookupEnv("FORGEJO_URL"); ok {
		c.ForgejoURL = strings.TrimRight(v, "/")
	} else {
		c.ForgejoURL = "http://forgejo:3000"
	}
	c.ExportDir = env("EXPORT_DIR", filepath.Join(c.DataDir, "export"))
	c.AllowSameRoot = env("ALLOW_SAME_ROOT", "") == "1"
	if rph, err := strconv.Atoi(env("REG_PER_HOUR", strconv.Itoa(DefaultRegPerHour))); err != nil || rph < 1 {
		return c, errors.New("REG_PER_HOUR must be a positive integer")
	} else {
		c.RegPerHour = rph
	}
	bits, err := strconv.Atoi(env("POW_BITS", "22"))
	if err != nil || bits < 0 || bits > 64 {
		return c, errors.New("POW_BITS must be 0..64")
	}
	c.PowBits = bits
	if c.PowBitsW, err = strconv.Atoi(env("POW_BITS_W", strconv.Itoa(DefaultPowBitsW))); err != nil || c.PowBitsW < 0 || c.PowBitsW > 40 {
		return c, errors.New("POW_BITS_W must be 0..40")
	}
	if c.SignKID, err = strconv.Atoi(env("SIGN_KID", "1")); err != nil || c.SignKID < 1 {
		return c, errors.New("SIGN_KID must be a positive integer")
	}
	for _, s := range []struct {
		name, def string
		dst       *int64
	}{{"ADMIN_BLOB_MAX", "64M", &c.AdminBlobMax}, {"PG_MAX_BYTES", "0", &c.PGMaxBytes}, {"DISK_BUDGET", "0", &c.DiskBudget}} {
		if *s.dst, err = ParseBytes(env(s.name, s.def)); err != nil {
			return c, fmt.Errorf("%s: %w", s.name, err)
		}
	}
	if c.DatabaseURL == "" {
		return c, errors.New("DATABASE_URL required")
	}
	s, err := Secret("SERVER_SECRET")
	if err != nil {
		return c, err
	}
	if len(s) < 16 {
		return c, errors.New("SERVER_SECRET too short (need >= 16 bytes)")
	}
	c.ServerSecret = []byte(s)
	for _, sec := range []struct {
		name string
		dst  *string
	}{{"ADMIN_TOKEN", &c.AdminToken}, {"FORGEJO_TOKEN", &c.ForgejoToken}, {"POLL_TOKEN", &c.PollToken},
		{"OPS_TOKEN", &c.OpsToken}, {"CHECK_TOKEN", &c.CheckToken}, {"COURIER_TOKEN", &c.CourierToken},
		{"FORGEJO_RO_TOKEN", &c.ForgejoROToken}, {"EDGE_SECRET", &c.EdgeSecret}} {
		if *sec.dst, err = Secret(sec.name); err != nil {
			return c, err
		}
	}
	return c, nil
}

// ParseBytes parses a byte size: a plain integer or one with a K/M/G/T suffix (binary units).
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, nil
	}
	mult := int64(1)
	for _, u := range []struct {
		suf string
		m   int64
	}{{"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}} {
		if strings.HasSuffix(s, u.suf+"IB") || strings.HasSuffix(s, u.suf+"B") || strings.HasSuffix(s, u.suf) {
			mult = u.m
			s = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(s, "IB"), "B"), u.suf)
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("bad size")
	}
	return n * mult, nil
}

// Secret reads NAME_FILE (trimmed) if set, else NAME; empty when neither is set.
func Secret(name string) (string, error) {
	if p := os.Getenv(name + "_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", name, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(os.Getenv(name)), nil
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}
