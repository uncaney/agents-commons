package keys

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/scrub"
)

// Policy pack (E2EE 9.4): `{v, rules_v, secret_regexes[], buckets, caps, banner, min_cs, batch_hours,
// stamp_bits}` served by GET /v1/policy with X-Cx-Sig-Server and its sha256 logged as a kind 5 leaf,
// so a weaker pack served by the CDN fails against the log. Clients pin (v, hash).

type policyPack struct {
	V    int
	Hash []byte
	Body []byte
	Leaf int64
}

type policyBody struct {
	V             int              `json:"v"`
	RulesV        int              `json:"rules_v"`
	SecretRegexes []string         `json:"secret_regexes"`
	Buckets       map[string][]int `json:"buckets"`
	Caps          map[string]int   `json:"caps"`
	Banner        string           `json:"banner"`
	MinCS         int              `json:"min_cs"`
	BatchHours    []int            `json:"batch_hours"`
	StampBits     int              `json:"stamp_bits"`
}

const banner = "sealed mail exists; keys are published; reports are recipient-revealed. A client that did not verify its code and the server key against the mirror runs at tier C/D: encrypted, keys unverified."

// buildPolicy renders the pack body for version v (deterministic: fixed field order, sorted maps).
func buildPolicy(v int, publicURL string) []byte {
	b := policyBody{V: v, RulesV: scrub.RulesV, SecretRegexes: tier1Regexes(publicURL),
		Buckets: map[string][]int{"pair": {1024, 4096}, "group": {1024, 4096}, "object": {4096, 16384, 65536}},
		Caps:    map[string]int{"bundle": e2e.BundleCap, "envelope": 6144, "group_msg": 4096 + 16, "object": 65536 + 16, "state": 65536},
		Banner:  banner, MinCS: int(e2e.CS1), BatchHours: batchHours(), StampBits: envInt("E2E_STAMP_BITS", 18, 8, 40)}
	out, _ := json.Marshal(b)
	return append(out, '\n')
}

// tier1Regexes extracts the tier-1 rules of GET /scrub/rules (name<TAB>regex lines, kind = name
// before the dot, tier-1 kinds listed in the first line).
func tier1Regexes(publicURL string) []string {
	lines := strings.Split(scrub.RulesText(publicURL), "\n")
	if len(lines) == 0 {
		return nil
	}
	t1 := map[string]bool{}
	for _, f := range strings.Fields(lines[0]) {
		if v, ok := strings.CutPrefix(f, "tier1="); ok {
			for _, k := range strings.Split(v, ",") {
				t1[k] = true
			}
		}
	}
	var out []string
	for _, l := range lines[1:] {
		name, re, ok := strings.Cut(l, "\t")
		if !ok || strings.HasPrefix(l, "#") || strings.ContainsAny(name, " =(") {
			continue
		}
		kind, _, _ := strings.Cut(name, ".")
		if t1[kind] && re != "" {
			out = append(out, re)
		}
	}
	return out
}

func batchHours() []int {
	v := strings.TrimSpace(os.Getenv("E2E_BATCH_HOURS"))
	if v == "" {
		return []int{0, 6, 12, 18}
	}
	var out []int
	for _, f := range strings.Split(v, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 0 || n > 23 {
			return []int{0, 6, 12, 18}
		}
		out = append(out, n)
	}
	return out
}

func envInt(name string, def, lo, hi int) int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || n < lo || n > hi {
		return def
	}
	return n
}

// ensurePolicy stores and logs the pack when its content changed since the latest version (or
// logs a stored pack that has no leaf yet), then caches it.
func (s *svc) ensurePolicy(ctx context.Context) error {
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := lockLog(ctx, tx); err != nil {
			return err
		}
		p := &policyPack{}
		var leaf *int64
		err := tx.QueryRow(ctx, `SELECT v, hash, body, leaf FROM policy_pack ORDER BY v DESC LIMIT 1`).Scan(&p.V, &p.Hash, &p.Body, &leaf)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			if leaf != nil {
				p.Leaf = *leaf
			}
			if cand := buildPolicy(p.V, s.d.Cfg.PublicURL); hmac.Equal(e2e.Sum(cand), p.Hash) {
				if leaf == nil {
					idx, _, err := appendLeaf(ctx, tx, KindPolicy, core.SystemID, p.V, p.Hash)
					if err != nil {
						return err
					}
					if _, err := tx.Exec(ctx, `UPDATE policy_pack SET leaf = $2 WHERE v = $1`, p.V, int64(idx)); err != nil {
						return err
					}
					p.Leaf = int64(idx)
				}
				s.policy.Store(p)
				return nil
			}
		}
		v := p.V + 1
		body := buildPolicy(v, s.d.Cfg.PublicURL)
		hash := e2e.Sum(body)
		if _, err := tx.Exec(ctx, `INSERT INTO policy_pack (v, hash, body) VALUES ($1, $2, $3)`, v, hash, body); err != nil {
			return err
		}
		idx, _, err := appendLeaf(ctx, tx, KindPolicy, core.SystemID, v, hash)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE policy_pack SET leaf = $2 WHERE v = $1`, v, int64(idx)); err != nil {
			return err
		}
		s.policy.Store(&policyPack{V: v, Hash: hash, Body: body, Leaf: int64(idx)})
		return nil
	})
}

// currentPolicy returns the cached pack, loading it when the cache is cold.
func (s *svc) currentPolicy(ctx context.Context) (*policyPack, error) {
	if p := s.policy.Load(); p != nil {
		return p, nil
	}
	if err := s.ensurePolicy(ctx); err != nil {
		return nil, err
	}
	if p := s.policy.Load(); p != nil {
		return p, nil
	}
	return nil, ErrNotReady
}
