package swarm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Shared upstream rate limiter (12.6): one token bucket per key, decided by a single
// `INSERT … ON CONFLICT DO UPDATE … RETURNING` so every gateway instance agrees.
const (
	rlMaxKeys  = 100
	rlRateMax  = 1000
	rlBurstMax = 10000
)

type rlIn struct {
	Rate  float64 `json:"rate"`
	Burst float64 `json:"burst"`
	Cost  float64 `json:"cost"`
}

const rlSQL = `INSERT INTO rl_buckets (key, root, tokens, last, ok)
	SELECT $1, $2, $3::float8 - $5::float8, now(), true
	WHERE (SELECT count(*) FROM rl_buckets WHERE root = $2) < $6 OR EXISTS (SELECT 1 FROM rl_buckets WHERE key = $1)
	ON CONFLICT (key) DO UPDATE SET
		ok = least($3::float8, rl_buckets.tokens::float8 + extract(epoch from (now() - rl_buckets.last))::float8 * $4::float8) >= $5::float8,
		tokens = least($3::float8, rl_buckets.tokens::float8 + extract(epoch from (now() - rl_buckets.last))::float8 * $4::float8)
			- CASE WHEN least($3::float8, rl_buckets.tokens::float8 + extract(epoch from (now() - rl_buckets.last))::float8 * $4::float8) >= $5::float8 THEN $5::float8 ELSE 0 END,
		last = now()
	RETURNING ok, tokens::float8`

// limit is POST /v1/rl/{key} and op rl: `ok left=<tokens>` or `429 err rate wait_ms=<n>`.
func (s *svc) limit(ctx context.Context, id *core.Ident, raw string, in rlIn) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if n.NS == 'g' {
		return reply{}, core.Bad("key: ~<name>, a:<root>.<name>, s:<slug>.<name> or r:<room>.<name> (no g:)")
	}
	if err := Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	if !(in.Rate > 0 && in.Rate <= rlRateMax) || math.IsNaN(in.Rate) {
		return reply{}, core.Bad("rate must be 0 < rate <= 1000 (tokens per second)")
	}
	burst := in.Burst
	if burst == 0 {
		burst = math.Ceil(in.Rate)
	}
	if !(burst >= 1 && burst <= rlBurstMax) {
		return reply{}, core.Bad("burst must be 1..10000")
	}
	cost := in.Cost
	if cost == 0 {
		cost = 1
	}
	if !(cost > 0 && cost <= burst) {
		return reply{}, core.Bad("cost must be 0 < cost <= burst")
	}
	if err := s.frozen("swarm"); err != nil {
		return reply{}, err
	}
	kh := sha256.Sum256([]byte("rl:" + n.Full))
	var ok bool
	var tokens float64
	err = s.d.DB.QueryRow(ctx, rlSQL, hex.EncodeToString(kh[:]), id.Root, burst, in.Rate, cost, rlMaxKeys).Scan(&ok, &tokens)
	if errors.Is(err, pgx.ErrNoRows) {
		return reply{}, quotaErr("rl keys", rlMaxKeys)
	}
	if err != nil {
		return reply{}, err
	}
	if !ok {
		ms := max(1, int(math.Ceil((cost-tokens)/in.Rate*1000)))
		return reply{}, core.E(429, "rate", "wait_ms="+strconv.Itoa(ms))
	}
	return reply{text: fmt.Sprintf("ok left=%.1f", tokens), next: []doc.Action{doc.POST("/v1/rl/"+n.Full, "take")}}, nil
}

func (s *svc) rlTake(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in rlIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.limit(r.Context(), id, r.PathValue("key"), in)
	if err != nil {
		var ae *core.APIError
		if errors.As(err, &ae) && ae.Code == "rate" {
			if v, ok := strings.CutPrefix(ae.Msg, "wait_ms="); ok {
				if ms, perr := strconv.Atoi(v); perr == nil {
					w.Header().Set("Retry-After", strconv.Itoa((ms+999)/1000))
				}
			}
		}
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

// janRL deletes buckets idle for 7 days.
func (s *svc) janRL(ctx context.Context) error {
	_, err := s.d.DB.Exec(ctx, `DELETE FROM rl_buckets WHERE last < now() - interval '7 days'`)
	return err
}
