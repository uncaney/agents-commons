package core

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
)

// Egress outbox caps (SPEC 20): 10k live rows, per-kind caps, and reserved headroom for the
// kinds that must never be starved by the others.
const (
	EgressMaxLive      = 10_000
	EgressMaxPayload   = 64 << 10
	egressReservedEach = 500
	egressDefaultCap   = 1000
)

var (
	egressKindCaps = map[string]int{"indexnow": 4000, "libmeta": 500, "hf": 200, "mirror": 200, "anchor": 50}
	egressDailyCap = map[string]int{"libmeta": 500}
	egressReserved = map[string]bool{"backup_ship": true, "mirror_rewrite": true, "cf_purge": true}
	egressKindRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

	// ErrOutboxFull is returned when a cap refuses the row; callers log and continue (nothing
	// user-visible depends on egress, SPEC 20 fallback).
	ErrOutboxFull = errors.New("egress outbox full")
)

// Egress enqueues a courier job inside the caller's tx. payload is marshalled to JSON (<= 64 KiB).
func Egress(ctx context.Context, q Q, kind string, payload any) error {
	if !egressKindRe.MatchString(kind) {
		return Bad("egress kind")
	}
	var raw json.RawMessage
	switch p := payload.(type) {
	case json.RawMessage:
		raw = p
	case []byte:
		raw = p
	default:
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		raw = b
	}
	if len(raw) == 0 || !json.Valid(raw) {
		return Bad("egress payload")
	}
	if len(raw) > EgressMaxPayload {
		return ErrSize
	}
	var live, kindLive, shared, day int
	err := q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE done_at IS NULL),
		count(*) FILTER (WHERE done_at IS NULL AND kind = $1),
		count(*) FILTER (WHERE done_at IS NULL AND NOT (kind = ANY($2))),
		count(*) FILTER (WHERE kind = $1 AND created > now() - interval '1 day')
		FROM egress_outbox WHERE done_at IS NULL OR created > now() - interval '1 day'`,
		kind, reservedKinds()).Scan(&live, &kindLive, &shared, &day)
	if err != nil {
		return err
	}
	if live >= EgressMaxLive {
		return ErrOutboxFull
	}
	if !egressReserved[kind] {
		if shared >= EgressMaxLive-egressReservedEach*len(egressReserved) {
			return ErrOutboxFull
		}
		kcap := egressDefaultCap
		if c, ok := egressKindCaps[kind]; ok {
			kcap = c
		}
		if kindLive >= kcap {
			return ErrOutboxFull
		}
		if dc, ok := egressDailyCap[kind]; ok && day >= dc {
			return ErrOutboxFull
		}
	}
	_, err = q.Exec(ctx, `INSERT INTO egress_outbox (kind, payload) VALUES ($1, $2)`, kind, raw)
	return err
}

func reservedKinds() []string {
	out := make([]string, 0, len(egressReserved))
	for k := range egressReserved {
		out = append(out, k)
	}
	return out
}

// EgressCap returns the live-row cap of a kind (for /admin/stats and metrics).
func EgressCap(kind string) int {
	if egressReserved[kind] {
		return EgressMaxLive
	}
	if c, ok := egressKindCaps[kind]; ok {
		return c
	}
	return egressDefaultCap
}
