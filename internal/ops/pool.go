package ops

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// poolStat is the slice of pgxpool.Stat the sampler and the gauges read.
type poolStat interface {
	AcquireCount() int64
	AcquiredConns() int32
	ConstructingConns() int32
	EmptyAcquireCount() int64
	EmptyAcquireWaitTime() time.Duration
	IdleConns() int32
	MaxConns() int32
}

type poolStatter struct{ p *pgxpool.Pool }

func (s poolStatter) Stat() poolStat { return s.p.Stat() }

// statOf wraps a pool for the gauges; nil pools (tests without an ops pool) yield nil.
func statOf(p *pgxpool.Pool) interface{ Stat() poolStat } {
	if p == nil {
		return nil
	}
	return poolStatter{p}
}

// poolSnap is the previous sample's cumulative pool counters (the sampler reads deltas).
type poolSnap struct {
	acquires, empty int64
	wait            time.Duration
}
