package gym

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/gym/mods"
)

// SeedSystem publishes the built gym modules in dir (gym-<kind>.wasm + manifest, produced by the
// image build) as services under the system root (19.5), reusing the catalog seed path. A missing
// or empty dir publishes nothing and is not an error.
func SeedSystem(ctx context.Context, d *core.Deps, dir string) (int, error) {
	return catalog.SeedSystem(ctx, d, dir)
}

// Refill is the pool janitor (19.5): for every (kind, level) it tops the unserved pool back up to
// PoolTarget, generating instances in-process with the same portable-Go logic the gym-<kind>
// modules wrap. Each instance is funded from the system faucet (reserved per instance); when the
// faucet runs short it stops, records an inbox event and leaves the pool as is (unfunded skip).
func (s *svc) Refill(ctx context.Context) error {
	unfunded := false
	for _, kind := range mods.Kinds {
		for level := 1; level <= MaxLevel; level++ {
			var have int
			if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FROM gym_tasks WHERE kind = $1 AND level = $2 AND served_to IS NULL`, kind, level).Scan(&have); err != nil {
				return err
			}
			need := PoolTarget - have
			if need <= 0 {
				continue
			}
			if err := s.refillBatch(ctx, kind, level, need); err != nil {
				if errors.Is(err, core.ErrCredits) {
					unfunded = true
					break
				}
				return err
			}
		}
		if unfunded {
			break
		}
	}
	if unfunded {
		return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			return core.Event(ctx, tx, "gym", "pool", "", "gym: system faucet unfunded; task pool refill skipped")
		})
	}
	return nil
}

// refillBatch reserves need credits from the system faucet and inserts need unserved instances of
// (kind, level) in one transaction. core.ErrCredits (faucet short) rolls the batch back untouched.
func (s *svc) refillBatch(ctx context.Context, kind string, level, need int) error {
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := core.Reserve(ctx, tx, core.SystemID, int64(need*GenCost)); err != nil {
			return err
		}
		for i := 0; i < need; i++ {
			if err := insertInstance(ctx, tx, kind, level); err != nil {
				return err
			}
		}
		return nil
	})
}

// insertInstance generates one task and stores it with a salted answer hash (seed, answer and salt
// stay server-side; only the prompt is ever served).
func insertInstance(ctx context.Context, q core.Q, kind string, level int) error {
	seed := randSeed()
	t, err := mods.Gen(kind, seed, level)
	if err != nil {
		return err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	h := sha256.Sum256(append([]byte(mods.Norm(t.Answer)), salt...))
	_, err = q.Exec(ctx, `INSERT INTO gym_tasks (id, kind, level, seed, prompt, answer, secret, answer_hash, salt, checker)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		core.NewID('g'), kind, level, seed, t.Prompt, t.Answer, t.Secret, h[:], salt, t.Check)
	return err
}

func randSeed() int64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("gym seed: %v", err))
	}
	return int64(binary.LittleEndian.Uint64(b[:]))
}
