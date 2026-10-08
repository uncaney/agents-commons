// Package randb is the public randomness beacon (SPEC-v2 27.9, P119): one commit-reveal round
// per unix minute. The seed s_t = HMAC(HKDF(server_secret,'cx-rand-v1'), t) is revealed at minute
// t; its commitment c_t = sha256(s_t) is published one round ahead, so a round's seed is pinned
// before it is revealed. mix_t = sha256 of the contribution hashes received during minute t-1
// (anyone may add entropy via POST /v1/rand/mix), and the beacon value is r_t = sha256(s_t||mix_t).
// Each round is signed as a rand1 statement; the day's rounds hash is stamped into the notary. The
// construction is trust-minimised, not trustless: the operator could still bias a round by
// grinding s_t before committing, but never after the commitment is out.
package randb

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/notary"
	"ekaii.fr/commons/internal/sign"
)

// TypeRand is the signed statement type of a beacon round (17.1); notary also registers it.
const TypeRand = "rand1"

func init() { sign.RegisterTypes(TypeRand) }

// Tunables (vars so tests can lower them).
var (
	// RowsKeep is the retention of rounds and contributions (27.9: 90 d).
	RowsKeep = 90 * 24 * time.Hour
	// MixPerMin is the per-IP-group contribution rate (27.9: 10/min).
	MixPerMin = 10
	// MaxCatchup bounds how many missed rounds one Advance produces, so a long outage never
	// backfills thousands of empty rounds in a single tick.
	MaxCatchup int64 = 180
	// StampDays is how many completed UTC days back Advance will (re)stamp into the notary.
	StampDays = 2
)

const (
	hkdfInfo = "cx-rand-v1" // HKDF info deriving the per-server seed key
	maxBody  = 1 << 10
	hashLen  = sha256.Size
)

// signerP is the statement signer; Register derives it from the config, with the package default
// as the fallback for tests that do not call Register.
var signerP atomic.Pointer[sign.Signer]

func signer() *sign.Signer {
	if s := signerP.Load(); s != nil {
		return s
	}
	return sign.Default()
}

// seedKey derives the per-server rand key K = HKDF-SHA256(server_secret, info 'cx-rand-v1').
func seedKey(secret []byte) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, hkdfInfo, hashLen)
	if err != nil {
		panic("randb: hkdf: " + err.Error())
	}
	return k
}

// seed is the round seed s_t = HMAC-SHA256(K, uint64be(t)).
func seed(key []byte, t int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(t))
	m := hmac.New(sha256.New, key)
	m.Write(b[:])
	return m.Sum(nil)
}

// commit is the published commitment c_t = sha256(s_t).
func commit(s []byte) []byte {
	h := sha256.Sum256(s)
	return h[:]
}

// beacon mixes the seed with the folded contributions: r_t = sha256(s_t || mix_t).
func beacon(s, mix []byte) []byte {
	h := sha256.New()
	h.Write(s)
	h.Write(mix)
	return h.Sum(nil)
}

// Round is one minute's beacon: the revealed seed, the folded contribution mix, the value, the
// number of contributions and the signed statement.
type Round struct {
	T     int64
	S     []byte
	Mix   []byte
	R     []byte
	NMix  int
	Sig   string
	CNext []byte // sha256(s_{t+1}); nil for a pending (future) round
}

// Line is the signed statement: rand1 t=<t> r=<hex> s=<hex> mix=<hex> n=<k> c_next=<hex> k=<kid>.
func (rd *Round) Line() string {
	return sign.Canonical(TypeRand,
		sign.KV{K: "t", V: fmt.Sprintf("%d", rd.T)},
		sign.KV{K: "r", V: hex.EncodeToString(rd.R)},
		sign.KV{K: "s", V: hex.EncodeToString(rd.S)},
		sign.KV{K: "mix", V: hex.EncodeToString(rd.Mix)},
		sign.KV{K: "n", V: fmt.Sprintf("%d", rd.NMix)},
		sign.KV{K: "c_next", V: hex.EncodeToString(rd.CNext)},
		sign.KV{K: "k", V: fmt.Sprintf("%d", signer().KID())})
}

// minute is the unix minute of t.
func minute(t time.Time) int64 { return t.Unix() / 60 }

// foldMix reads the distinct contribution hashes received in unix minute m, sorts them ascending
// by their raw bytes and returns mix = sha256(h0 || h1 || …) with the count folded in. With no
// contributions the mix is sha256 of the empty string, which is still well defined.
func foldMix(ctx context.Context, q core.Q, m int64) (mix []byte, n int, err error) {
	rows, err := q.Query(ctx, `SELECT h FROM rand_mix WHERE t = $1`, m)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var hs [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, 0, err
		}
		hs = append(hs, h)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	sort.Slice(hs, func(i, j int) bool { return string(hs[i]) < string(hs[j]) })
	h := sha256.New()
	for _, x := range hs {
		h.Write(x)
	}
	return h.Sum(nil), len(hs), nil
}

// Advance produces every round due at now (one per elapsed minute, at most MaxCatchup in a tick)
// and stamps any just-completed UTC day into the notary. It is idempotent: rounds already written
// are kept (ON CONFLICT DO NOTHING), so two gateway instances racing under the janitor's advisory
// lock never corrupt the chain. Returns the rounds written this call.
func Advance(ctx context.Context, db *pgxpool.Pool, secret []byte, now time.Time) (int, error) {
	key := seedKey(secret)
	cur := minute(now)
	var written int
	err := core.Tx(ctx, db, func(tx pgx.Tx) error {
		var last *int64
		if err := tx.QueryRow(ctx, `SELECT max(t) FROM rand_rounds`).Scan(&last); err != nil {
			return err
		}
		start := cur
		if last != nil {
			start = *last + 1
		}
		if cur-start >= MaxCatchup {
			start = cur - MaxCatchup + 1
		}
		for t := start; t <= cur; t++ {
			mix, n, err := foldMix(ctx, tx, t-1)
			if err != nil {
				return err
			}
			s := seed(key, t)
			rd := &Round{T: t, S: s, Mix: mix, R: beacon(s, mix), NMix: n, CNext: commit(seed(key, t+1))}
			rd.Sig = signer().Sign(TypeRand, rd.Line())
			tag, err := tx.Exec(ctx, `INSERT INTO rand_rounds (t, s, mix, r, n_mix, sig) VALUES ($1, $2, $3, $4, $5, $6)
				ON CONFLICT (t) DO NOTHING`, t, s, mix, rd.R, n, rd.Sig)
			if err != nil {
				return err
			}
			written += int(tag.RowsAffected())
		}
		return nil
	})
	if err != nil {
		return written, err
	}
	if err := stampDays(ctx, db, now); err != nil {
		return written, err
	}
	return written, nil
}

// stampDays stamps the rounds hash of each completed UTC day (in the last StampDays days) into the
// notary. The day hash is sha256(r_t0 || r_t1 || …) over the day's rounds in ascending t; Stamp is
// first-seen, so re-stamping a stable completed day is a no-op after the first time.
func stampDays(ctx context.Context, db core.Q, now time.Time) error {
	y, mo, d := now.UTC().Date()
	today := time.Date(y, mo, d, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= StampDays; i++ {
		day := today.AddDate(0, 0, -i)
		lo := day.Unix() / 60
		hi := day.AddDate(0, 0, 1).Unix() / 60
		rows, err := db.Query(ctx, `SELECT r FROM rand_rounds WHERE t >= $1 AND t < $2 ORDER BY t`, lo, hi)
		if err != nil {
			return err
		}
		h := sha256.New()
		var n int
		for rows.Next() {
			var r []byte
			if err := rows.Scan(&r); err != nil {
				rows.Close()
				return err
			}
			h.Write(r)
			n++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		note := fmt.Sprintf("rand %s rounds=%d", day.Format("2006-01-02"), n)
		if _, _, err := notary.Stamp(ctx, db, h.Sum(nil), note, core.SystemID); err != nil {
			return err
		}
	}
	return nil
}

// loadRound reads round t, or (nil, nil) when it is not in the table.
func loadRound(ctx context.Context, q core.Q, t int64) (*Round, error) {
	rd := &Round{T: t}
	err := q.QueryRow(ctx, `SELECT s, mix, r, n_mix, sig FROM rand_rounds WHERE t = $1`, t).
		Scan(&rd.S, &rd.Mix, &rd.R, &rd.NMix, &rd.Sig)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rd, nil
}

// latest returns the newest round, or (nil, nil) before the first round exists.
func latest(ctx context.Context, q core.Q) (*Round, error) {
	var t *int64
	if err := q.QueryRow(ctx, `SELECT max(t) FROM rand_rounds`).Scan(&t); err != nil {
		return nil, err
	}
	if t == nil {
		return nil, nil
	}
	return loadRound(ctx, q, *t)
}

// contributions lists the sorted contribution hashes folded into round t (received in minute t-1).
func contributions(ctx context.Context, q core.Q, t int64) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT h FROM rand_mix WHERE t = $1 ORDER BY h`, t-1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, hex.EncodeToString(h))
	}
	return out, rows.Err()
}

// addMix records one contribution for the current minute (ON CONFLICT collapses duplicates).
func addMix(ctx context.Context, q core.Q, m int64, h []byte) error {
	_, err := q.Exec(ctx, `INSERT INTO rand_mix (t, h) VALUES ($1, $2) ON CONFLICT (t, h) DO NOTHING`, m, h)
	return err
}

// Janitor drops rounds and contributions past the 90 d retention.
func Janitor(ctx context.Context, q core.Q) error {
	cut := minute(time.Now().Add(-RowsKeep))
	if _, err := q.Exec(ctx, `DELETE FROM rand_rounds WHERE t < $1`, cut); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `DELETE FROM rand_mix WHERE t < $1`, cut)
	return err
}

// --- per-IP-group minute rate limiter -----------------------------------------------------------

// rateWindow is one group's current minute bucket.
type rateWindow struct {
	start time.Time
	n     int
}

// rateLimiter caps contributions at MixPerMin per IP group per minute, in process (best-effort,
// like core's admin failure limiter). Two instances each enforce their own share.
type rateLimiter struct {
	mu sync.Mutex
	m  map[string]*rateWindow
}

func newRateLimiter() *rateLimiter { return &rateLimiter{m: map[string]*rateWindow{}} }

const rateMaxGroups = 100_000

// allow reports whether group may submit now, and the seconds until its window resets when not.
func (l *rateLimiter) allow(group string, now time.Time) (ok bool, retry int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.m[group]
	if w == nil {
		if len(l.m) >= rateMaxGroups {
			l.sweepLocked(now)
			if len(l.m) >= rateMaxGroups {
				return false, 60
			}
		}
		w = &rateWindow{}
		l.m[group] = w
	}
	if now.Sub(w.start) >= time.Minute {
		w.start, w.n = now, 0
	}
	if w.n >= MixPerMin {
		return false, int((time.Minute-now.Sub(w.start))/time.Second) + 1
	}
	w.n++
	return true, 0
}

func (l *rateLimiter) sweepLocked(now time.Time) {
	for k, w := range l.m {
		if now.Sub(w.start) >= time.Minute {
			delete(l.m, k)
		}
	}
}

// parseHash decodes a 64-hex contribution hash into 32 bytes.
func parseHash(s string) ([]byte, error) {
	if len(s) != 2*hashLen {
		return nil, core.Bad("h must be 64 hex chars (sha256)")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, core.Bad("h must be 64 hex chars (sha256)")
	}
	return b, nil
}
