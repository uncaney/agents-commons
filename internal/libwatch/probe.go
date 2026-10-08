package libwatch

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

const (
	probeMonths  = 36 // sample window: last 36 months (27.3)
	probeDecoys  = 2
	probeMinN    = 10
	probeMaxN    = 20
	probePoolCap = 4000
)

// detRand is a deterministic SHA-256 counter DRBG seeded from an HKDF pseudo-random key; the same
// (day-key, seed) always yields the same stream, so a probe is reproducible within its day.
type detRand struct {
	prk  []byte
	ctr  uint64
	buf  []byte
	used int
}

func newDetRand(prk []byte) *detRand { return &detRand{prk: prk} }

func (r *detRand) refill() {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], r.ctr)
	r.ctr++
	h := sha256.Sum256(append(append([]byte(nil), r.prk...), c[:]...))
	r.buf, r.used = h[:], 0
}

func (r *detRand) u64() uint64 {
	if r.buf == nil || r.used+8 > len(r.buf) {
		r.refill()
	}
	v := binary.BigEndian.Uint64(r.buf[r.used : r.used+8])
	r.used += 8
	return v
}

// intn returns a uniform int in [0,n) (n>0) with rejection sampling.
func (r *detRand) intn(n int) int {
	if n <= 1 {
		return 0
	}
	lim := ^uint64(0) - (^uint64(0) % uint64(n))
	for {
		v := r.u64()
		if v < lim {
			return int(v % uint64(n))
		}
	}
}

// shuffle Fisher-Yates in place.
func (r *detRand) shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		swap(i, r.intn(i+1))
	}
}

// dayKey derives the per-day key from the server secret (27.3: HKDF(day-key, seed)).
func dayKey(secret []byte, day time.Time) []byte {
	k, _ := hkdf.Key(sha256.New, secret, []byte("libwatch/cutoff/v1"), "day:"+day.UTC().Format("2006-01-02"), 32)
	return k
}

// probePRK expands the day key with the caller's seed into the DRBG's pseudo-random key.
func probePRK(secret []byte, day time.Time, seed string) []byte {
	k, _ := hkdf.Key(sha256.New, dayKey(secret, day), nil, "probe:"+seed, 32)
	return k
}

// ProbeItem is one listed release (or decoy) with its true release month hidden from the caller.
type ProbeItem struct {
	Idx      int
	Lib, Ver string
	Month    string // YYYY-MM of the real release; "" for a decoy
	Decoy    bool
}

type poolRow struct {
	key, ver string
	month    string
}

// probeSample builds the deterministic sample for (day, seed, n): n real releases drawn from the
// last 36 months plus 2 decoys, shuffled, indexed from 1. The real-release month is retained
// server-side for scoring but never shown.
func probeSample(ctx context.Context, q core.Q, secret []byte, seed string, n int, day time.Time) ([]ProbeItem, error) {
	if n < probeMinN || n > probeMaxN {
		return nil, core.Bad(fmt.Sprintf("n must be %d..%d", probeMinN, probeMaxN))
	}
	since := day.UTC().AddDate(0, -probeMonths, 0).Format("2006-01-02")
	rows, err := q.Query(ctx, `SELECT key, ver, to_char(released, 'YYYY-MM') FROM lib_releases
		WHERE released >= $1::date AND released <= $2::date ORDER BY released, key, ver LIMIT $3`,
		since, day.UTC().Format("2006-01-02"), probePoolCap)
	if err != nil {
		return nil, err
	}
	var pool []poolRow
	present := map[string]bool{}
	for rows.Next() {
		var p poolRow
		if err := rows.Scan(&p.key, &p.ver, &p.month); err != nil {
			rows.Close()
			return nil, err
		}
		pool = append(pool, p)
		present[p.key+"\x00"+p.ver] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(pool) < n {
		return nil, core.E(409, "sparse", fmt.Sprintf("need %d releases in the window, have %d", n, len(pool)))
	}
	rnd := newDetRand(probePRK(secret, day, seed))
	idx := make([]int, len(pool))
	for i := range idx {
		idx[i] = i
	}
	rnd.shuffle(len(idx), func(i, j int) { idx[i], idx[j] = idx[j], idx[i] })
	items := make([]ProbeItem, 0, n+probeDecoys)
	for i := 0; i < n; i++ {
		p := pool[idx[i]]
		items = append(items, ProbeItem{Lib: p.key, Ver: p.ver, Month: p.month})
	}
	// decoys: a real lib with a fabricated, non-existent version.
	for d := 0; d < probeDecoys; d++ {
		p := pool[idx[rnd.intn(len(pool))]]
		ver := decoyVer(p.ver, rnd)
		for present[p.key+"\x00"+ver] {
			ver = decoyVer(ver, rnd)
		}
		present[p.key+"\x00"+ver] = true
		items = append(items, ProbeItem{Lib: p.key, Ver: ver, Decoy: true})
	}
	rnd.shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })
	for i := range items {
		items[i].Idx = i + 1
	}
	return items, nil
}

// decoyVer fabricates a version by bumping the numeric tail of a real version.
func decoyVer(ver string, rnd *detRand) string {
	i := strings.LastIndexAny(ver, "0123456789")
	if i < 0 {
		return ver + "." + strconv.Itoa(100+rnd.intn(900))
	}
	j := i
	for j > 0 && ver[j-1] >= '0' && ver[j-1] <= '9' {
		j--
	}
	num, _ := strconv.Atoi(ver[j : i+1])
	return ver[:j] + strconv.Itoa(num+1+rnd.intn(40)) + ver[i+1:]
}

// listText renders the probe list: a head line and `<i> <lib> <ver>` rows, no dates.
func listText(seed string, items []ProbeItem) string {
	var b strings.Builder
	n := 0
	for _, it := range items {
		if !it.Decoy {
			n++
		}
	}
	fmt.Fprintf(&b, "probe seed=%s n=%d items=%d\n", doc.SafeLine(seed), n, len(items))
	for _, it := range items {
		fmt.Fprintf(&b, "%d %s %s\n", it.Idx, doc.SafeLine(it.Lib), doc.SafeLine(it.Ver))
	}
	b.WriteString("next: GET /cutoff/probe?seed=" + doc.SafeLine(seed) + "&a=1:y,2:n,…")
	b.WriteByte('\n')
	return b.String()
}

// estOut is the scored estimate.
type estOut struct {
	Cutoff        string
	Conf          float64
	Known, N      int
	DecoysYes     int
	WindowA, WinB string
}

// parseAnswers reads `1:y,2:n,3:u,…` into idx -> answer byte ('y'|'n'|'u').
func parseAnswers(s string) map[int]byte {
	out := map[int]byte{}
	for _, tok := range strings.Split(s, ",") {
		i, a, ok := strings.Cut(strings.TrimSpace(tok), ":")
		if !ok {
			continue
		}
		idx, err := strconv.Atoi(strings.TrimSpace(i))
		if err != nil {
			continue
		}
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		switch a[0] {
		case 'y', 'n', 'u':
			out[idx] = a[0]
		}
	}
	return out
}

// estimate scores answers against the hidden sample (27.3): the latest month m with >= 60 % of
// releases in [m-2, m] known and <= 30 % in (m, m+3] known; each decoy answered yes costs 0.3
// confidence.
func estimate(items []ProbeItem, ans map[int]byte) estOut {
	type ri struct {
		month string
		yes   bool
	}
	var reals []ri
	decoysYes := 0
	months := map[string]bool{}
	for _, it := range items {
		yes := ans[it.Idx] == 'y'
		if it.Decoy {
			if yes {
				decoysYes++
			}
			continue
		}
		reals = append(reals, ri{it.Month, yes})
		months[it.Month] = true
	}
	out := estOut{Cutoff: "?", N: len(reals), DecoysYes: decoysYes}
	for _, r := range reals {
		if r.yes {
			out.Known++
		}
	}
	var cands []string
	for m := range months {
		cands = append(cands, m)
	}
	sort.Strings(cands)
	best := ""
	var bestLow, bestAfter float64
	for _, m := range cands {
		mt, err := time.Parse("2006-01", m)
		if err != nil {
			continue
		}
		lowLo := mt.AddDate(0, -2, 0)
		aftHi := mt.AddDate(0, 3, 0)
		var low, lowK, aft, aftK int
		for _, r := range reals {
			rt, err := time.Parse("2006-01", r.month)
			if err != nil {
				continue
			}
			switch {
			case !rt.Before(lowLo) && !rt.After(mt):
				low++
				if r.yes {
					lowK++
				}
			case rt.After(mt) && !rt.After(aftHi):
				aft++
				if r.yes {
					aftK++
				}
			}
		}
		if low == 0 {
			continue
		}
		fracLow := float64(lowK) / float64(low)
		fracAft := 0.0
		if aft > 0 {
			fracAft = float64(aftK) / float64(aft)
		}
		if fracLow >= 0.60 && fracAft <= 0.30 {
			best, bestLow, bestAfter = m, fracLow, fracAft // latest wins (cands ascending)
		}
	}
	if best == "" {
		return out
	}
	out.Cutoff = best
	conf := bestLow * (1 - bestAfter)
	conf -= 0.3 * float64(decoysYes)
	out.Conf = round1(clamp01(conf))
	mt, _ := time.Parse("2006-01", best)
	out.WindowA = mt.AddDate(0, -2, 0).Format("2006-01")
	out.WinB = mt.AddDate(0, 2, 0).Format("2006-01")
	return out
}

// Text renders the estimate line (27.3).
func (e estOut) Text() string {
	win := ""
	if e.Cutoff != "?" {
		win = fmt.Sprintf(" window=%s..%s", e.WindowA, e.WinB)
	}
	return fmt.Sprintf("cutoff~%s conf=%s known=%d/%d decoys_yes=%d/%d%s",
		e.Cutoff, strconv.FormatFloat(e.Conf, 'f', 1, 64), e.Known, e.N, e.DecoysYes, probeDecoys, win)
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
