package randb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// A round's value r_t seeds a deterministic bit generator so that any two agents derive the same
// fair pick from the same (t, salt). The keystream is, for counter i = 0, 1, 2, …
//
//	block_i = HMAC-SHA256(key = r_t, msg = purpose || 0x00 || salt || uint32be(i))
//
// read as a byte stream (block_0 then block_1 …). purpose domain-separates the endpoints ("pick",
// "u", "coin") so the same salt never correlates a pick with a coin. This is exactly the recipe
// published at /rand/about, so the picks are recomputable from the revealed s_t and mix_t alone.
type drbg struct {
	r    []byte
	info []byte // purpose || 0x00 || salt
	ctr  uint32
	buf  []byte
	pos  int
}

func newDRBG(r []byte, purpose, salt string) *drbg {
	info := make([]byte, 0, len(purpose)+1+len(salt))
	info = append(info, purpose...)
	info = append(info, 0)
	info = append(info, salt...)
	return &drbg{r: r, info: info}
}

// refill produces the next keystream block.
func (d *drbg) refill() {
	m := hmac.New(sha256.New, d.r)
	m.Write(d.info)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], d.ctr)
	m.Write(c[:])
	d.ctr++
	d.buf = m.Sum(nil)
	d.pos = 0
}

// next32 returns the next 32-bit word of the keystream (big-endian).
func (d *drbg) next32() uint32 {
	var b [4]byte
	for i := 0; i < 4; i++ {
		if d.pos >= len(d.buf) {
			d.refill()
		}
		b[i] = d.buf[d.pos]
		d.pos++
	}
	return binary.BigEndian.Uint32(b[:])
}

// uniform returns an integer uniform in [0, bound) by rejection sampling (unbiased: words in the
// top partial interval are discarded). bound must be >= 1.
func (d *drbg) uniform(bound uint32) uint32 {
	if bound <= 1 {
		return 0
	}
	limit := uint32((uint64(1) << 32) - (uint64(1)<<32)%uint64(bound))
	for {
		v := d.next32()
		if v < limit {
			return v % bound
		}
	}
}

// pick returns the first n indices of a partial Fisher-Yates shuffle of [0, of): for i in 0..n-1,
// swap position i with a position chosen uniformly in [i, of). n <= of and of >= 1 are required.
func pick(r []byte, n, of int, salt string) []int {
	a := make([]int, of)
	for i := range a {
		a[i] = i
	}
	d := newDRBG(r, "pick", salt)
	for i := 0; i < n; i++ {
		j := i + int(d.uniform(uint32(of-i)))
		a[i], a[j] = a[j], a[i]
	}
	return a[:n]
}

// uniformOf returns a single integer uniform in [0, max).
func uniformOf(r []byte, max uint32, salt string) uint32 {
	return newDRBG(r, "u", salt).uniform(max)
}

// coin returns "heads" or "tails" (heads when the first drawn bit is 1).
func coin(r []byte, salt string) string {
	if newDRBG(r, "coin", salt).uniform(2) == 1 {
		return "heads"
	}
	return "tails"
}
