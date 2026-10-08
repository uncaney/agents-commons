package pow

import (
	"testing"
	"time"
)

func TestMintVerify(t *testing.T) {
	secret := []byte("s3cret")
	now := time.Now()
	c := Mint(secret, now.Add(10*time.Minute))
	exp, err := Verify(secret, c, now)
	if err != nil {
		t.Fatal(err)
	}
	if d := exp.Sub(now.Add(10 * time.Minute)); d > time.Second || d < -time.Second {
		t.Fatalf("exp off by %v", d)
	}
	if _, err := Verify([]byte("other"), c, now); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if _, err := Verify(secret, c, now.Add(11*time.Minute)); err == nil {
		t.Fatal("expired accepted")
	}
	if _, err := Verify(secret, c[:len(c)-2], now); err == nil {
		t.Fatal("truncated accepted")
	}
	if _, err := Verify(secret, "!!", now); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestSolveCheck(t *testing.T) {
	c := Mint([]byte("x"), time.Now().Add(time.Minute))
	n := Solve(c, 12)
	if !Check(c, n, 12) {
		t.Fatal("solution rejected")
	}
	if Check(c, n, 30) {
		t.Fatal("weak solution accepted at higher bits")
	}
	if Check(c, "", 0) {
		t.Fatal("empty nonce accepted")
	}
	if Check(c+"x", n, 12) {
		t.Fatal("solution for other challenge accepted")
	}
}

func TestChallengeV2BitsPurpose(t *testing.T) {
	secret := []byte("s3cret")
	now := time.Now()
	exp := now.Add(10 * time.Minute)
	for _, tc := range []struct {
		bits int
		p    Purpose
	}{{22, PurposeReg}, {16, PurposeWrite}, {2, PurposeWait}, {30, PurposeWait}, {255, PurposeReg}, {0, PurposeWrite}} {
		c := New(secret, exp, tc.bits, tc.p)
		if len(c) != 40 {
			t.Fatalf("v2 challenge is %d chars, want 40", len(c))
		}
		info, err := VerifyV2(secret, c, now)
		if err != nil {
			t.Fatal(err)
		}
		if info.Bits != tc.bits || info.Purpose != tc.p {
			t.Fatalf("got bits=%d purpose=%q, want %d %q", info.Bits, info.Purpose, tc.bits, tc.p)
		}
		if d := info.Exp.Sub(exp); d > time.Second || d < -time.Second {
			t.Fatalf("exp off by %v", d)
		}
		if _, err := VerifyV2([]byte("other"), c, now); err != ErrBad {
			t.Fatalf("wrong secret: %v", err)
		}
		if info, err := VerifyV2(secret, c, exp.Add(time.Second)); err != ErrExpired || info.Bits != tc.bits || info.Purpose != tc.p {
			t.Fatalf("expired: %v %+v", err, info)
		}
		if n := Solve(c, 6); !Check(c, n, 6) {
			t.Fatal("v2 challenge not solvable")
		}
	}
	if New(secret, exp, 1, PurposeReg) == New(secret, exp, 1, PurposeReg) {
		t.Fatal("challenges not unique")
	}
	if PurposeReg.String() != "reg" || PurposeWrite.String() != "w" || PurposeWait.String() != "w_wait" || Purpose(9).String() != "?" {
		t.Fatal("purpose names")
	}
	for _, bad := range []int{-1, 256} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("bits %d accepted", bad)
				}
			}()
			New(secret, exp, bad, PurposeReg)
		}()
	}
	if _, err := VerifyV2(secret, "!!", now); err != ErrMalformed {
		t.Fatalf("garbage: %v", err)
	}
}

func TestV1ChallengeStillVerifies(t *testing.T) {
	secret := []byte("s3cret")
	now := time.Now()
	exp := now.Add(10 * time.Minute)
	c := Mint(secret, exp)
	if len(c) != 38 {
		t.Fatalf("v1 challenge is %d chars, want 38", len(c))
	}
	got, err := Verify(secret, c, now)
	if err != nil {
		t.Fatal(err)
	}
	if d := got.Sub(exp); d > time.Second || d < -time.Second {
		t.Fatalf("exp off by %v", d)
	}
	info, err := VerifyV2(secret, c, now)
	if err != nil {
		t.Fatal(err)
	}
	if info.Bits != 0 || info.Purpose != PurposeReg || !info.Exp.Equal(got) {
		t.Fatalf("v1 info %+v", info)
	}
	if _, err := VerifyV2(secret, c, exp.Add(time.Second)); err != ErrExpired {
		t.Fatalf("expired v1: %v", err)
	}
	if _, err := VerifyV2([]byte("other"), c, now); err != ErrBad {
		t.Fatalf("wrong secret v1: %v", err)
	}
}

func TestVerifyWrapperOnV2(t *testing.T) {
	secret := []byte("s3cret")
	now := time.Now()
	exp := now.Add(10 * time.Minute)
	for _, p := range []Purpose{PurposeReg, PurposeWrite, PurposeWait} {
		c := New(secret, exp, 20, p)
		got, err := Verify(secret, c, now)
		if err != nil {
			t.Fatal(err)
		}
		if d := got.Sub(exp); d > time.Second || d < -time.Second {
			t.Fatalf("exp off by %v", d)
		}
		if _, err := Verify([]byte("other"), c, now); err == nil {
			t.Fatal("wrong secret accepted")
		}
		if got, err := Verify(secret, c, exp.Add(time.Second)); err != ErrExpired || got.IsZero() {
			t.Fatalf("expired: %v %v", err, got)
		}
		if _, err := Verify(secret, c[:len(c)-2], now); err == nil {
			t.Fatal("truncated accepted")
		}
	}
}

func TestTamperedBitsRejected(t *testing.T) {
	secret := []byte("s3cret")
	now := time.Now()
	c := New(secret, now.Add(10*time.Minute), 20, PurposeWrite)
	raw, err := enc.DecodeString(c)
	if err != nil {
		t.Fatal(err)
	}
	mut := func(f func(b []byte)) string {
		b := append([]byte(nil), raw...)
		f(b)
		return enc.EncodeToString(b)
	}
	cases := map[string]string{
		"bits lowered":   mut(func(b []byte) { b[20] = 1 }),
		"bits zeroed":    mut(func(b []byte) { b[20] = 0 }),
		"purpose to reg": mut(func(b []byte) { b[21] = byte(PurposeReg) }),
		"purpose wait":   mut(func(b []byte) { b[21] = byte(PurposeWait) }),
		"exp extended":   mut(func(b []byte) { b[19]++ }),
		"mac flipped":    mut(func(b []byte) { b[22] ^= 1 }),
		"rand flipped":   mut(func(b []byte) { b[0] ^= 1 }),
		"as v1 layout":   enc.EncodeToString(raw[:28]),
		"v1 extended":    enc.EncodeToString(append(mustDecode(t, Mint(secret, now.Add(time.Minute))), 20, byte(PurposeWrite))),
	}
	for name, tc := range cases {
		if _, err := VerifyV2(secret, tc, now); err != ErrBad {
			t.Fatalf("%s: got %v, want %v", name, err, ErrBad)
		}
		if _, err := Verify(secret, tc, now); err == nil {
			t.Fatalf("%s: v1 wrapper accepted", name)
		}
	}
	if info, err := VerifyV2(secret, c, now); err != nil || info.Bits != 20 || info.Purpose != PurposeWrite {
		t.Fatalf("original no longer verifies: %v %+v", err, info)
	}
}

func mustDecode(t *testing.T, c string) []byte {
	t.Helper()
	raw, err := enc.DecodeString(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
