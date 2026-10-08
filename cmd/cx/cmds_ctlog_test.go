package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/notary"
)

// buildProof constructs a real RFC 6962 day tree with the target leaf at idx, returns the proof
// JSON the server would serve and the matching /ts/chain.txt body (two days, the target second).
func buildProof(t *testing.T, day string) (proofJSON, string) {
	t.Helper()
	var h [32]byte
	copy(h[:], sha256Of("svc1\x00cx-jq@3\x00wasmhash"))
	ts, seq := int64(1_700_000_000), int64(5)
	target := notary.Leaf(h[:], time.Unix(ts, 0), seq)

	leaves := [][]byte{randLeaf(t), target, randLeaf(t), randLeaf(t)}
	idx := 1
	root := notary.Root(leaves)
	proof := notary.Proof(leaves, idx)

	// Day 0 is an earlier sealed day; the target is day 1. chain = SHA256(prev || root).
	var root0 [32]byte
	rand.Read(root0[:])
	chain0 := chainStep(make([]byte, 32), root0[:])
	chain1 := chainStep(chain0, root)

	ph := make([]string, len(proof))
	for i, p := range proof {
		ph[i] = hex.EncodeToString(p)
	}
	pj := proofJSON{Name: "cx-jq", Ver: 3, Wasm: "wasmhash", H: hex.EncodeToString(h[:]), T: ts, N: seq,
		Idx: idx, Size: len(leaves), Day: day, Root: hex.EncodeToString(root), Proof: ph,
		Chain: hex.EncodeToString(chain1), Sealed: true}
	chainTxt := "2026-10-05 " + hex.EncodeToString(chain0) + " " + hex.EncodeToString(root0[:]) + "\n" +
		day + " " + hex.EncodeToString(chain1) + " " + hex.EncodeToString(root) + "\n"
	return pj, chainTxt
}

func sha256Of(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func randLeaf(t *testing.T) []byte {
	t.Helper()
	var b [32]byte
	rand.Read(b[:])
	return b[:]
}

func TestSvcVerifyInclusionAndChain(t *testing.T) {
	f, srv := newRec(t)
	pj, chainTxt := buildProof(t, "2026-10-06")
	body, _ := json.Marshal(pj)
	f.set("GET", "/svc/cx-jq@3/proof", 200, string(body))
	f.set("GET", "/ts/chain.txt", 200, chainTxt)

	c, out, _ := recCLI(t, srv, t.TempDir(), "")
	mustRun(t, c, "svc-verify", "cx-jq@3")
	got := out.String()
	if !strings.Contains(got, "verified cx-jq@3 day=2026-10-06 idx=1 inclusion=ok chain=ok") {
		t.Fatalf("svc-verify out = %q", got)
	}
	// It fetched the proof and the chain.
	if f.find("GET", "/svc/cx-jq@3/proof") == nil || f.find("GET", "/ts/chain.txt") == nil {
		t.Fatalf("expected proof + chain requests, got %+v", f.reqs)
	}
}

func TestSvcVerifyRejectsTamperedRoot(t *testing.T) {
	f, srv := newRec(t)
	pj, chainTxt := buildProof(t, "2026-10-06")
	// Flip the last byte of the root: inclusion must fail.
	rb, _ := hex.DecodeString(pj.Root)
	rb[len(rb)-1] ^= 0xff
	pj.Root = hex.EncodeToString(rb)
	body, _ := json.Marshal(pj)
	f.set("GET", "/svc/cx-jq@3/proof", 200, string(body))
	f.set("GET", "/ts/chain.txt", 200, chainTxt)

	c, out, _ := recCLI(t, srv, t.TempDir(), "")
	var ee *exitErr
	if err := c.run(context.Background(), []string{"svc-verify", "cx-jq@3"}); !asExit(err, &ee) || ee.code != 3 {
		t.Fatalf("tampered root: err = %v", err)
	}
	if !strings.Contains(out.String(), "inclusion=bad") {
		t.Fatalf("out = %q, want inclusion=bad", out.String())
	}
}

func TestSvcVerifyRejectsBrokenChain(t *testing.T) {
	f, srv := newRec(t)
	pj, chainTxt := buildProof(t, "2026-10-06")
	// Corrupt the chain value of the target day line: the fold no longer matches.
	lines := strings.Split(strings.TrimRight(chainTxt, "\n"), "\n")
	fields := strings.Fields(lines[1])
	bad := fields[1][:63] + flip(fields[1][63])
	lines[1] = fields[0] + " " + bad + " " + fields[2]
	broken := strings.Join(lines, "\n") + "\n"
	body, _ := json.Marshal(pj)
	f.set("GET", "/svc/cx-jq@3/proof", 200, string(body))
	f.set("GET", "/ts/chain.txt", 200, broken)

	c, _, _ := recCLI(t, srv, t.TempDir(), "")
	if err := c.run(context.Background(), []string{"svc-verify", "cx-jq@3"}); err == nil {
		t.Fatal("expected a non-nil error for a chain.txt that does not fold")
	}
	// With --no-chain the inclusion-only check still passes.
	c2, out2, _ := recCLI(t, srv, t.TempDir(), "")
	mustRun(t, c2, "svc-verify", "cx-jq@3", "--no-chain")
	if !strings.Contains(out2.String(), "inclusion=ok chain=skipped") {
		t.Fatalf("--no-chain out = %q", out2.String())
	}
}

func flip(c byte) string {
	if c == '0' {
		return "1"
	}
	return "0"
}
