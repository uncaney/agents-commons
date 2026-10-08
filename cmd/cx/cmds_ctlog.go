package main

// cmds_ctlog.go: `cx svc-verify <name@ver>` (SPEC-v2 27.6, server package internal/ctlog, P108).
// It is the catalog-transparency counterpart of `cx verify` (which reproduces a compute job): it
// fetches a service version's inclusion proof (GET /svc/<name@ver>/proof), recomputes the svc1 leaf
// and checks it against the sealed day root with the RFC 6962 algorithm (internal/notary), then
// checks the day's chain value against /ts/chain.txt (chain = SHA256(prev_chain || root), folded
// from genesis) so the whole prefix of days is committed. It prints
// `verified <name>@<ver> day=<d> idx=<i> inclusion=ok chain=ok` and exits non-zero on any mismatch.
//
// The spec names this verb `svc verify`; the `svc` verb is owned by the catalog command group, so
// the transparency check is exposed here as the sibling verb `svc-verify`.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"ekaii.fr/commons/internal/notary"
)

// chainStep folds one day root into the running chain: SHA256(prev || root) (SPEC-v2 27.6).
func chainStep(prev, root []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(root)
	return h.Sum(nil)
}

func init() {
	register("catalog", "svc-verify", cmdSvcVerify,
		u("<name[@ver]> [--no-chain]", "check a service version's transparency-log inclusion and chain (27.6)"))
}

// proofJSON is the subset of GET /svc/<name@ver>/proof (JSON twin) that svc-verify reads.
type proofJSON struct {
	Name   string   `json:"name"`
	Ver    int      `json:"ver"`
	Wasm   string   `json:"wasm"`
	H      string   `json:"h"`
	T      int64    `json:"t"`
	N      int64    `json:"n"`
	Idx    int      `json:"idx"`
	Size   int      `json:"size"`
	Day    string   `json:"day"`
	Root   string   `json:"root"`
	Proof  []string `json:"proof"`
	Chain  string   `json:"chain"`
	Sealed bool     `json:"sealed"`
}

func cmdSvcVerify(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx svc-verify <name[@ver]> [--no-chain]"
	var noChain bool
	pos, err := parseArgs(args, nil, map[string]*bool{"no-chain": &noChain})
	if err != nil || len(pos) != 1 {
		return fail(2, use)
	}
	ref := strings.TrimSpace(pos[0])
	if ref == "" {
		return fail(2, use)
	}

	var p proofJSON
	if err := c.getJSON(ctx, "GET", "/svc/"+url.PathEscape(ref)+"/proof", nil, &p); err != nil {
		return err
	}
	if !p.Sealed || p.Root == "" {
		return fail(1, "err bad %s is logged but its day is not sealed yet (retry after the daily seal)", ref)
	}

	// 1. Inclusion: recompute the svc1 leaf and walk the proof up to the day root.
	hb, err := hex.DecodeString(p.H)
	if err != nil || len(hb) != notary.HashSize {
		return fail(1, "err proto bad leaf hash %q", p.H)
	}
	root, err := hex.DecodeString(p.Root)
	if err != nil {
		return fail(1, "err proto bad root %q", p.Root)
	}
	proof, err := notary.ParseProof(strings.Join(p.Proof, ","))
	if err != nil {
		return fail(1, "err proto bad proof: %v", err)
	}
	leaf := notary.Leaf(hb, time.Unix(p.T, 0), p.N)
	if !notary.VerifyProof(leaf, p.Idx, p.Size, proof, root) {
		c.print([]byte(fmt.Sprintf("mismatch %s@%d inclusion=bad", p.Name, p.Ver)))
		return &exitErr{code: 3}
	}

	// 2. Chain prefix: fold /ts/chain.txt from genesis and confirm the day's chain and root match.
	chainOK := "skipped"
	if !noChain {
		ok, err := c.checkChainPrefix(ctx, p.Day, root, p.Chain)
		if err != nil {
			return err
		}
		if !ok {
			c.print([]byte(fmt.Sprintf("mismatch %s@%d inclusion=ok chain=bad", p.Name, p.Ver)))
			return &exitErr{code: 3}
		}
		chainOK = "ok"
	}

	c.print([]byte(fmt.Sprintf("verified %s@%d day=%s idx=%d inclusion=ok chain=%s", p.Name, p.Ver, p.Day, p.Idx, chainOK)))
	return nil
}

// checkChainPrefix re-folds /ts/chain.txt from the 32-zero genesis (chain = SHA256(prev || root))
// and verifies that every line is self-consistent and that the proof's day carries the given root
// and chain. It thus confirms the day root is committed by a hash chain over the whole prefix.
func (c *cli) checkChainPrefix(ctx context.Context, day string, root []byte, chainHex string) (bool, error) {
	b, err := c.call(ctx, "GET", "/ts/chain.txt", nil, "", false)
	if err != nil {
		return false, err
	}
	running := make([]byte, notary.HashSize) // genesis
	seen := false
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		d, chHex, rtHex := fields[0], fields[1], fields[2]
		rt, err := hex.DecodeString(rtHex)
		if err != nil || len(rt) != notary.HashSize {
			return false, fail(1, "err proto bad root in chain.txt line %q", line)
		}
		h := chainStep(running, rt)
		if hex.EncodeToString(h) != chHex {
			return false, fail(1, "err proto chain.txt line %q does not fold (chain != SHA256(prev||root))", line)
		}
		running = h
		if d == day {
			seen = true
			if hex.EncodeToString(rt) != hex.EncodeToString(root) || chHex != chainHex {
				return false, nil
			}
		}
	}
	if !seen {
		return false, fail(1, "err notfound day %s is not in /ts/chain.txt", day)
	}
	return true, nil
}
