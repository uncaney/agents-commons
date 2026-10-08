package e2e_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/e2e"
)

// Every parser has a testing.F target whose seeds are genuine inputs plus damaged ones; the body checks
// the parser's invariants and that verification succeeds only on byte-identical genuine input. The
// targets are also driven by TestFuzzSweep, a time-boxed mutation loop that runs on every go test
// (10 s by default, also under -short; E2E_FUZZ_SECONDS overrides).

type target struct {
	name  string
	seeds [][]byte
	check func(t testing.TB, b []byte)
}

func genuine(seeds [][]byte) map[string]bool {
	m := map[string]bool{}
	for _, s := range seeds {
		m[string(s)] = true
	}
	return m
}

func damaged(seeds [][]byte) [][]byte {
	out := append([][]byte(nil), seeds...)
	for _, s := range seeds {
		if len(s) > 1 {
			out = append(out, s[:len(s)/2], s[:len(s)-1])
			flip := append([]byte(nil), s...)
			flip[len(flip)/3] ^= 0x40
			out = append(out, flip)
		}
	}
	return append(out, nil, []byte{0x01}, bytes.Repeat([]byte{0}, 71), bytes.Repeat([]byte{0xff}, 600))
}

func envelopeTarget(tb testing.TB) target {
	// HPKE draws an ephemeral key from crypto/rand, so a fuzz worker process seals different bytes than
	// the coordinator: genuineness is judged by the opened content, not by byte identity.
	p := newPair(tb)
	var seeds [][]byte
	known := map[string]bool{}
	for _, cs := range []e2e.Suite{e2e.CS1, e2e.CS2} {
		for _, n := range []int{0, 500, 1500, e2e.MaxPayload} {
			payload := bytes.Repeat([]byte{'e'}, n)
			known[string(payload)] = true
			seeds = append(seeds, p.seal(tb, cs, payload, e2e.TypeText).Envelope)
		}
	}
	ok := genuine(seeds)
	return target{name: "envelope", seeds: damaged(seeds), check: func(t testing.TB, b []byte) {
		e, err := e2e.ParseEnvelope(b)
		if err != nil {
			if ok[string(b)] {
				t.Fatal("genuine envelope refused")
			}
			return
		}
		if !bytes.Equal(e.Bytes(), b) || len(e.Enc) != e.CS.EncSize() || !e2e.IsBucket(e.Bucket(), e2e.MailBuckets) || len(b) > e2e.MailCap || len(e.HdrBytes()) != e2e.HdrLen {
			t.Fatal("parse invariants")
		}
		sk := p.ekB1
		if e.CS == e2e.CS2 {
			sk = p.ekB2
		}
		in, oerr := e.Open(e2e.OpenParams{Me: bob, RecipientKey: sk, RecipientAK: p.akB, SenderAK: p.ba.AK})
		if oerr != nil {
			if ok[string(b)] {
				t.Fatalf("genuine envelope failed to open: %v", oerr)
			}
			return
		}
		if !known[string(in.Payload)] || in.TS != uint32(now) || in.Type != e2e.TypeText || e.From != alice || e.To != bob {
			t.Fatal("an envelope with unknown content opened")
		}
	}}
}

func bundleTarget(tb testing.TB) target {
	var seeds [][]byte
	for i, cs2 := range []bool{false, true} {
		_, raw := bundleFor(tb, seedN(70+byte(i)), alice, 1, cs2, e2e.FlagLKOK, 2959)
		seeds = append(seeds, raw)
	}
	b, _ := e2e.NewBundle(seedN(72), e2e.BundleParams{ID: carol, Seq: 1, IAT: 1, Exp: 86400, Flags: e2e.FlagCS2 | e2e.FlagPQ, MinCS: 2, E0: 1, NEK: 2, RevCommit: make([]byte, 32)})
	raw, _ := b.Sign(e2e.IK(seedN(72)), nil, e2e.PQID(seedN(72)))
	seeds = append(seeds, raw)
	ok := genuine(seeds)
	return target{name: "bundle", seeds: damaged(seeds), check: func(t testing.TB, b []byte) {
		pb, err := e2e.ParseBundle(b)
		if err != nil {
			if ok[string(b)] {
				t.Fatal("genuine bundle refused")
			}
			return
		}
		can, err := pb.Canonical()
		if err != nil || !bytes.Equal(append(append(append(can, pb.SigIK...), pb.SigPrev...), pb.SigPQ...), b) {
			t.Fatal("canonical round trip")
		}
		if (pb.Verify() == nil) != ok[string(b)] {
			t.Fatalf("verify genuine=%v", ok[string(b)])
		}
	}}
}

func cxs1Target(tb testing.TB) target {
	secret := []byte("fuzz secret")
	kv := e2e.SealV1Key(e2e.MK(seedN(73)))
	var seeds, raws [][]byte
	for _, n := range []int{0, 1, 33, 700} {
		r, _ := e2e.Cxs1Seal(secret, bytes.Repeat([]byte{byte(n)}, n), rnd(uint64(n)))
		raws = append(raws, r)
		v1, _ := e2e.Seal1(kv, "ns|k", bytes.Repeat([]byte{byte(n)}, n), rnd(uint64(n)))
		v2, _ := e2e.Seal2(kv, "ns|k", bytes.Repeat([]byte{byte(n)}, n), rnd(uint64(n)))
		seeds = append(seeds, r, []byte(v1), []byte(v2), []byte(e2e.EncodeCxs1(r)))
	}
	ok, rawOK := genuine(seeds), genuine(raws)
	return target{name: "cxs1", seeds: damaged(seeds), check: func(t testing.TB, b []byte) {
		_, err := e2e.Cxs1Open(secret, b)
		if (err == nil) != rawOK[string(b)] {
			t.Fatalf("cxs1 open=%v genuine=%v", err, rawOK[string(b)])
		}
		s := string(b)
		if rec, err := e2e.DecodeCxs1(s); err == nil {
			if _, err := e2e.Cxs1Open(secret, rec); (err == nil) != rawOK[string(rec)] {
				t.Fatal("text form open")
			}
		}
		_, e1 := e2e.Open1(kv, "ns|k", s)
		_, e2 := e2e.Open2(kv, "ns|k", s)
		if (e1 == nil || e2 == nil) != (ok[s] && e2e.IsSealed(s)) {
			t.Fatalf("sealed open genuine=%v", ok[s])
		}
		if n, err := e2e.SealedNonce(s); err == nil && (len(n) != 12 && len(n) != 16 || !e2e.IsSealed(s)) {
			t.Fatal("nonce of a sealed value")
		}
	}}
}

func reqsigTarget(tb testing.TB) target {
	rk := e2e.RK(seedN(74))
	body := []byte("body")
	var seeds [][]byte
	for i := 0; i < 3; i++ {
		h, _ := e2e.SignReq(rk, "POST", "/v1/x/"+bob, uint64(now+int64(i)), e2e.Sum([]byte{byte(i)})[:16], body)
		seeds = append(seeds, []byte(h))
	}
	ok := genuine(seeds)
	return target{name: "reqsig", seeds: damaged(seeds), check: func(t testing.TB, b []byte) {
		s := string(b)
		sig, err := e2e.ParseReqSig(s)
		if err != nil {
			if ok[s] {
				t.Fatal("genuine header refused")
			}
			return
		}
		if sig.Header() != strings.TrimSpace(s) {
			t.Fatal("header round trip")
		}
		if ss, err := e2e.ParseSendSig(sig.SendSig()); err != nil || ss.TS != sig.TS {
			t.Fatal("send_sig round trip")
		}
		_, verr := e2e.VerifyReq(rk.Public().(ed25519.PublicKey), "POST", "/v1/x/"+bob, s, body, now)
		if (verr == nil) != ok[strings.TrimSpace(s)] {
			t.Fatalf("verify genuine=%v", ok[strings.TrimSpace(s)])
		}
	}}
}

func commitHeaderTarget(testing.TB) target {
	th := make([]byte, 32)
	seeds := [][]byte{
		[]byte(`{"e":5,"by":3,"add":[{"id":"abobbob","leaf":12,"ekh":"0a1b2c3d"}],"rm":[2],"upd":true,"pp":[7,8],"th":"` + hexZero(th) + `","ext":{"admins":[1]}}`),
		[]byte(`{"e":1,"by":1,"th":"` + hexZero(th) + `"}`),
		[]byte(`{"e":1,"by":1,"th":"` + hexZero(th) + `","ext":[]}`),
	}
	return target{name: "commit-header", seeds: damaged(seeds), check: func(t testing.TB, b []byte) {
		h, err := e2e.ParseCommitHeader(b)
		if err != nil {
			return
		}
		re, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e2e.ParseCommitHeader(re); err != nil {
			t.Fatalf("re-marshalled header refused: %v", err)
		}
	}}
}

func groupRowsTarget(tb testing.TB) target {
	s := newSwarm(tb)
	roster := []e2e.Member{s.member(1, alice), s.member(2, bob)}
	c, err := e2e.BuildCommit(e2e.CommitParams{GID: gid, CS: e2e.CS1, Epoch: 1, Idx: 1, Members: s.fanout(alice, bob), InitPrev: e2e.InitSecret0,
		THPrev: make([]byte, 32), RosterHash: e2e.RosterHash(roster), IK: s.ik(alice), Rand: rnd(1)})
	if err != nil {
		tb.Fatal(err)
	}
	app, _ := e2e.SealApp(e2e.AppParams{GID: gid, Epoch: 1, Idx: 2, Gen: 1, CType: 1, Payload: []byte("x"), MsgRoot: c.Secrets.MsgRoot, IK: s.ik(bob), Rand: rnd(2)})
	w, _ := e2e.BuildWelcome(e2e.WelcomeParams{GID: gid, CS: e2e.CS1, Epoch: 1, Idx: 1, To: carol, NewcomerKey: s.ek(carol), Joiner: c.Secrets.Joiner, GCtx: c.GCtx,
		Roster: []e2e.RosterLeaf{{Idx: 1, ID: alice, Leaf: 3}}, IX: make([]byte, 32), IK: s.ik(alice)})
	prop, _ := e2e.BuildProposal(gid, 1, 1, 0, 0, []byte(`{"rm":[2]}`), s.ik(alice))
	obj, _ := e2e.SealObject(e2e.ObjParams{GID: gid, Epoch: 1, Idx: 1, Ver: 1, OID: make([]byte, 16), OKind: 'n', Payload: []byte("{}"), MsgRoot: c.Secrets.MsgRoot, IK: s.ik(alice), Rand: rnd(3)})
	seeds := [][]byte{c.Row, app.Row, w, prop, obj}
	ok := genuine(seeds)
	ik := s.bundles[alice].IK
	ikB := s.bundles[bob].IK
	// commit and welcome rows carry HPKE encapsulations (random per process), so a verified row is judged
	// by its content: it must carry exactly what the genuine rows carry.
	return target{name: "group-rows", seeds: damaged(seeds), check: func(t testing.TB, b []byte) {
		verified := false
		if m, err := e2e.ParseApp(b); err == nil && m.VerifySig(ikB) {
			if in, err := m.Open(c.Secrets.MsgRoot); err == nil {
				if string(in.Payload) != "x" || in.CType != 1 {
					t.Fatal("app row with unknown content verified")
				}
				verified = true
			}
		}
		if cm, err := e2e.ParseCommit(b, e2e.CS1); err == nil && cm.VerifySig(ik) {
			if sec, _, err := cm.Process(2, s.sk(bob), e2e.InitSecret0, make([]byte, 32), e2e.RosterHash(roster)); err == nil {
				if !bytes.Equal(sec.Epoch, c.Secrets.Epoch) {
					t.Fatal("commit with another epoch secret verified")
				}
				verified = true
			}
		}
		if wm, err := e2e.ParseWelcome(b, e2e.CS1); err == nil && wm.VerifySig(ik) {
			if body, err := wm.Open(s.sk(carol)); err == nil {
				if !bytes.Equal(body.Joiner, c.Secrets.Joiner) || wm.To != carol {
					t.Fatal("welcome with unknown content verified")
				}
				verified = true
			}
		}
		if pm, err := e2e.ParseProposal(b); err == nil && pm.VerifySig(ik) {
			if string(pm.JSON) != `{"rm":[2]}` {
				t.Fatal("proposal with unknown content verified")
			}
			verified = true
		}
		if om, err := e2e.ParseObject(b); err == nil && om.VerifySig(ik) {
			if _, payload, err := om.Open(c.Secrets.MsgRoot); err == nil {
				if string(payload) != "{}" {
					t.Fatal("object with unknown content verified")
				}
				verified = true
			}
		}
		if !verified && ok[string(b)] {
			t.Fatal("genuine row refused")
		}
	}}
}

func merkleTarget(testing.TB) target {
	var tr e2e.Tree
	for i := 0; i < 9; i++ {
		tr.Append(e2e.LeafHash([]byte{byte(i)}))
	}
	root := tr.Root()
	seeds := [][]byte{[]byte(e2e.EncodePath(tr.Inclusion(3, 9))), []byte(e2e.EncodePath(tr.Consistency(4, 9))), []byte("")}
	return target{name: "merkle-path", seeds: damaged(seeds), check: func(t testing.TB, b []byte) {
		path, err := e2e.DecodePath(string(b))
		if err != nil {
			return
		}
		if len(path) > e2e.MaxPathLen || len(path) > 0 && !strings.EqualFold(e2e.EncodePath(path), string(bytes.TrimSpace(b))) {
			t.Fatal("path codec")
		}
		gp := tr.Inclusion(3, 9)
		same := len(path) == len(gp)
		for i := 0; same && i < len(gp); i++ {
			same = bytes.Equal(path[i], gp[i])
		}
		if e2e.VerifyInclusion(tr.Leaf(3), 3, 9, path, root) != same {
			t.Fatal("inclusion with a mutated path")
		}
		e2e.VerifyConsistency(4, 9, tr.RootAt(4), root, path)
	}}
}

func stateTarget(testing.TB) target {
	k := e2e.KState(seedN(75))
	var seeds [][]byte
	for _, pt := range []string{"{}", `{"cursor":5,"seen":["a","b"]}`} {
		blob, _ := e2e.SealState(k, alice, 3, []byte(pt), rnd(1))
		seeds = append(seeds, blob, []byte(pt))
	}
	ok := genuine(seeds)
	return target{name: "state", seeds: damaged(seeds), check: func(t testing.TB, b []byte) {
		pt, err := e2e.OpenState(k, alice, 3, b)
		if (err == nil) != (ok[string(b)] && len(b) > 0 && b[0] == e2e.StateVer) {
			t.Fatalf("open genuine=%v", ok[string(b)])
		}
		if err == nil {
			if _, err := e2e.DecodeState(pt); err != nil {
				t.Fatal("genuine state does not decode")
			}
		}
		e2e.DecodeState(b)
	}}
}

func linesTarget(tb testing.TB) target {
	p := newPair(tb)
	l := &logEnv{p: p}
	for i := 0; i < 5; i++ {
		l.tree.Append(e2e.LeafHash([]byte{byte(i)}))
	}
	h := l.head(&l.tree, 5, now, true)
	ml, _ := e2e.FormatMirrorHead(h, 1)
	seeds := [][]byte{ml, []byte("size=5 root=" + hexZero(h.Root) + " at=1 sig=" + b64(h.Sig)), []byte("idx=1 leaf=" + hexZero(h.Root) + " path=" + e2e.EncodePath(l.tree.Inclusion(1, 5))),
		[]byte("path=" + e2e.EncodePath(l.tree.Consistency(2, 5))), []byte("5:" + hexZero(h.Root)[:16]), []byte(e2e.FormatSeed(seedN(1)))}
	return target{name: "lines", seeds: damaged(seeds), check: func(t testing.TB, b []byte) {
		s := string(b)
		if h, err := e2e.ParseMirrorHead(b); err == nil {
			if re, err := e2e.FormatMirrorHead(h, 0); err != nil || len(re) == 0 {
				t.Fatal("mirror head round trip")
			}
		}
		e2e.ParseSTHLine(s)
		e2e.ParseInclLine(s)
		e2e.ParseConsLine(s)
		e2e.ParseGossip(s)
		if seed, err := e2e.ParseSeed(s); err == nil && len(seed) != 32 {
			t.Fatal("seed length")
		}
	}}
}

func hexZero(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i], out[2*i+1] = digits[c>>4], digits[c&15]
	}
	return string(out)
}

func fuzz(f *testing.F, mk func(testing.TB) target) {
	tg := mk(f)
	for _, s := range tg.seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { tg.check(t, b) })
}

func FuzzEnvelope(f *testing.F)     { fuzz(f, envelopeTarget) }
func FuzzBundle(f *testing.F)       { fuzz(f, bundleTarget) }
func FuzzCxs1(f *testing.F)         { fuzz(f, cxs1Target) }
func FuzzReqSig(f *testing.F)       { fuzz(f, reqsigTarget) }
func FuzzCommitHeader(f *testing.F) { fuzz(f, commitHeaderTarget) }
func FuzzGroupRows(f *testing.F)    { fuzz(f, groupRowsTarget) }
func FuzzMerklePath(f *testing.F)   { fuzz(f, merkleTarget) }
func FuzzState(f *testing.F)        { fuzz(f, stateTarget) }
func FuzzLines(f *testing.F)        { fuzz(f, linesTarget) }

// mutate applies one to three random edits to a genuine seed.
func mutate(r *rand.Rand, seeds [][]byte) []byte {
	b := append([]byte(nil), seeds[r.IntN(len(seeds))]...)
	for n := 1 + r.IntN(3); n > 0; n-- {
		switch r.IntN(6) {
		case 0:
			if len(b) > 0 {
				b[r.IntN(len(b))] ^= 1 << uint(r.IntN(8))
			}
		case 1:
			if len(b) > 0 {
				b = b[:r.IntN(len(b))]
			}
		case 2:
			i := 0
			if len(b) > 0 {
				i = r.IntN(len(b) + 1)
			}
			b = append(b[:i], append([]byte{byte(r.IntN(256))}, b[i:]...)...)
		case 3:
			if len(b) > 0 {
				i := r.IntN(len(b))
				b = append(b[:i], b[i+1:]...)
			}
		case 4:
			if len(b) > 8 {
				i := r.IntN(len(b) - 8)
				for j := i; j < i+8; j++ {
					b[j] = byte(r.IntN(256))
				}
			}
		case 5:
			if len(b) > 0 {
				b[r.IntN(len(b))] = byte(r.IntN(256))
			}
		}
	}
	return b
}

func TestFuzzSweep(t *testing.T) {
	budget := 10 * time.Second
	if v, err := strconv.Atoi(os.Getenv("E2E_FUZZ_SECONDS")); err == nil && v >= 0 {
		budget = time.Duration(v) * time.Second
	}
	makers := []func(testing.TB) target{envelopeTarget, bundleTarget, cxs1Target, reqsigTarget, commitHeaderTarget, groupRowsTarget, merkleTarget, stateTarget, linesTarget}
	per := budget / time.Duration(len(makers))
	r := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 7))
	for _, mk := range makers {
		tg := mk(t)
		for _, s := range tg.seeds {
			tg.check(t, s)
		}
		n := 0
		for deadline := time.Now().Add(per); time.Now().Before(deadline); n++ {
			tg.check(t, mutate(r, tg.seeds))
		}
		t.Logf("%s: %d mutated inputs", tg.name, n)
	}
}
