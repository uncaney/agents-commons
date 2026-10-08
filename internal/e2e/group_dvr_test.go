package e2e_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/e2e"
)

type swarm struct {
	seeds   map[string][]byte
	bundles map[string]*e2e.Bundle
	leaf    map[string]uint64
	epoch   uint32
}

func newSwarm(t testing.TB) *swarm {
	t.Helper()
	s := &swarm{seeds: map[string][]byte{alice: seedN(50), bob: seedN(51), carol: seedN(52), dave: seedN(53)},
		bundles: map[string]*e2e.Bundle{}, leaf: map[string]uint64{alice: 3, bob: 5, carol: 8, dave: 13}, epoch: e2e.Epoch(now)}
	for id, seed := range s.seeds {
		s.bundles[id], _ = bundleFor(t, seed, id, 1, false, 0, s.epoch)
	}
	return s
}

func (s *swarm) member(idx uint16, id string) e2e.Member {
	return e2e.Member{Idx: idx, ID: id, IK: s.bundles[id].IK, Leaf: s.leaf[id]}
}

func (s *swarm) ek(id string) []byte {
	k, _ := s.bundles[id].EK(e2e.CS1, s.epoch)
	return k
}

func (s *swarm) sk(id string) hpke.PrivateKey {
	k, _ := e2e.EK(s.seeds[id], e2e.CS1, s.epoch, nil)
	return k
}

func (s *swarm) ik(id string) ed25519.PrivateKey { return e2e.IK(s.seeds[id]) }

func (s *swarm) fanout(ids ...string) []e2e.Fanout {
	var out []e2e.Fanout
	for i, id := range ids {
		out = append(out, e2e.Fanout{Idx: uint16(i + 1), Key: s.ek(id)})
	}
	return out
}

func TestCxg1ScheduleCommitWelcome(t *testing.T) {
	s := newSwarm(t)
	roster1 := []e2e.Member{s.member(1, alice), s.member(2, bob), s.member(3, carol)}
	rh1 := e2e.RosterHash(roster1)
	if !bytes.Equal(rh1, e2e.RosterHash([]e2e.Member{s.member(3, carol), s.member(1, alice), s.member(2, bob)})) {
		t.Fatal("roster hash must not depend on order")
	}
	alt := s.member(2, bob)
	alt.Leaf++
	if bytes.Equal(rh1, e2e.RosterHash([]e2e.Member{s.member(1, alice), alt, s.member(3, carol)})) {
		t.Fatal("roster hash must bind the log leaf")
	}
	th0 := make([]byte, 32)
	c1, err := e2e.BuildCommit(e2e.CommitParams{GID: gid, CS: e2e.CS1, Epoch: 1, Idx: 1, Gen: 1, Pol: 3,
		Header:  e2e.CommitHeader{Add: []e2e.Added{{ID: bob, Leaf: 5, EKH: e2e.EKH(s.ek(bob))}, {ID: carol, Leaf: 8, EKH: e2e.EKH(s.ek(carol))}}},
		Members: s.fanout(alice, bob, carol), InitPrev: e2e.InitSecret0, THPrev: th0, RosterHash: rh1, IK: s.ik(alice), Rand: rnd(1)})
	if err != nil {
		t.Fatal(err)
	}
	if len(c1.Row) != 85+2+len(c1.JSON)+2+3*(2+32+48)+32+64 {
		t.Fatalf("commit size %d", len(c1.Row))
	}
	want := e2e.Schedule(e2e.InitSecret0, c1.CommitSecret, c1.GCtx)
	if !bytes.Equal(want.Epoch, c1.Secrets.Epoch) || !bytes.Equal(want.MsgRoot, c1.Secrets.MsgRoot) || bytes.Equal(want.Init, want.Confirm) {
		t.Fatal("schedule")
	}
	pc, err := e2e.ParseCommit(c1.Row, e2e.CS1)
	if err != nil {
		t.Fatal(err)
	}
	if !pc.VerifySig(s.bundles[alice].IK) || pc.VerifySig(s.bundles[bob].IK) || pc.Header.E != 1 || pc.Header.By != 1 || pc.Header.TH != hex.EncodeToString(th0) || len(pc.Env) != 3 {
		t.Fatal("parsed commit")
	}
	for idx, id := range map[uint16]string{1: alice, 2: bob, 3: carol} {
		sec, cth, err := pc.Process(idx, s.sk(id), e2e.InitSecret0, th0, rh1)
		if err != nil || !bytes.Equal(sec.Epoch, c1.Secrets.Epoch) || !bytes.Equal(cth, c1.ConfirmedTH) {
			t.Fatalf("%s process: %v", id, err)
		}
	}
	// negatives: a disagreeing roster, a stale transcript, the wrong init secret, a non-member, the wrong key
	if _, _, err := pc.Process(2, s.sk(bob), e2e.InitSecret0, th0, e2e.Sum(rh1)); !errors.Is(err, e2e.ErrConfTag) {
		t.Fatalf("roster disagreement: %v", err)
	}
	if _, _, err := pc.Process(2, s.sk(bob), e2e.InitSecret0, e2e.Sum(th0), rh1); !errors.Is(err, e2e.ErrOrder) {
		t.Fatalf("stale transcript: %v", err)
	}
	if _, _, err := pc.Process(2, s.sk(bob), e2e.Sum(nil), th0, rh1); !errors.Is(err, e2e.ErrConfTag) {
		t.Fatalf("wrong init: %v", err)
	}
	if _, _, err := pc.Process(4, s.sk(dave), e2e.InitSecret0, th0, rh1); !errors.Is(err, e2e.ErrNoEnv) {
		t.Fatalf("non-member: %v", err)
	}
	if _, _, err := pc.Process(2, s.sk(carol), e2e.InitSecret0, th0, rh1); !errors.Is(err, e2e.ErrOpen) {
		t.Fatalf("wrong key: %v", err)
	}
	for i := 0; i < len(c1.Row); i += 13 {
		bad := append([]byte(nil), c1.Row...)
		bad[i] ^= 1
		if c, err := e2e.ParseCommit(bad, e2e.CS1); err == nil && c.VerifySig(s.bundles[alice].IK) {
			t.Fatalf("tampered commit byte %d accepted", i)
		}
	}
	// app message in epoch 1
	app, err := e2e.SealApp(e2e.AppParams{GID: gid, Epoch: 1, Idx: 2, Gen: 1, Pol: 3, CType: e2e.CTypeText, Payload: []byte("hi swarm"),
		MsgRoot: c1.Secrets.MsgRoot, IK: s.ik(bob), Rand: rnd(2)})
	if err != nil || len(app.Row) != 85+1024+16+64 {
		t.Fatal(err)
	}
	pa, err := e2e.ParseApp(app.Row)
	if err != nil || !pa.VerifySig(s.bundles[bob].IK) || pa.VerifySig(s.bundles[alice].IK) {
		t.Fatal("app parse/sig", err)
	}
	if in, err := pa.Open(c1.Secrets.MsgRoot); err != nil || string(in.Payload) != "hi swarm" || in.CType != e2e.CTypeText {
		t.Fatal("app open", err)
	}
	if _, err := pa.Open(e2e.Sum([]byte("other epoch"))); !errors.Is(err, e2e.ErrOpen) {
		t.Fatal("wrong epoch secret accepted")
	}
	for i := 0; i < len(app.Row); i += 11 {
		bad := append([]byte(nil), app.Row...)
		bad[i] ^= 1
		m, err := e2e.ParseApp(bad)
		if err != nil {
			continue
		}
		_, oerr := m.Open(c1.Secrets.MsgRoot)
		if m.VerifySig(s.bundles[bob].IK) && oerr == nil {
			t.Fatalf("tampered app byte %d accepted", i)
		}
	}
	// epoch 2: alice adds dave; the Welcome gives him the joiner secret and the roster leaves
	roster2 := append(append([]e2e.Member(nil), roster1...), s.member(4, dave))
	rh2 := e2e.RosterHash(roster2)
	c2, err := e2e.BuildCommit(e2e.CommitParams{GID: gid, CS: e2e.CS1, Epoch: 2, Idx: 1, Gen: 2, Pol: 3,
		Header:  e2e.CommitHeader{Add: []e2e.Added{{ID: dave, Leaf: 13, EKH: e2e.EKH(s.ek(dave))}}},
		Members: s.fanout(alice, bob, carol, dave), InitPrev: c1.Secrets.Init, THPrev: c1.ConfirmedTH, RosterHash: rh2, IK: s.ik(alice), Rand: rnd(3)})
	if err != nil {
		t.Fatal(err)
	}
	pc2, _ := e2e.ParseCommit(c2.Row, e2e.CS1)
	for idx, id := range map[uint16]string{1: alice, 2: bob, 3: carol} {
		sec, _, err := pc2.Process(idx, s.sk(id), c1.Secrets.Init, c1.ConfirmedTH, rh2)
		if err != nil || !bytes.Equal(sec.Epoch, c2.Secrets.Epoch) {
			t.Fatalf("%s epoch 2: %v", id, err)
		}
		if _, _, err := pc2.Process(idx, s.sk(id), c1.Secrets.Init, th0, rh2); !errors.Is(err, e2e.ErrOrder) {
			t.Fatal("stale member view accepted")
		}
	}
	ix := e2e.Sum([]byte("ix"))
	rosterLeaves := []e2e.RosterLeaf{{Idx: 1, ID: alice, Leaf: 3}, {Idx: 2, ID: bob, Leaf: 5}, {Idx: 3, ID: carol, Leaf: 8}, {Idx: 4, ID: dave, Leaf: 13}}
	w, err := e2e.BuildWelcome(e2e.WelcomeParams{GID: gid, CS: e2e.CS1, Epoch: 2, Idx: 1, Gen: 3, Pol: 3, To: dave, NewcomerKey: s.ek(dave),
		Joiner: c2.Secrets.Joiner, GCtx: c2.GCtx, Roster: rosterLeaves, IX: ix, Ext: []byte(`{"admins":[1]}`), IK: s.ik(alice)})
	if err != nil {
		t.Fatal(err)
	}
	pw, err := e2e.ParseWelcome(w, e2e.CS1)
	if err != nil || pw.To != dave || !pw.VerifySig(s.bundles[alice].IK) || pw.VerifySig(s.bundles[bob].IK) {
		t.Fatal("welcome parse", err)
	}
	body, err := pw.Open(s.sk(dave))
	if err != nil || !bytes.Equal(body.Joiner, c2.Secrets.Joiner) || len(body.Roster) != 4 || !bytes.Equal(body.IX, ix) || string(body.Ext) != `{"admins":[1]}` {
		t.Fatal("welcome open", err)
	}
	if _, err := pw.Open(s.sk(carol)); err == nil {
		t.Fatal("welcome opened by a non-addressee")
	}
	moved := append([]byte(nil), w...)
	copy(moved[85:92], carol)
	if pm, err := e2e.ParseWelcome(moved, e2e.CS1); err == nil {
		if _, err := pm.Open(s.sk(dave)); err == nil {
			t.Fatal("re-addressed welcome accepted")
		}
	}
	g, e, rhW, thPrev, err := e2e.ParseGroupContext(body.GCtx)
	if err != nil || g != gid || e != 2 || !bytes.Equal(thPrev, c1.ConfirmedTH) || !bytes.Equal(rhW, rh2) {
		t.Fatal("group context", err)
	}
	// the joiner rebuilds the roster from DVR-verified bundles and must land on the same hash
	var rebuilt []e2e.Member
	for _, rl := range body.Roster {
		rebuilt = append(rebuilt, e2e.Member{Idx: rl.Idx, ID: rl.ID, IK: s.bundles[rl.ID].IK, Leaf: rl.Leaf})
	}
	if !bytes.Equal(e2e.RosterHash(rebuilt), rhW) {
		t.Fatal("joiner roster hash")
	}
	// a roster leaf pointing at another id's bundle is caught by the hash before any key is derived
	wrong := append([]e2e.Member(nil), rebuilt...)
	wrong[1].IK = s.bundles[carol].IK
	if bytes.Equal(e2e.RosterHash(wrong), rhW) {
		t.Fatal("substituted roster key not detected")
	}
	secD := e2e.ScheduleFromJoiner(body.Joiner, body.GCtx)
	if !bytes.Equal(secD.Epoch, c2.Secrets.Epoch) || !bytes.Equal(secD.Init, c2.Secrets.Init) || !bytes.Equal(secD.MsgRoot, c2.Secrets.MsgRoot) || !bytes.Equal(secD.Confirm, c2.Secrets.Confirm) {
		t.Fatal("joiner schedule")
	}
	if _, err := pa.Open(secD.MsgRoot); err == nil {
		t.Fatal("newcomer opened a past epoch")
	}
	// dave posts, carol reads
	app2, _ := e2e.SealApp(e2e.AppParams{GID: gid, Epoch: 2, Idx: 4, Gen: 1, CType: e2e.CTypeStateOp, Payload: []byte(`{"op":"claim","k":"t1"}`),
		MsgRoot: secD.MsgRoot, IK: s.ik(dave), Rand: rnd(4)})
	pa2, _ := e2e.ParseApp(app2.Row)
	if in, err := pa2.Open(c2.Secrets.MsgRoot); err != nil || !pa2.VerifySig(s.bundles[dave].IK) || in.CType != e2e.CTypeStateOp {
		t.Fatal("epoch 2 message", err)
	}
	// epoch 3 removes bob: no envelope for idx 2, so bob cannot derive the epoch
	roster3 := []e2e.Member{s.member(1, alice), s.member(3, carol), s.member(4, dave)}
	c3, err := e2e.BuildCommit(e2e.CommitParams{GID: gid, CS: e2e.CS1, Epoch: 3, Idx: 1, Gen: 4, Header: e2e.CommitHeader{Rm: []uint16{2}, PP: []uint64{77}},
		Members:  []e2e.Fanout{{Idx: 1, Key: s.ek(alice)}, {Idx: 3, Key: s.ek(carol)}, {Idx: 4, Key: s.ek(dave)}},
		InitPrev: c2.Secrets.Init, THPrev: c2.ConfirmedTH, RosterHash: e2e.RosterHash(roster3), IK: s.ik(alice), Rand: rnd(5)})
	if err != nil {
		t.Fatal(err)
	}
	pc3, _ := e2e.ParseCommit(c3.Row, e2e.CS1)
	if _, _, err := pc3.Process(2, s.sk(bob), c2.Secrets.Init, c2.ConfirmedTH, e2e.RosterHash(roster3)); !errors.Is(err, e2e.ErrNoEnv) {
		t.Fatal("removed member derived the epoch")
	}
	if sec, _, err := pc3.Process(4, s.sk(dave), secD.Init, c2.ConfirmedTH, e2e.RosterHash(roster3)); err != nil || !bytes.Equal(sec.Epoch, c3.Secrets.Epoch) {
		t.Fatal("dave epoch 3", err)
	}
	// proposals: member-signed and server-signed
	online := ed25519.NewKeyFromSeed(seedN(100))
	prop, err := e2e.BuildProposal(gid, 3, 0, 0, 0, []byte(`{"rm":[3],"by":"server","why":"purge"}`), online)
	if err != nil {
		t.Fatal(err)
	}
	pp, err := e2e.ParseProposal(prop)
	if err != nil || !pp.VerifySig(pub(online)) || pp.VerifySig(s.bundles[alice].IK) {
		t.Fatal("proposal", err)
	}
	if _, err := e2e.BuildProposal(gid, 3, 0, 0, 0, []byte(`{"rm":`), online); err == nil {
		t.Fatal("invalid proposal json accepted")
	}
	// objects (encrypted spaces): sealed under the epoch, searchable by blind tag
	oid := e2e.Sum([]byte("task-1"))[:16]
	bt := e2e.BlindTag(ix, "Urgent")
	if !bytes.Equal(bt, e2e.BlindTag(ix, "urgent")) || len(bt) != 16 {
		t.Fatal("blind tag")
	}
	obj, err := e2e.SealObject(e2e.ObjParams{GID: gid, Epoch: 3, Idx: 4, Gen: 2, Ver: 1, OID: oid, OKind: 't', Tags: [][]byte{bt},
		Payload: []byte(`{"title":"ship it","body":"..."}`), MsgRoot: c3.Secrets.MsgRoot, IK: s.ik(dave), Rand: rnd(6)})
	if err != nil {
		t.Fatal(err)
	}
	po, err := e2e.ParseObject(obj)
	if err != nil || po.Ver != 1 || !bytes.Equal(po.OID, oid) || po.OKind != 't' || len(po.Tags) != 1 || !po.VerifySig(s.bundles[dave].IK) {
		t.Fatal("object parse", err)
	}
	if _, payload, err := po.Open(c3.Secrets.MsgRoot); err != nil || !strings.Contains(string(payload), "ship it") {
		t.Fatal("object open", err)
	}
	if _, _, err := po.Open(c2.Secrets.MsgRoot); err == nil {
		t.Fatal("object opened under another epoch")
	}
	// commit header parser
	for _, bad := range []string{`{"e":1,"by":1,"th":"ab"}`, `{"e":1,"by":1,"th":"` + hex.EncodeToString(th0) + `","x":1}`, `{"e":0,"by":1,"th":"` + hex.EncodeToString(th0) + `"}`,
		`{"e":1,"by":1,"th":"` + hex.EncodeToString(th0) + `"} {}`, `{"e":1,"by":1,"th":"` + hex.EncodeToString(th0) + `","add":[{"id":"bad","leaf":1,"ekh":"12345678"}]}`} {
		if _, err := e2e.ParseCommitHeader([]byte(bad)); err == nil {
			t.Fatalf("commit header %s accepted", bad)
		}
	}
	if _, err := e2e.ParseCommitHeader(bytes.Repeat([]byte(" "), e2e.CommitHdrCap+1)); err == nil {
		t.Fatal("oversized header accepted")
	}
}

type logEnv struct {
	p    *pair
	tree e2e.Tree
	wPKs map[string][]byte
}

func (l *logEnv) head(tr *e2e.Tree, size uint64, at int64, witness bool) *e2e.Head {
	h := &e2e.Head{Size: size, Root: tr.RootAt(size), At: uint64(at)}
	h.Sig = e2e.Sign(l.p.onlineSK, e2e.STHBytes(size, h.Root, h.At))
	if witness {
		h.Witness = map[string][]byte{"w1": e2e.Sign(l.p.w1SK, e2e.WitnessBytes(size, h.Root, h.At))}
	}
	return h
}

func TestDVRPure(t *testing.T) {
	p := newPair(t)
	l := &logEnv{p: p, wPKs: map[string][]byte{"w1": p.w1PK}}
	for i := 0; i < 5; i++ {
		l.tree.Append(e2e.LeafHash([]byte{byte(i)}))
	}
	chB, _ := p.bb.CanonicalHash()
	if l.tree.Append(e2e.KlogLeaf(1, bob, chB, 5)) != 5 {
		t.Fatal("leaf index")
	}
	for i := 0; i < 3; i++ {
		l.tree.Append(e2e.LeafHash([]byte{0x10 + byte(i)}))
	}
	hw := l.head(&l.tree, 9, now-3600, true)
	base := e2e.DVRInput{Now: now, ID: bob, Raw: p.rawB, Leaf: 5, OnlinePK: p.onlinePK, WitnessPKs: l.wPKs, Witnessed: hw, Inclusion: l.tree.Inclusion(5, 9)}
	res, err := e2e.DVR(base)
	if err != nil {
		t.Fatal(err)
	}
	ek2, _ := p.bb.EK(e2e.CS2, p.epoch)
	if res.CS != e2e.CS2 || res.Epoch != p.epoch || res.LT || res.Provisional || res.TOFU || !bytes.Equal(res.Key, ek2) ||
		res.Pin.Seq != 1 || res.Pin.CS != 2 || res.Pin.Leaf != 5 || res.Pin.Pol != e2e.PolicyBoth || res.Pin.FP != hex.EncodeToString(p.bb.Fingerprint()) || res.Cache.HeadSize != 9 {
		t.Fatalf("result %+v", res)
	}
	in := base
	in.ClientMaxCS = e2e.CS1
	ek1, _ := p.bb.EK(e2e.CS1, p.epoch)
	if res, err := e2e.DVR(in); err != nil || res.CS != e2e.CS1 || !bytes.Equal(res.Key, ek1) {
		t.Fatal("cs1 client", err)
	}
	step := func(t *testing.T, in e2e.DVRInput, want int, detail string) {
		t.Helper()
		_, err := e2e.DVR(in)
		var de *e2e.DVRError
		if !errors.As(err, &de) || de.Step != want || !strings.Contains(de.Detail, detail) || !strings.HasPrefix(err.Error(), "err dvr ") {
			t.Fatalf("want step %d %q, got %v", want, detail, err)
		}
	}
	// step 1
	in = base
	in.ID = carol
	step(t, in, 1, "id mismatch")
	in = base
	in.Raw = append([]byte(nil), p.rawB...)
	in.Raw[100] ^= 1
	step(t, in, 1, "signature")
	in = base
	in.Raw = in.Raw[:len(in.Raw)-1]
	step(t, in, 1, "shape")
	in = base
	in.Now = int64(p.bb.IAT) - 600
	step(t, in, 1, "iat")
	in = base
	in.Now = int64(p.bb.Exp) + 1
	step(t, in, 1, "expired")
	in = base
	in.Pin = &e2e.Pin{FP: res.Pin.FP, PQ: "ab"}
	step(t, in, 1, "pq_id")
	// step 2
	in = base
	in.Witnessed = nil
	step(t, in, 2, "mirror unreachable")
	in = base
	in.Pending = true
	step(t, in, 2, "pending")
	in = base
	in.Witnessed = l.head(&l.tree, 9, now-3600, false)
	step(t, in, 2, "witness")
	in = base
	in.WitnessPKs = map[string][]byte{"w1": p.onlinePK}
	step(t, in, 2, "witness")
	in = base
	in.Inclusion = l.tree.Inclusion(4, 9)
	step(t, in, 2, "inclusion")
	in = base
	in.Leaf = 6
	step(t, in, 2, "inclusion")
	in = base
	in.Witnessed = &e2e.Head{Size: 9, Root: hw.Root, At: hw.At, Sig: e2e.Sign(p.w1SK, e2e.STHBytes(9, hw.Root, hw.At)), Witness: hw.Witness}
	step(t, in, 2, "sth signature")
	in = base
	in.IndexSeq = 2
	step(t, in, 2, "refetch")
	// a leaf newer than the witnessed head: fresh server STH consistent with it -> provisional
	hw4 := l.head(&l.tree, 4, now-7200, true)
	sth := l.head(&l.tree, 9, now-600, false)
	prov := base
	prov.Witnessed, prov.ServerSTH, prov.Consistency = hw4, sth, l.tree.Consistency(4, 9)
	if res, err := e2e.DVR(prov); err != nil || !res.Provisional || res.Cache.HeadSize != 9 || !res.Cache.Provisional {
		t.Fatal("provisional", err)
	}
	in = prov
	in.ServerSTH = nil
	step(t, in, 2, "no sth")
	in = prov
	in.ServerSTH = l.head(&l.tree, 9, now-86401, false)
	step(t, in, 2, "stale head")
	in = prov
	in.ServerSTH = l.head(&l.tree, 9, now+600, false)
	step(t, in, 2, "future")
	in = prov
	in.Consistency = l.tree.Consistency(3, 9)
	step(t, in, 2, "fork")
	// the host forks the log for the victim: bob's leaf substituted by an attacker bundle, served with a
	// fresh STH over the fork. The fork is inconsistent with the witnessed head.
	attacker := seedN(66)
	ab, err := e2e.NewBundle(attacker, e2e.BundleParams{ID: bob, Seq: 2, IAT: uint32(now - 60), Exp: uint32(now + 86400), Flags: e2e.FlagCS2,
		MailPolicy: e2e.PolicyBoth, MinCS: 1, E0: p.epoch, NEK: 5, RevCommit: make([]byte, 32), PrevHash: chB})
	if err != nil {
		t.Fatal(err)
	}
	rawAtt, _ := ab.Sign(e2e.IK(attacker), nil, nil)
	chA, _ := ab.CanonicalHash()
	var fork e2e.Tree
	for i := uint64(0); i < 9; i++ {
		if i == 5 {
			fork.Append(e2e.KlogLeaf(1, bob, chA, 5))
			continue
		}
		fork.Append(l.tree.Leaf(i))
	}
	fork.Append(e2e.KlogLeaf(1, bob, chA, 9))
	fork.Append(e2e.LeafHash([]byte("filler")))
	forkIn := base
	forkIn.Raw, forkIn.Leaf = rawAtt, 9
	forkIn.ServerSTH, forkIn.Inclusion, forkIn.Consistency = l.head(&fork, 11, now-60, false), fork.Inclusion(9, 11), fork.Consistency(9, 11)
	step(t, forkIn, 2, "fork")
	split := forkIn
	split.Witnessed, split.Consistency = hw4, fork.Consistency(4, 11)
	split.ServerSTH = l.head(&fork, 4, now-60, false)
	split.ServerSTH.Root = fork.RootAt(4)
	// same size as the witnessed head but a different root
	split.ServerSTH = &e2e.Head{Size: 4, Root: e2e.Sum([]byte("other")), At: uint64(now - 60)}
	split.ServerSTH.Sig = e2e.Sign(p.onlineSK, e2e.STHBytes(4, split.ServerSTH.Root, split.ServerSTH.At))
	step(t, split, 2, "split-view")
	// an unpublished substitute (not in any head the client holds) is unusable immediately
	unpub := base
	unpub.Raw = rawAtt
	step(t, unpub, 2, "inclusion")
	// step 3
	in = base
	in.Pin = &e2e.Pin{FP: res.Pin.FP, Seq: 2, CS: 2, Leaf: 5, Pol: 1}
	step(t, in, 3, "regress seq")
	in = base
	in.Pin = &e2e.Pin{FP: res.Pin.FP, Seq: 1, CS: 2, Leaf: 5, Pol: e2e.PolicyE2EE}
	step(t, in, 3, "regress policy")
	in = base
	in.Pin = &e2e.Pin{FP: res.Pin.FP, Seq: 1, CS: 2, Leaf: 7, Pol: 1}
	step(t, in, 3, "regress leaf")
	in = base
	in.Pin = &e2e.Pin{FP: hex.EncodeToString(p.ba.Fingerprint()), Seq: 1, CS: 2, Leaf: 5, Pol: 1}
	step(t, in, 3, "ik changed")
	in = base
	in.Pin = &e2e.Pin{FP: res.Pin.FP, Seq: 1, CS: 2, Leaf: 5, Pol: 1}
	if r, err := e2e.DVR(in); err != nil || r.Pin != *in.Pin {
		t.Fatal("pinned peer", err)
	}
	// a chained rotation: bob's seq 2 under a new ik, signed by the old one, at leaf 9 of the honest log
	newSeed := seedN(21)
	rb, _ := e2e.NewBundle(newSeed, e2e.BundleParams{ID: bob, Seq: 2, IAT: uint32(now - 60), Exp: uint32(now + 86400), Flags: e2e.FlagCS2,
		MailPolicy: e2e.PolicyBoth, MinCS: 1, E0: p.epoch, NEK: 5, RevCommit: make([]byte, 32), PrevHash: chB})
	rawRot, _ := rb.Sign(e2e.IK(newSeed), e2e.IK(p.sb), nil)
	chR, _ := rb.CanonicalHash()
	l.tree.Append(e2e.KlogLeaf(1, bob, chR, 9))
	hw10 := l.head(&l.tree, 10, now-60, true)
	rot := base
	rot.Raw, rot.Leaf, rot.Witnessed, rot.Inclusion = rawRot, 9, hw10, l.tree.Inclusion(9, 10)
	rot.Pin = &e2e.Pin{FP: res.Pin.FP, Seq: 1, CS: 2, Leaf: 5, Pol: 1}
	step(t, rot, 3, "ik changed")
	rot.PrevIK = p.bb.IK
	if r, err := e2e.DVR(rot); err != nil || r.Pin.FP != hex.EncodeToString(rb.Fingerprint()) || r.Pin.Seq != 2 {
		t.Fatal("rotation", err)
	}
	// step 4: a bundle without a current-epoch ek
	_, rawStale := bundleFor(t, p.sb, bob, 1, true, 0, p.epoch-10)
	var stTree e2e.Tree
	sb, _ := e2e.ParseBundle(rawStale)
	chSt, _ := sb.CanonicalHash()
	stTree.Append(e2e.KlogLeaf(1, bob, chSt, 0))
	stale := base
	stale.Raw, stale.Leaf, stale.Witnessed, stale.Inclusion = rawStale, 0, l.head(&stTree, 1, now-60, true), nil
	step(t, stale, 4, "stale-bundle")
	// ... unless lk_ok is set and the peer is unpinned
	_, rawLK := bundleFor(t, p.sb, bob, 1, true, e2e.FlagLKOK, p.epoch-10)
	lb, _ := e2e.ParseBundle(rawLK)
	chLK, _ := lb.CanonicalHash()
	var lkTree e2e.Tree
	lkTree.Append(e2e.KlogLeaf(1, bob, chLK, 0))
	lk := stale
	lk.Raw, lk.Witnessed = rawLK, l.head(&lkTree, 1, now-60, true)
	r, err := e2e.DVR(lk)
	if err != nil || !r.LT || r.Epoch != 0 || !bytes.Equal(r.Key, lb.LK2) {
		t.Fatal("lk_ok", err)
	}
	lk.Pin = &e2e.Pin{FP: hex.EncodeToString(lb.Fingerprint()), Seq: 1, CS: 2, Leaf: 0, Pol: 1}
	step(t, lk, 4, "stale-bundle")
	// first hour of a week: e-1 is accepted (a bundle issued before that week, listing epochs up to e-1)
	fhNow := e2e.EpochStart(p.epoch-5) + 100
	fb, err := e2e.NewBundle(p.sb, e2e.BundleParams{ID: bob, Seq: 1, IAT: uint32(fhNow - 86400), Exp: uint32(fhNow + 86400), Flags: e2e.FlagCS2,
		MailPolicy: e2e.PolicyBoth, MinCS: 1, E0: p.epoch - 10, NEK: 5, RevCommit: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	rawFH, _ := fb.Sign(e2e.IK(p.sb), nil, nil)
	chFH, _ := fb.CanonicalHash()
	var fhTree e2e.Tree
	fhTree.Append(e2e.KlogLeaf(1, bob, chFH, 0))
	fh := stale
	fh.Raw, fh.Witnessed, fh.Now = rawFH, l.head(&fhTree, 1, fhNow-60, true), fhNow
	if r, err := e2e.DVR(fh); err != nil || r.Epoch != p.epoch-6 || r.LT {
		t.Fatal("first hour", err)
	}
	fh.Now = e2e.EpochStart(p.epoch-5) + 3601
	fh.Witnessed = l.head(&fhTree, 1, fh.Now-60, true)
	step(t, fh, 4, "stale-bundle")
	// tier D: no mirror, the server's own fresh STH
	tofu := base
	tofu.Witnessed, tofu.TOFU, tofu.ServerSTH = nil, true, l.head(&l.tree, 9, now-600, false)
	if r, err := e2e.DVR(tofu); err != nil || !r.TOFU || r.Provisional {
		t.Fatal("tofu", err)
	}
	tofu.ServerSTH = l.head(&l.tree, 9, now-90000, false)
	step(t, tofu, 2, "stale head")
	// step 5
	if err := e2e.VerifyOwnEntry([]uint64{5, 9}, []uint64{9, 5}); err != nil {
		t.Fatal(err)
	}
	if err := e2e.VerifyOwnEntry([]uint64{5}, []uint64{5, 9}); !errors.Is(err, e2e.ErrKeySubstituted) {
		t.Fatalf("foreign leaf: %v", err)
	}
	if err := e2e.VerifyOwnEntry([]uint64{5, 9}, []uint64{5}); err == nil {
		t.Fatal("withheld leaf accepted")
	}
	// wire parsers
	line := "size=9 root=" + hex.EncodeToString(hw.Root) + " at=" + itoa(int64(hw.At)) + " sig=" + b64(hw.Sig) + " cert=AAAA\n"
	ph, cert, err := e2e.ParseSTHLine(line)
	if err != nil || ph.Size != 9 || !bytes.Equal(ph.Root, hw.Root) || !bytes.Equal(ph.Sig, hw.Sig) || len(cert) != 3 {
		t.Fatal("sth line", err)
	}
	if _, _, err := e2e.ParseSTHLine("size=x root=00"); err == nil {
		t.Fatal("bad sth line accepted")
	}
	ml, err := e2e.FormatMirrorHead(hw, 1)
	if err != nil {
		t.Fatal(err)
	}
	mh, err := e2e.ParseMirrorHead(ml)
	if err != nil || mh.Size != 9 || !bytes.Equal(mh.Witness["w1"], hw.Witness["w1"]) || e2e.VerifyHead(mh, p.onlinePK, l.wPKs, 1) != nil {
		t.Fatal("mirror head", err)
	}
	if _, err := e2e.ParseMirrorHead([]byte(`{"size":1,"root":"zz"}`)); err == nil {
		t.Fatal("bad mirror head accepted")
	}
	idx, leaf, path, err := e2e.ParseInclLine("idx=5 leaf=" + hex.EncodeToString(l.tree.Leaf(5)) + " path=" + e2e.EncodePath(l.tree.Inclusion(5, 9)))
	if err != nil || idx != 5 || !bytes.Equal(leaf, l.tree.Leaf(5)) || !e2e.VerifyInclusion(leaf, idx, 9, path, hw.Root) {
		t.Fatal("incl line", err)
	}
	cp, err := e2e.ParseConsLine("path=" + e2e.EncodePath(l.tree.Consistency(4, 9)))
	if err != nil || !e2e.VerifyConsistency(4, 9, l.tree.RootAt(4), hw.Root, cp) {
		t.Fatal("cons line", err)
	}
	gh := e2e.GossipHeader(9, hw.Root)
	gs, gr, err := e2e.ParseGossip(gh)
	if err != nil || gs != 9 || gr != hex.EncodeToString(hw.Root)[:16] || !e2e.SplitView(9, gr, 9, "0000000000000000") || e2e.SplitView(9, gr, 10, "0000000000000000") {
		t.Fatal("gossip", err)
	}
	if _, _, err := e2e.ParseGossip("9:abc"); err == nil {
		t.Fatal("bad gossip accepted")
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func b64(b []byte) string {
	const al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out []byte
	for i := 0; i < len(b); i += 3 {
		var v uint32
		n := 0
		for j := 0; j < 3; j++ {
			v <<= 8
			if i+j < len(b) {
				v |= uint32(b[i+j])
				n++
			}
		}
		for j := 0; j < n+1; j++ {
			out = append(out, al[(v>>(18-6*j))&63])
		}
	}
	return string(out)
}
