package kat

import (
	"bytes"
	"crypto/hpke"
	"encoding/json"
	"errors"
	"fmt"

	"ekaii.fr/commons/internal/e2e"
)

// ---- cxg1.json

type memberVec struct {
	Idx  uint16 `json:"idx"`
	ID   string `json:"id"`
	Seed string `json:"seed"`
	IK   string `json:"ik"`
	Leaf uint64 `json:"leaf"`
	EK   string `json:"ek"` // ek1(KeyEpoch) the commit sealed to
}

type schedVec struct {
	Joiner  string `json:"joiner_secret"`
	Epoch   string `json:"epoch_secret"`
	Init    string `json:"init_secret"`
	Confirm string `json:"confirmation_key"`
	MsgRoot string `json:"msg_root"`
}

type appVec struct {
	Idx     uint16 `json:"idx"`
	Gen     uint32 `json:"gen"`
	Pol     uint16 `json:"pol"`
	S       string `json:"s"`
	KF      string `json:"kf"`
	CType   uint8  `json:"ctype"`
	Payload string `json:"payload"`
	C       string `json:"c"`
	Key     string `json:"key"`
	Padded  string `json:"padded"`
	Hdr     string `json:"hdr"`
	CT      string `json:"ct"`
	Sig     string `json:"sig"`
	Row     string `json:"row"`
}

type rosterVec struct {
	Idx  uint16 `json:"idx"`
	ID   string `json:"id"`
	Leaf uint64 `json:"leaf"`
}

type welVec struct {
	To     string      `json:"to"`
	Seed   string      `json:"seed"`
	Key    string      `json:"key"`
	Gen    uint32      `json:"gen"`
	Roster []rosterVec `json:"roster"`
	IX     string      `json:"ix"`
	Ext    string      `json:"ext"`
	Body   string      `json:"body"` // plaintext: joiner || gctx || roster leaves || ix || ext
	Row    string      `json:"row"`  // recorded (HPKE)
}

type objVec struct {
	Idx     uint16   `json:"idx"`
	Gen     uint32   `json:"gen"`
	Pol     uint16   `json:"pol"`
	Ver     uint32   `json:"ver"`
	OID     string   `json:"oid"`
	OKind   string   `json:"okind"`
	Tags    []string `json:"tags"`
	S       string   `json:"s"`
	KF      string   `json:"kf"`
	Payload string   `json:"payload"`
	C       string   `json:"c"`
	Key     string   `json:"key"`
	Row     string   `json:"row"`
}

type btVec struct {
	IX  string `json:"ix"`
	Tag string `json:"tag"`
	BT  string `json:"bt"`
}

type cxg1Neg struct {
	Kind       string `json:"kind"` // no-env | roster | order | app-row | commit-row | welcome-key | object-row
	What       string `json:"what"`
	Idx        uint16 `json:"idx,omitempty"`
	Seed       string `json:"seed,omitempty"`
	RosterHash string `json:"roster_hash,omitempty"`
	THPrev     string `json:"th_prev,omitempty"`
	Row        string `json:"row,omitempty"`
}

type cxg1Doc struct {
	Name         string      `json:"name"`
	Description  string      `json:"description"`
	GID          string      `json:"gid"`
	CS           uint8       `json:"cs"`
	KeyEpoch     uint32      `json:"key_epoch"` // prekey epoch of the member keys
	Epoch        uint32      `json:"epoch"`     // group epoch of the commit
	Members      []memberVec `json:"members"`
	RosterHash   string      `json:"roster_hash"`
	THPrev       string      `json:"th_prev"`
	InitPrev     string      `json:"init_prev"`
	CommitSecret string      `json:"commit_secret"`
	GCtx         string      `json:"group_context"`
	Schedule     schedVec    `json:"schedule"`
	Header       string      `json:"header"` // clear_hdr_json
	Envs         string      `json:"envs"`   // recorded (HPKE)
	TH           string      `json:"th"`
	ConfTag      string      `json:"conf_tag"`
	ConfirmedTH  string      `json:"confirmed_th"`
	Sig          string      `json:"sig"`
	Row          string      `json:"row"`
	App          appVec      `json:"app"`
	Welcome      welVec      `json:"welcome"`
	Object       objVec      `json:"object"`
	BlindTags    []btVec     `json:"blind_tags"`
	Negative     []cxg1Neg   `json:"negative"`
}

func (d *cxg1Doc) members(x *dec) ([]e2e.Member, map[uint16][]byte) {
	var ms []e2e.Member
	seeds := map[uint16][]byte{}
	for _, m := range d.Members {
		ms = append(ms, e2e.Member{Idx: m.Idx, ID: m.ID, IK: x.b(m.IK), Leaf: m.Leaf})
		seeds[m.Idx] = x.b(m.Seed)
	}
	return ms, seeds
}

func memberSK(seed []byte, cs e2e.Suite, epoch uint32) hpke.PrivateKey {
	k, err := e2e.EK(seed, cs, epoch, nil)
	if err != nil {
		panic(err)
	}
	return k
}

// commitRow assembles a commit from recorded envs; every other byte is deterministic.
func commitRow(d *cxg1Doc, x *dec, envs []byte) (hdr, js, th, tag, sig, row []byte, sec e2e.EpochSecrets, err error) {
	seeds := map[uint16][]byte{}
	for _, m := range d.Members {
		seeds[m.Idx] = x.b(m.Seed)
	}
	h := e2e.GHdr{Kind: e2e.GKindCommit, GID: d.GID, Epoch: d.Epoch, Idx: 1, Gen: 1, Pol: 3, S: make([]byte, 32), C: make([]byte, 32)}
	hdr = h.Marshal()
	js = []byte(d.Header)
	thPrev, initPrev, rh, cs := x.b(d.THPrev), x.b(d.InitPrev), x.b(d.RosterHash), x.b(d.CommitSecret)
	if x.err != nil {
		return nil, nil, nil, nil, nil, nil, sec, x.err
	}
	th = e2e.TranscriptHash(thPrev, js, envs)
	sec = e2e.Schedule(initPrev, cs, e2e.GroupContext(d.GID, d.Epoch, rh, thPrev))
	tag = e2e.ConfTag(sec.Confirm, th)
	sig = e2e.GSig(e2e.IK(seeds[1]), hdr, js, envs, tag)
	row = append(append(append(append(append(append([]byte(nil), hdr...), e2e.U16(uint16(len(js)))...), js...), envs...), tag...), sig...)
	return
}

func (g *gen) cxg1() (*cxg1Doc, error) {
	var prior cxg1Doc
	hasPrior := g.priorDoc("cxg1.json", &prior)
	d := &cxg1Doc{Name: "cxg1", Description: "Group protocol (E2EE 5): roster_hash = sha256 of (u16 idx || id || ik || u64 leaf) sorted by idx; GroupContext = \"cx1/gctx\" || 0x00 || gid || u32(e) || roster_hash || confirmed_th_{e-1}; joiner = HKDF-Extract(salt = init_{e-1}, ikm = commit_secret); epoch_secret = Expand(joiner, \"cx1/epoch\" || 0x00 || GroupContext, 32); init/confirmation_key/msg_root = Expand(epoch_secret, \"cx1/init\"|\"cx1/confirm\"|\"cx1/msg\", 32); th = sha256(confirmed_th_{e-1} || clear_hdr_json || envs); conf_tag = HMAC(confirmation_key, th); confirmed_th = sha256(th || conf_tag). Rows: 85-byte header (ver 1 | kind | gid | epoch | idx | gen | pol | s | C). App: k_m = HKDF(msg_root, salt = s, \"cx1/gmsg\" || 0x00 || gid || u32(e) || u16(idx), 32), AES-256-GCM nonce 0, aad = hdr; sig = Ed25519(ik, \"cx1/gsig\" || 0x00 || hdr || ct). Commit envs (recorded: HPKE) = n u16 | n x (idx u16 | enc | ct48), each hpke.Seal(member ek, info \"cx1/gcommit\" || 0x00 || gid || u32(e), commit_secret); clear_hdr_json.th is the confirmed transcript hash the committer built on. Welcome (recorded): hdr | to | enc | ct | sig with aad = hdr || to, pt = joiner || GroupContext || u16 n || n x (u16 idx | id | u64 leaf) || ix || ext."}
	d.GID, d.CS, d.KeyEpoch, d.Epoch = gid, 1, e2e.Epoch(now), 1
	ids := []string{alice, bob, carol}
	leaves := []uint64{3, 5, 8}
	for i, id := range ids {
		s := g.seed()
		d.Members = append(d.Members, memberVec{Idx: uint16(i + 1), ID: id, Seed: hx(s), IK: hx(pub(e2e.IK(s))), Leaf: leaves[i], EK: hx(memberSK(s, e2e.CS1, d.KeyEpoch).PublicKey().Bytes())})
	}
	x := &dec{}
	ms, seeds := d.members(x)
	rh := e2e.RosterHash(ms)
	d.RosterHash, d.THPrev, d.InitPrev, d.CommitSecret = hx(rh), hx(make([]byte, 32)), hx(e2e.InitSecret0), hx(g.d.bytes(32))
	ch := e2e.CommitHeader{E: 1, By: 1, Add: []e2e.Added{{ID: bob, Leaf: 5, EKH: e2e.EKH(mustHex(d.Members[1].EK))}, {ID: carol, Leaf: 8, EKH: e2e.EKH(mustHex(d.Members[2].EK))}}, TH: d.THPrev, Ext: json.RawMessage(`{"admins":[1]}`)}
	js, _ := json.Marshal(&ch)
	d.Header = string(js)
	d.GCtx = hx(e2e.GroupContext(gid, 1, rh, make([]byte, 32)))
	var envs []byte
	if hasPrior && prior.Header == d.Header && prior.CommitSecret == d.CommitSecret && sameMembers(prior.Members, d.Members) && envsOpen(&prior, mustHex(prior.Envs)) == nil {
		envs = mustHex(prior.Envs)
	} else {
		var fan []e2e.Fanout
		for _, m := range d.Members {
			fan = append(fan, e2e.Fanout{Idx: m.Idx, Key: mustHex(m.EK)})
		}
		b, err := e2e.BuildCommit(e2e.CommitParams{GID: gid, CS: e2e.CS1, Epoch: 1, Idx: 1, Gen: 1, Pol: 3, Header: ch, Members: fan, CommitSecret: mustHex(d.CommitSecret),
			InitPrev: e2e.InitSecret0, THPrev: make([]byte, 32), RosterHash: rh, IK: e2e.IK(seeds[1])})
		if err != nil {
			return nil, err
		}
		envs = b.Envs
	}
	d.Envs = hx(envs)
	_, _, th, tag, sig, row, sec, err := commitRow(d, x, envs)
	if err != nil {
		return nil, err
	}
	d.TH, d.ConfTag, d.ConfirmedTH, d.Sig, d.Row = hx(th), hx(tag), hx(e2e.ConfirmedTH(th, tag)), hx(sig), hx(row)
	d.Schedule = schedVec{Joiner: hx(sec.Joiner), Epoch: hx(sec.Epoch), Init: hx(sec.Init), Confirm: hx(sec.Confirm), MsgRoot: hx(sec.MsgRoot)}
	// app message from bob
	s, kf := g.d.bytes(32), g.d.bytes(32)
	payload := []byte(`{"op":"claim","k":"t1","prev_head":"` + hx(g.d.bytes(8)) + `"}`)
	app, err := e2e.SealApp(e2e.AppParams{GID: gid, Epoch: 1, Idx: 2, Gen: 7, Pol: 3, KF: kf, S: s, CType: e2e.CTypeStateOp, Payload: payload, MsgRoot: sec.MsgRoot, IK: e2e.IK(seeds[2])})
	if err != nil {
		return nil, err
	}
	d.App = appVec{Idx: 2, Gen: 7, Pol: 3, S: hx(s), KF: hx(kf), CType: e2e.CTypeStateOp, Payload: hx(payload), C: hx(e2e.GFrank(kf, gid, 1, 2, 7, e2e.CTypeStateOp, payload)),
		Key: hx(app.Key), Padded: hx(app.Padded), Hdr: hx(app.Hdr), CT: hx(app.CT), Sig: hx(app.Sig), Row: hx(app.Row)}
	// welcome to dave at epoch 1
	ds := g.seed()
	ix := g.d.bytes(32)
	roster := []rosterVec{{1, alice, 3}, {2, bob, 5}, {3, carol, 8}, {4, dave, 13}}
	w := welVec{To: dave, Seed: hx(ds), Key: hx(memberSK(ds, e2e.CS1, d.KeyEpoch).PublicKey().Bytes()), Gen: 2, Roster: roster, IX: hx(ix), Ext: hx([]byte(`{"admins":[1]}`))}
	body := welcomeBody(sec.Joiner, mustHex(d.GCtx), roster, ix, []byte(`{"admins":[1]}`))
	w.Body = hx(body)
	if hasPrior && prior.Welcome.Body == w.Body && prior.Welcome.Seed == w.Seed && welcomeOpens(prior.Welcome, mustHex(prior.Members[0].IK), mustHex(prior.Welcome.Row)) == nil {
		w.Row = prior.Welcome.Row
	} else {
		var rl []e2e.RosterLeaf
		for _, r := range roster {
			rl = append(rl, e2e.RosterLeaf{Idx: r.Idx, ID: r.ID, Leaf: r.Leaf})
		}
		row, err := e2e.BuildWelcome(e2e.WelcomeParams{GID: gid, CS: e2e.CS1, Epoch: 1, Idx: 1, Gen: 2, Pol: 3, To: dave, NewcomerKey: mustHex(w.Key), Joiner: sec.Joiner, GCtx: mustHex(d.GCtx),
			Roster: rl, IX: ix, Ext: []byte(`{"admins":[1]}`), IK: e2e.IK(seeds[1])})
		if err != nil {
			return nil, err
		}
		w.Row = hx(row)
	}
	d.Welcome = w
	// object from alice with two blind tags
	oid := g.d.bytes(16)
	tags := []string{"Urgent", "release"}
	var bts [][]byte
	for _, t := range tags {
		bt := e2e.BlindTag(ix, t)
		bts = append(bts, bt)
		d.BlindTags = append(d.BlindTags, btVec{IX: hx(ix), Tag: t, BT: hx(bt)})
	}
	d.BlindTags = append(d.BlindTags, btVec{IX: hx(ix), Tag: "URGENT", BT: hx(e2e.BlindTag(ix, "urgent"))})
	os, okf := g.d.bytes(32), g.d.bytes(32)
	opayload := []byte(`{"title":"ship it","body":"cut the release","tags":["urgent","release"],"ts":1790000000}`)
	orow, err := e2e.SealObject(e2e.ObjParams{GID: gid, Epoch: 1, Idx: 1, Gen: 2, Pol: 3, Ver: 1, OID: oid, OKind: 't', Tags: bts, KF: okf, S: os, Payload: opayload, MsgRoot: sec.MsgRoot, IK: e2e.IK(seeds[1])})
	if err != nil {
		return nil, err
	}
	d.Object = objVec{Idx: 1, Gen: 2, Pol: 3, Ver: 1, OID: hx(oid), OKind: "t", Tags: hxs(bts), S: hx(os), KF: hx(okf), Payload: hx(opayload),
		C: hx(e2e.ObjFrank(okf, gid, oid, 1, 't', opayload)), Key: hx(e2e.ObjKey(sec.MsgRoot, os, gid, oid, 1)), Row: hx(orow)}
	// negatives
	alt := append([]e2e.Member(nil), ms...)
	alt[1].IK = ms[2].IK
	appBad := append([]byte(nil), app.Row...)
	appBad[100] ^= 1
	commitBad := append([]byte(nil), row...)
	commitBad[len(row)-70] ^= 1 // inside conf_tag
	objBad := mustHex(d.Object.Row)
	objBad[200] ^= 1
	d.Negative = []cxg1Neg{
		{Kind: "no-env", What: "a non-member (idx 4) finds no envelope: commit missing one member", Idx: 4, Seed: hx(ds)},
		{Kind: "roster", What: "roster leaf pointing at another id's bundle: GroupContext differs, confirmation tag mismatch", Idx: 2, RosterHash: hx(e2e.RosterHash(alt))},
		{Kind: "order", What: "member whose confirmed transcript differs: err order", Idx: 2, THPrev: hx(e2e.Sum([]byte("elsewhere")))},
		{Kind: "app-row", What: "flipped app ciphertext byte", Row: hx(appBad)},
		{Kind: "commit-row", What: "flipped confirmation tag byte (signature covers it)", Row: hx(commitBad)},
		{Kind: "welcome-key", What: "welcome opened with a member's key instead of the newcomer's", Idx: 1},
		{Kind: "object-row", What: "flipped object byte", Row: hx(objBad)},
	}
	return d, nil
}

func sameMembers(a, b []memberVec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func welcomeBody(joiner, gctx []byte, roster []rosterVec, ix, ext []byte) []byte {
	out := append(append(append([]byte(nil), joiner...), gctx...), e2e.U16(uint16(len(roster)))...)
	for _, r := range roster {
		out = append(out, e2e.U16(r.Idx)...)
		out = append(out, r.ID...)
		out = append(out, e2e.U64(r.Leaf)...)
	}
	return append(append(out, ix...), ext...)
}

// envsOpen checks that every recorded commit envelope decapsulates to the commit secret.
func envsOpen(d *cxg1Doc, envs []byte) error {
	x := &dec{}
	_, seeds := d.members(x)
	hdr, js, _, tag, sig, _, _, err := commitRow(d, x, envs)
	if err != nil {
		return err
	}
	row := append(append(append(append(append(append([]byte(nil), hdr...), e2e.U16(uint16(len(js)))...), js...), envs...), tag...), sig...)
	c, err := e2e.ParseCommit(row, e2e.Suite(d.CS))
	if err != nil {
		return err
	}
	for _, m := range d.Members {
		s, err := c.OpenSecret(m.Idx, memberSK(seeds[m.Idx], e2e.Suite(d.CS), d.KeyEpoch))
		if err != nil {
			return err
		}
		if err := want("commit secret", s, x.b(d.CommitSecret)); err != nil {
			return err
		}
	}
	return x.err
}

func welcomeOpens(w welVec, committerIK, row []byte) error {
	x := &dec{}
	pw, err := e2e.ParseWelcome(row, e2e.CS1)
	if err != nil {
		return err
	}
	if !pw.VerifySig(committerIK) || pw.To != w.To {
		return errors.New("welcome signature")
	}
	body, err := pw.Open(memberSK(x.b(w.Seed), e2e.CS1, e2e.Epoch(now)))
	if err != nil {
		return err
	}
	var rl []rosterVec
	for _, r := range body.Roster {
		rl = append(rl, rosterVec{Idx: r.Idx, ID: r.ID, Leaf: r.Leaf})
	}
	if err := want("welcome body", welcomeBody(body.Joiner, body.GCtx, rl, body.IX, body.Ext), x.b(w.Body)); err != nil {
		return err
	}
	return x.err
}

func checkCxg1(data []byte) error {
	var d cxg1Doc
	if err := unmarshal(data, &d); err != nil {
		return err
	}
	x := &dec{}
	ms, seeds := d.members(x)
	for _, m := range d.Members {
		if err := want("member ik", pub(e2e.IK(x.b(m.Seed))), x.b(m.IK)); err != nil {
			return err
		}
		if err := want("member ek", memberSK(x.b(m.Seed), e2e.Suite(d.CS), d.KeyEpoch).PublicKey().Bytes(), x.b(m.EK)); err != nil {
			return err
		}
	}
	rh := e2e.RosterHash(ms)
	if err := want("roster hash", rh, x.b(d.RosterHash)); err != nil {
		return err
	}
	if err := want("group context", e2e.GroupContext(d.GID, d.Epoch, rh, x.b(d.THPrev)), x.b(d.GCtx)); err != nil {
		return err
	}
	envs := x.b(d.Envs)
	if err := envsOpen(&d, envs); err != nil {
		return err
	}
	_, _, th, tag, sig, row, sec, err := commitRow(&d, x, envs)
	if err != nil {
		return err
	}
	for _, c := range []struct {
		what string
		got  []byte
		exp  string
	}{{"joiner", sec.Joiner, d.Schedule.Joiner}, {"epoch_secret", sec.Epoch, d.Schedule.Epoch}, {"init", sec.Init, d.Schedule.Init}, {"confirmation_key", sec.Confirm, d.Schedule.Confirm},
		{"msg_root", sec.MsgRoot, d.Schedule.MsgRoot}, {"th", th, d.TH}, {"conf_tag", tag, d.ConfTag}, {"confirmed_th", e2e.ConfirmedTH(th, tag), d.ConfirmedTH}, {"sig", sig, d.Sig}, {"row", row, d.Row}} {
		if err := want(c.what, c.got, x.b(c.exp)); err != nil {
			return err
		}
	}
	pc, err := e2e.ParseCommit(row, e2e.Suite(d.CS))
	if err != nil {
		return err
	}
	if !pc.VerifySig(ms[0].IK) {
		return errors.New("commit signature")
	}
	for _, m := range d.Members {
		got, cth, err := pc.Process(m.Idx, memberSK(seeds[m.Idx], e2e.Suite(d.CS), d.KeyEpoch), x.b(d.InitPrev), x.b(d.THPrev), rh)
		if err != nil || !bytes.Equal(got.Epoch, sec.Epoch) || !bytes.Equal(cth, x.b(d.ConfirmedTH)) {
			return fmt.Errorf("member %d process: %v", m.Idx, err)
		}
	}
	// app
	a := d.App
	payload, kf, s := x.b(a.Payload), x.b(a.KF), x.b(a.S)
	app, err := e2e.SealApp(e2e.AppParams{GID: d.GID, Epoch: d.Epoch, Idx: a.Idx, Gen: a.Gen, Pol: a.Pol, KF: kf, S: s, CType: a.CType, Payload: payload, MsgRoot: sec.MsgRoot, IK: e2e.IK(seeds[a.Idx])})
	if err != nil {
		return err
	}
	for _, c := range []struct {
		what string
		got  []byte
		exp  string
	}{{"app C", e2e.GFrank(kf, d.GID, d.Epoch, a.Idx, a.Gen, a.CType, payload), a.C}, {"app key", app.Key, a.Key}, {"app padded", app.Padded, a.Padded},
		{"app hdr", app.Hdr, a.Hdr}, {"app ct", app.CT, a.CT}, {"app sig", app.Sig, a.Sig}, {"app row", app.Row, a.Row}} {
		if err := want(c.what, c.got, x.b(c.exp)); err != nil {
			return err
		}
	}
	pa, err := e2e.ParseApp(app.Row)
	if err != nil {
		return err
	}
	in, err := pa.Open(sec.MsgRoot)
	if err != nil || !pa.VerifySig(ms[a.Idx-1].IK) || !bytes.Equal(in.Payload, payload) || !bytes.Equal(in.KF, kf) {
		return errors.New("app open")
	}
	// welcome
	if err := welcomeOpens(d.Welcome, ms[0].IK, x.b(d.Welcome.Row)); err != nil {
		return err
	}
	if err := want("welcome key", memberSK(x.b(d.Welcome.Seed), e2e.CS1, d.KeyEpoch).PublicKey().Bytes(), x.b(d.Welcome.Key)); err != nil {
		return err
	}
	pw, _ := e2e.ParseWelcome(x.b(d.Welcome.Row), e2e.CS1)
	body, err := pw.Open(memberSK(x.b(d.Welcome.Seed), e2e.CS1, d.KeyEpoch))
	if err != nil {
		return err
	}
	joined := e2e.ScheduleFromJoiner(body.Joiner, body.GCtx)
	if !bytes.Equal(joined.Epoch, sec.Epoch) || !bytes.Equal(joined.MsgRoot, sec.MsgRoot) || !bytes.Equal(body.IX, x.b(d.Welcome.IX)) || !bytes.Equal(body.Ext, x.b(d.Welcome.Ext)) {
		return errors.New("joiner schedule")
	}
	if _, e, rhW, _, err := e2e.ParseGroupContext(body.GCtx); err != nil || e != d.Epoch || !bytes.Equal(rhW, rh) {
		return errors.New("welcome group context")
	}
	// object
	o := d.Object
	oid, okf, os, op := x.b(o.OID), x.b(o.KF), x.b(o.S), x.b(o.Payload)
	orow, err := e2e.SealObject(e2e.ObjParams{GID: d.GID, Epoch: d.Epoch, Idx: o.Idx, Gen: o.Gen, Pol: o.Pol, Ver: o.Ver, OID: oid, OKind: o.OKind[0], Tags: x.bs(o.Tags), KF: okf, S: os, Payload: op, MsgRoot: sec.MsgRoot, IK: e2e.IK(seeds[o.Idx])})
	if err != nil {
		return err
	}
	if err := want("object row", orow, x.b(o.Row)); err != nil {
		return err
	}
	if err := want("object C", e2e.ObjFrank(okf, d.GID, oid, o.Ver, o.OKind[0], op), x.b(o.C)); err != nil {
		return err
	}
	if err := want("object key", e2e.ObjKey(sec.MsgRoot, os, d.GID, oid, o.Ver), x.b(o.Key)); err != nil {
		return err
	}
	po, err := e2e.ParseObject(orow)
	if err != nil {
		return err
	}
	if _, pl, err := po.Open(sec.MsgRoot); err != nil || !bytes.Equal(pl, op) || !po.VerifySig(ms[o.Idx-1].IK) {
		return errors.New("object open")
	}
	for _, b := range d.BlindTags {
		if err := want("blind tag "+b.Tag, e2e.BlindTag(x.b(b.IX), b.Tag), x.b(b.BT)); err != nil {
			return err
		}
	}
	for _, n := range d.Negative {
		var failed bool
		switch n.Kind {
		case "no-env":
			_, _, err := pc.Process(n.Idx, memberSK(x.b(n.Seed), e2e.CS1, d.KeyEpoch), x.b(d.InitPrev), x.b(d.THPrev), rh)
			failed = errors.Is(err, e2e.ErrNoEnv)
		case "roster":
			_, _, err := pc.Process(n.Idx, memberSK(seeds[n.Idx], e2e.CS1, d.KeyEpoch), x.b(d.InitPrev), x.b(d.THPrev), x.b(n.RosterHash))
			failed = errors.Is(err, e2e.ErrConfTag)
		case "order":
			_, _, err := pc.Process(n.Idx, memberSK(seeds[n.Idx], e2e.CS1, d.KeyEpoch), x.b(d.InitPrev), x.b(n.THPrev), rh)
			failed = errors.Is(err, e2e.ErrOrder)
		case "app-row":
			m, err := e2e.ParseApp(x.b(n.Row))
			if err != nil {
				failed = true
				break
			}
			_, oerr := m.Open(sec.MsgRoot)
			failed = oerr != nil || !m.VerifySig(ms[a.Idx-1].IK)
		case "commit-row":
			c, err := e2e.ParseCommit(x.b(n.Row), e2e.CS1)
			failed = err != nil || !c.VerifySig(ms[0].IK)
		case "welcome-key":
			_, err := pw.Open(memberSK(seeds[n.Idx], e2e.CS1, d.KeyEpoch))
			failed = err != nil
		case "object-row":
			ob, err := e2e.ParseObject(x.b(n.Row))
			if err != nil {
				failed = true
				break
			}
			_, _, oerr := ob.Open(sec.MsgRoot)
			failed = oerr != nil || !ob.VerifySig(ms[o.Idx-1].IK)
		default:
			return fmt.Errorf("unknown negative kind %q", n.Kind)
		}
		if !failed {
			return fmt.Errorf("negative %q accepted", n.What)
		}
	}
	return x.err
}
