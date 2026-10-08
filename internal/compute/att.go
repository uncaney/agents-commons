package compute

// Attestation surface (SPEC-v2 14.2 pages, 27.6 donor-signed results): publishing a job's signed
// att1 receipt as the public /att/<job> page, reproductions, the revoked list and the att sitemap.
// Wording is fixed here: a receipt is a replication observed by the gateway, never a proof.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// RevokedListFn lists the lines of GET /att/revoked.txt (14.5: one att1 line + reason per result
// revoked by an audit or a banned module, kept 1 y); P45 installs it. nil = an empty list.
var RevokedListFn func(ctx context.Context, q core.Q) ([]string, error)

const (
	receiptNote    = "replication receipt observed by agents.ekaii.fr, not a cryptographic proof of execution. Donor signatures bind each listed donor to this result; the server could still invent donors. Reproduce it yourself: POST /v1/j/<id>/reproduce"
	revokedHeader  = "# agents.ekaii.fr revoked compute results: one att1 line + reason per line (audit mismatch, banned module); kept 1 year"
	spkiPrefix     = "302a300506032b6570032100" // Ed25519 SubjectPublicKeyInfo DER prefix before the raw key
	maxSitemapAtt  = 5000
	b64Py          = `python3 -c 'import base64,sys;s=sys.argv[1];sys.stdout.buffer.write(base64.urlsafe_b64decode(s+"="*(-len(s)%4)))'`
	attPageMaxRows = 64 // agreeing replicas listed (2, 3 with a tie-break; bounded anyway)
)

// RegisterAtt mounts the attestation routes, the admin blob upload (adminblob.go), the att sitemap
// and the reproductions janitor. Register (P13) runs on the same Deps first.
func RegisterAtt(mux *http.ServeMux, d *core.Deps) { svcFor(d).registerAtt(mux) }

func (s *svc) registerAtt(mux *http.ServeMux) {
	d := s.d
	mux.HandleFunc("POST /v1/j/{id}/publish", s.hPublishJob)
	mux.HandleFunc("POST /v1/j/{id}/reproduce", s.hReproduce)
	mux.HandleFunc("GET /att/revoked.txt", s.hRevoked)
	mux.HandleFunc("GET /att/{job}", s.hAttPage)
	mux.HandleFunc("PUT /admin/blob", d.AdminOnly(s.hAdminBlob))
	d.RegisterScope("POST /v1/j/{id}/publish", "j")
	d.RegisterScope("POST /v1/j/{id}/reproduce", "j")
	d.RegisterSitemap("att", s.attSitemap)
	d.RegisterOpenAPI(openAPIAtt)
	d.Janitor.Add("compute_repro", func(ctx context.Context) error { return settleRepros(ctx, d.DB, "") })
}

// OpsAtt returns the MCP ops of this file (P60b merges them next to Ops).
func OpsAtt(d *core.Deps) map[string]Op {
	s := svcFor(d)
	return map[string]Op{"jpub": s.opJPub, "jrepro": s.opJRepro}
}

// OpMetaAtt describes OpsAtt for the registry (3.5).
var OpMetaAtt = map[string]core.OpMeta{
	"jpub":   {Scope: "j", Cost: 1, Mutating: true},
	"jrepro": {Scope: "j", Cost: 1, Mutating: true},
}

// HelpAtt is the help{t:att} text (<= 200 tokens).
const HelpAtt = `receipts: jpub{id} publish a finished job's signed att1 receipt as the public page /att/<id> (line, server key, verify one-liners, donor <id> pub= dsig= lease= tuples, repro=k/n)
jrepro{id,wait} re-run a published job's wasm+in (+fs, same ms/mb) as a new paid job of yours and compare: repro of=<id> match=0|1; GET /att/<id>.json for the tuples
GET /att/revoked.txt results revoked by audit | GET /.well-known/cx-key server key | GET /verify?s=&sig= online check. Receipts are replication observations, not proofs.`

// attJob is the jobs row as the receipt surface reads it.
type attJob struct {
	id, submitter, root, status, reason, wasm, input, fs, out string
	lane, kind, att, sig, cachedFrom                          string
	ms, mb, usedMs, code                                      int
	published                                                 bool
	created                                                   time.Time
	finished                                                  *time.Time
}

func loadAttJob(ctx context.Context, q core.Q, jid string) (*attJob, error) {
	j := &attJob{id: jid}
	err := q.QueryRow(ctx, `SELECT submitter, root, status, reason, wasm, input, fs, out, lane, kind, att, att_sig, cached_from, ms, mb, used_ms, code, published, created, finished_at
		FROM jobs WHERE id = $1`, jid).
		Scan(&j.submitter, &j.root, &j.status, &j.reason, &j.wasm, &j.input, &j.fs, &j.out, &j.lane, &j.kind, &j.att, &j.sig, &j.cachedFrom,
			&j.ms, &j.mb, &j.usedMs, &j.code, &j.published, &j.created, &j.finished)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return j, err
}

// outcome is the comparable result of a finalized job (reproductions compare it).
func (j *attJob) outcome() string {
	return j.status + ":" + j.reason + ":" + strconv.Itoa(j.code) + ":" + j.out
}

func (j *attJob) finishedAt() time.Time {
	if j.finished != nil {
		return *j.finished
	}
	return j.created
}

// attFields parses the canonical att1 line into its k=v fields.
func attFields(line string) map[string]string {
	f := map[string]string{}
	for _, tok := range strings.Fields(line)[1:] {
		if k, v, ok := strings.Cut(tok, "="); ok {
			f[k] = v
		}
	}
	return f
}

// --- publish ------------------------------------------------------------------------------------

// publishJob flips jobs.published for the submitter's finalized job (14.2). Own-lane jobs stay
// private; cached rows carry no receipt of their own.
func (s *svc) publishJob(ctx context.Context, id *core.Ident, jid string) (*attJob, error) {
	if !core.ValidIDPrefix(jid, 'j') {
		return nil, core.Bad("bad job id")
	}
	j, err := loadAttJob(ctx, s.d.DB, jid)
	if err != nil {
		return nil, err
	}
	if j == nil || j.root != id.Root {
		return nil, core.ErrNotFound
	}
	switch {
	case j.lane == "own":
		return nil, core.Bad("own-lane jobs are private")
	case j.att == "" && j.cachedFrom != "":
		return nil, core.E(409, "bad", "cached result has no receipt of its own")
	case j.att == "":
		return nil, core.E(409, "bad", jid+" "+j.status+" (no attestation yet)")
	}
	if j.published {
		return j, nil
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE jobs SET published = true WHERE id = $1`, jid); err != nil {
			return err
		}
		return core.Audit(ctx, tx, id.ID, "jpub", jid, 1)
	})
	if err != nil {
		return nil, err
	}
	j.published = true
	return j, nil
}

func publishReply(jid string) (string, map[string]any) {
	return "ok published " + jid + " /att/" + jid, map[string]any{"ok": true, "id": jid, "url": "/att/" + jid}
}

func (s *svc) hPublishJob(w http.ResponseWriter, r *http.Request) {
	id, err := s.authCompute(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	j, err := s.publishJob(r.Context(), id, r.PathValue("id"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	text, js := publishReply(j.id)
	core.OK(w, r, text, js)
}

func (s *svc) opJPub(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if err := s.checkIdent(id); err != nil {
		return "", err
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	j, err := s.publishJob(ctx, id, in.ID)
	if err != nil {
		return "", err
	}
	text, _ := publishReply(j.id)
	return text, nil
}

// --- reproduce ------------------------------------------------------------------------------------

// settleRepros records every finalized re-run of a published job's (wasm, input, fs, mb) that was
// created after the job finished as a reproductions row (match = same outcome), keyed by the
// re-run's root and finish time so the janitor and the waiting reproduce call never double count.
// jid narrows the pass to one published job ("" = all).
func settleRepros(ctx context.Context, q core.Q, jid string) error {
	_, err := q.Exec(ctx, `INSERT INTO reproductions (job, by_root, match, at)
		SELECT o.id, r.root, (o.status = r.status AND o.reason = r.reason AND o.code = r.code AND o.out = r.out), r.finished_at
		FROM jobs o JOIN jobs r ON r.wasm = o.wasm AND r.input = o.input AND r.fs = o.fs AND r.mb = o.mb
		WHERE o.published AND o.att <> '' AND ($1 = '' OR o.id = $1)
		  AND r.id <> o.id AND r.att <> '' AND r.cached_from = '' AND r.kind = 'job' AND r.lane <> 'own'
		  AND r.finished_at IS NOT NULL AND r.created > o.finished_at
		  AND NOT EXISTS (SELECT 1 FROM reproductions x WHERE x.job = o.id AND x.by_root = r.root AND x.at = r.finished_at)`, jid)
	return err
}

// reproCount returns (matched, total) reproductions of a job.
func reproCount(ctx context.Context, q core.Q, jid string) (int, int, error) {
	var k, n int
	err := q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE match), count(*) FROM reproductions WHERE job = $1`, jid).Scan(&k, &n)
	return k, n, err
}

// reproduce submits the published job's exact spec as a fresh paid job of the caller (14.2); with
// wait > 0 it long-polls the new job and, once final, records and reports the comparison.
func (s *svc) reproduce(ctx context.Context, id *core.Ident, jid string, wait int) (int, string, map[string]any, error) {
	if !core.ValidIDPrefix(jid, 'j') {
		return 0, "", nil, core.Bad("bad job id")
	}
	o, err := loadAttJob(ctx, s.d.DB, jid)
	if err != nil {
		return 0, "", nil, err
	}
	if o == nil || (!o.published && o.root != id.Root) {
		return 0, "", nil, core.ErrNotFound
	}
	switch {
	case o.lane == "own":
		return 0, "", nil, core.Bad("own-lane jobs are private")
	case o.att == "":
		return 0, "", nil, core.E(409, "bad", jid+" "+o.status+" (no attestation yet)")
	}
	res, err := s.submit(ctx, id, []Spec{{Wasm: o.wasm, In: o.input, FS: o.fs, Ms: o.ms, Mb: o.mb, Fresh: true}})
	if err != nil {
		return 0, "", nil, err
	}
	if err := core.Audit(ctx, s.d.DB, id.ID, "jrepro", jid, 1); err != nil {
		return 0, "", nil, err
	}
	st, text, j := s.reply(res)
	rid := res.ids[0]
	j["repro_of"] = jid
	line := "repro of=" + jid
	if wait > 0 {
		v, err := s.status(ctx, id, rid, wait)
		if err != nil {
			return 0, "", nil, err
		}
		if v.final() {
			if err := settleRepros(ctx, s.d.DB, jid); err != nil {
				return 0, "", nil, err
			}
			r, err := loadAttJob(ctx, s.d.DB, rid)
			if err != nil {
				return 0, "", nil, err
			}
			match := r != nil && r.att != "" && r.outcome() == o.outcome()
			st, text, j = 200, v.text(), v.json()
			j["repro_of"], j["match"] = jid, match
			line += fmt.Sprintf(" match=%d", b2i(match))
			if r != nil && r.att == "" {
				line += " (no consensus: not counted)"
			}
		}
	}
	return st, text + "\n" + line, j, nil
}

func (s *svc) hReproduce(w http.ResponseWriter, r *http.Request) {
	id, err := s.authCompute(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	wait, err := waitParam(r, maxJobWait)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	st, text, j, err := s.reproduce(r.Context(), id, r.PathValue("id"), wait)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, st, text, j)
}

func (s *svc) opJRepro(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if err := s.checkIdent(id); err != nil {
		return "", err
	}
	var in struct {
		ID   string `json:"id"`
		Wait int    `json:"wait"`
	}
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	_, text, _, err := s.reproduce(ctx, id, in.ID, clampWait(in.Wait, maxJobWait))
	return text, err
}

// --- /att/<job> page -------------------------------------------------------------------------------

// donorRow is one agreeing replica: its root, lease, donor signature and the key it verifies with.
type donorRow struct {
	root, lease   string
	dsig          []byte
	pub, pubPrev  []byte
	hasSignature  bool
	publicKeyText string // hex of the key the dsig verifies against (else the current pub, else "-")
}

// agreeingDonors lists the replicas that reported the winning fingerprint (s=, c=, o= of the att
// line), oldest report first, with the key each donor signature verifies against.
func agreeingDonors(ctx context.Context, q core.Q, j *attJob, f map[string]string) ([]donorRow, error) {
	code, _ := strconv.Atoi(f["c"])
	out := f["o"]
	if out == "-" {
		out = ""
	}
	rows, err := q.Query(ctx, `SELECT coalesce(r.worker_root, ''), coalesce(r.lease, ''), r.dsig, i.pub, i.pub_prev
		FROM replicas r LEFT JOIN identities i ON i.id = r.worker_root
		WHERE r.job = $1 AND r.state = 'reported' AND coalesce(r.status, '') = $2 AND coalesce(r.code, 0) = $3 AND coalesce(r.out, '') = $4
		ORDER BY r.reported_at, r.id LIMIT $5`, j.id, f["s"], code, out, attPageMaxRows)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ds []donorRow
	fp := f["s"] + ":" + strconv.Itoa(code) + ":" + out
	for rows.Next() {
		var d donorRow
		if err := rows.Scan(&d.root, &d.lease, &d.dsig, &d.pub, &d.pubPrev); err != nil {
			return nil, err
		}
		d.hasSignature = len(d.dsig) == ed25519.SignatureSize
		d.publicKeyText = "-"
		if len(d.pub) == ed25519.PublicKeySize {
			d.publicKeyText = hex.EncodeToString(d.pub)
		}
		if d.hasSignature {
			m := dsigMessage(j.id, d.lease, fp)
			for _, k := range [][]byte{d.pub, d.pubPrev} {
				if len(k) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(k), m, d.dsig) {
					d.publicKeyText = hex.EncodeToString(k) // a rotated donor key still verifies with pub_prev
					break
				}
			}
		}
		ds = append(ds, d)
	}
	return ds, rows.Err()
}

func (d donorRow) dsigText() string {
	if !d.hasSignature {
		return "-"
	}
	return base64.RawURLEncoding.EncodeToString(d.dsig)
}

// publicRoles names the job blobs (wasm, in, fs, out) that are world-readable right now.
func publicRoles(ctx context.Context, q core.Q, j *attJob) (string, error) {
	roles := []struct{ name, hash string }{{"wasm", j.wasm}, {"in", j.input}, {"fs", j.fs}, {"out", j.out}}
	hashes := make([]string, 0, 4)
	for _, r := range roles {
		if r.hash != "" {
			hashes = append(hashes, r.hash)
		}
	}
	pub, err := scanStrings(q.Query(ctx, `SELECT hash FROM blobs WHERE hash = ANY($1) AND public AND NOT private`, hashes))
	if err != nil {
		return "", err
	}
	set := map[string]bool{}
	for _, h := range pub {
		set[h] = true
	}
	var out []string
	for _, r := range roles {
		if r.hash != "" && set[r.hash] {
			out = append(out, r.name)
		}
	}
	if len(out) == 0 {
		return "-", nil
	}
	return strings.Join(out, ","), nil
}

// attIndexable is the one predicate (4.5) for receipt pages and the att sitemap: the submitter
// root is the author; the page carries no user text, so only standing and age matter.
func attIndexable(st trust.Standing, finished time.Time) bool {
	return trust.Indexable("att", trust.IndexInput{Author: st, Seed: st.Seed, Age: time.Since(finished)})
}

// shQ quotes s for a POSIX single-quoted shell string.
func shQ(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// jsQ renders s as a JSON string literal (valid in JavaScript and Python sources).
func jsQ(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// verifySnippets renders the offline checks of the server signature: OpenSSL (>= 1.1.1, -rawin),
// Node 20+ crypto.verify and Python with `cryptography`, each prefixing the cx-sig-v1 domain.
func verifySnippets(line, sig, pub string) (openssl, node, py string) {
	typ, _, _ := strings.Cut(line, " ")
	sig = strings.TrimPrefix(sig, "sig=")
	openssl = strings.Join([]string{
		"PUB=" + shQ(pub) + "; LINE=" + shQ(line) + "; SIG=" + shQ(sig),
		`printf '` + spkiPrefix + `%s' "$PUB" | xxd -r -p > pub.der`,
		`printf 'cx-sig-v1\0` + typ + `\0%s' "$LINE" > msg.bin`,
		b64Py + ` "$SIG" > sig.bin`,
		`openssl pkeyutl -verify -pubin -keyform DER -inkey pub.der -rawin -in msg.bin -sigfile sig.bin`,
	}, "\n")
	node = strings.Join([]string{
		`const { createPublicKey, verify } = require("node:crypto");`,
		`const pub = ` + jsQ(pub) + `, line = ` + jsQ(line) + `, sig = ` + jsQ(sig) + `;`,
		`const key = createPublicKey({ key: Buffer.concat([Buffer.from("` + spkiPrefix + `", "hex"), Buffer.from(pub, "hex")]), format: "der", type: "spki" });`,
		`console.log(verify(null, Buffer.concat([Buffer.from("cx-sig-v1\0` + typ + `\0"), Buffer.from(line)]), key, Buffer.from(sig, "base64url")));`,
	}, "\n")
	py = strings.Join([]string{
		`import base64`,
		`from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey`,
		`pub = ` + jsQ(pub),
		`line = ` + jsQ(line),
		`sig = ` + jsQ(sig),
		`msg = b"cx-sig-v1\0` + typ + `\0" + line.encode()`,
		`key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub))`,
		`key.verify(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)), msg)  # raises on mismatch`,
		`print("valid")`,
	}, "\n")
	return
}

// dsigSnippets renders the donor-signature checks (27.6): message cx-dsig-v1 || 0 || job || 0 ||
// lease || 0 || fingerprint, one donor line's pub/lease/dsig at a time.
func dsigSnippets(job, fp string) (openssl, node string) {
	openssl = strings.Join([]string{
		`# one donor line at a time: PUB=<pub> LEASE=<lease> DSIG=<dsig>`,
		`printf '` + spkiPrefix + `%s' "$PUB" | xxd -r -p > donor.der`,
		`printf 'cx-dsig-v1\0` + job + `\0%s\0` + fp + `' "$LEASE" > dmsg.bin`,
		b64Py + ` "$DSIG" > dsig.bin`,
		`openssl pkeyutl -verify -pubin -keyform DER -inkey donor.der -rawin -in dmsg.bin -sigfile dsig.bin`,
	}, "\n")
	node = strings.Join([]string{
		`const { createPublicKey, verify } = require("node:crypto");`,
		`const job = ` + jsQ(job) + `, fp = ` + jsQ(fp) + `; // per donor line: pub, lease, dsig`,
		`const key = createPublicKey({ key: Buffer.concat([Buffer.from("` + spkiPrefix + `", "hex"), Buffer.from(pub, "hex")]), format: "der", type: "spki" });`,
		`console.log(verify(null, Buffer.from("cx-dsig-v1\0" + job + "\0" + lease + "\0" + fp), key, Buffer.from(dsig, "base64url")));`,
	}, "\n")
	return
}

// attDoc builds the receipt page. JSON renditions carry the donor tuples as rows (donor, pub,
// dsig, lease) so cx verify reads them as objects; text renditions list one donor line each.
func (s *svc) attDoc(ctx context.Context, j *attJob, st trust.Standing, stOK bool, tuples bool) (*doc.Doc, error) {
	f := attFields(j.att)
	donors, err := agreeingDonors(ctx, s.d.DB, j, f)
	if err != nil {
		return nil, err
	}
	k, n, err := reproCount(ctx, s.d.DB, j.id)
	if err != nil {
		return nil, err
	}
	public, err := publicRoles(ctx, s.d.DB, j)
	if err != nil {
		return nil, err
	}
	status := j.status
	if j.reason != "" {
		status += " " + j.reason
	}
	d := &doc.Doc{
		Head:      fmt.Sprintf("att %s %s n=%s d=%s repro=%d/%d", j.id, status, f["n"], f["d"], k, n),
		Title:     "compute receipt " + j.id,
		Canonical: "/att/" + j.id,
		NoIndex:   !(stOK && attIndexable(st, j.finishedAt())),
	}
	d.Desc = fmt.Sprintf("Replication receipt of WASM job %s: %s agreeing donors, distinct=%s, %d/%d reproductions matched. Observed by agents.ekaii.fr, not a proof of execution.",
		j.id, f["n"], f["d"], k, n)
	add := func(name, val string) { d.Fields = append(d.Fields, doc.F{Name: name, Val: val}) }
	multi := func(name, val string) { d.Fields = append(d.Fields, doc.F{Name: name, Val: val, Multi: true}) }
	add("line", j.att)
	add("sig", j.sig)
	kid, _ := strconv.Atoi(f["k"])
	pub := "-"
	if s.signer != nil {
		if p, ok := s.signer.PublicOf(kid); ok {
			pub = hex.EncodeToString(p)
		}
	}
	add("kid", f["k"])
	add("pubkey", pub)
	add("key", "/.well-known/cx-key")
	by := j.root + " lvl=L?"
	if stOK {
		by = fmt.Sprintf("%s lvl=L%d", j.root, st.Level())
	}
	add("by", by)
	add("at", j.finishedAt().UTC().Format(time.RFC3339))
	if lane := f["lane"]; lane != "" {
		add("lane", lane)
	}
	add("repro", fmt.Sprintf("%d/%d", k, n))
	add("public", public)
	// The SPEC line "donor <id> pub=<hex> dsig=<b64url>" gains the lease as an appended field: the
	// donor signature covers cx-dsig-v1 || job || lease || fingerprint, so a verifier needs it.
	if tuples {
		d.Cols = []string{"donor", "pub", "dsig", "lease"}
		for _, dn := range donors {
			d.Rows = append(d.Rows, []string{dn.root, dn.publicKeyText, dn.dsigText(), dn.lease})
		}
	} else {
		for _, dn := range donors {
			add("donor", dn.root+" pub="+dn.publicKeyText+" dsig="+dn.dsigText()+" lease="+dn.lease)
		}
	}
	add("online", "GET /verify?s="+url.QueryEscape(j.att)+"&sig="+url.QueryEscape(strings.TrimPrefix(j.sig, "sig=")))
	o, nd, py := verifySnippets(j.att, j.sig, pub)
	multi("verify_openssl", o)
	multi("verify_node", nd)
	multi("verify_python", py)
	signed := false
	for _, dn := range donors {
		signed = signed || dn.hasSignature
	}
	if signed {
		out := f["o"]
		if out == "-" {
			out = ""
		}
		do, dnode := dsigSnippets(j.id, f["s"]+":"+f["c"]+":"+out)
		multi("verify_dsig_openssl", do)
		multi("verify_dsig_node", dnode)
	}
	add("note", strings.ReplaceAll(receiptNote, "<id>", j.id))
	d.Next = []doc.Action{doc.POST("/v1/j/"+j.id+"/reproduce", "same wasm+in"), doc.GET("/att/"+j.id+".json", ""),
		doc.GET("/.well-known/cx-key", "server key"), doc.GET("/att/revoked.txt", "")}
	ld := map[string]any{"@context": "https://schema.org", "@type": "DigitalDocument", "name": "compute receipt " + j.id,
		"url": doc.Base() + "/att/" + j.id, "dateCreated": j.finishedAt().UTC().Format(time.RFC3339),
		"author":  map[string]any{"@type": "Thing", "identifier": j.root, "url": doc.Base() + "/a/" + j.root},
		"license": doc.CurrentSite().License, "isAccessibleForFree": true, "description": d.Desc}
	d.LD = ld
	return d, nil
}

func (s *svc) hAttPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	jid, _ := doc.SplitSuffix(r.PathValue("job"))
	if !core.ValidIDPrefix(jid, 'j') {
		doc.Fail(w, r, core.ErrNotFound)
		return
	}
	j, err := loadAttJob(ctx, s.d.DB, jid)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if j == nil || !j.published || j.att == "" {
		doc.Fail(w, r, core.ErrNotFound) // unknown and unpublished are the same 404
		return
	}
	st, err := trust.Load(ctx, s.d.DB, j.root)
	stOK := err == nil
	if err != nil && !errors.Is(err, core.ErrNotFound) {
		doc.Fail(w, r, err)
		return
	}
	f := doc.Negotiate(r)
	d, err := s.attDoc(ctx, j, st, stOK, f == doc.JSON || f == doc.JSONLD || f == doc.Problem)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Reply(w, r, 200, d)
}

// hRevoked serves /att/revoked.txt: a header line, then whatever RevokedListFn reports.
func (s *svc) hRevoked(w http.ResponseWriter, r *http.Request) {
	lines := []string{revokedHeader}
	if RevokedListFn != nil {
		more, err := RevokedListFn(r.Context(), s.d.DB)
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		for _, l := range more {
			if l = doc.SafeLine(strings.TrimSpace(l)); l != "" {
				lines = append(lines, l)
			}
		}
	}
	doc.ServeStatic(w, r, time.Time{}, []byte(strings.Join(lines, "\n")+"\n"), "text/plain; charset=utf-8")
}

// attSitemap lists the published receipts that pass trust.Indexable (9.2).
func (s *svc) attSitemap(ctx context.Context) ([]core.SitemapURL, error) {
	rows, err := s.d.DB.Query(ctx, `SELECT id, root, finished_at FROM jobs WHERE published AND att <> '' AND lane <> 'own'
		AND finished_at < now() - interval '1 hour' ORDER BY finished_at DESC LIMIT $1`, maxSitemapAtt)
	if err != nil {
		return nil, err
	}
	type row struct {
		id, root string
		at       time.Time
	}
	var rs []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.id, &x.root, &x.at); err != nil {
			rows.Close()
			return nil, err
		}
		rs = append(rs, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	standings := map[string]*trust.Standing{}
	var out []core.SitemapURL
	for _, x := range rs {
		st, seen := standings[x.root]
		if !seen {
			if loaded, err := trust.Load(ctx, s.d.DB, x.root); err == nil {
				st = &loaded
			} else if !errors.Is(err, core.ErrNotFound) {
				return nil, err
			}
			standings[x.root] = st
		}
		if st != nil && attIndexable(*st, x.at) {
			out = append(out, core.SitemapURL{Loc: doc.Base() + "/att/" + x.id, LastMod: x.at})
		}
	}
	return out, nil
}

var openAPIAtt = json.RawMessage(`{"paths":{
"/v1/j/{id}/publish":{"post":{"operationId":"jpub","summary":"Publish a finalized job's signed att1 receipt as the public page /att/<id> (submitter; own-lane jobs stay private)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok published <id> /att/<id>"},"404":{"description":"err notfound"},"409":{"description":"err bad no attestation yet"}}}},
"/v1/j/{id}/reproduce":{"post":{"operationId":"jrepro","summary":"Re-run a published job's wasm+in (+fs, same ms/mb) as a fresh paid job of yours; ?wait<=85 reports match=0|1 and records the reproduction","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},{"name":"wait","in":"query","schema":{"type":"integer"}}],"responses":{"200":{"description":"<new id> [done …] then: repro of=<id> [match=0|1]"},"202":{"description":"queued eta=unknown (no donors online)"},"402":{"description":"err credits"},"404":{"description":"err notfound"}}}},
"/att/{job}":{"get":{"operationId":"att","summary":"Public replication receipt (HTML, .md, .json, .txt): att1 line, sig, server key, donor tuples (donor pub dsig lease), repro=k/n, verify one-liners with the cx-sig-v1 domain prefix; indexable per trust.Indexable","parameters":[{"name":"job","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"receipt page"},"404":{"description":"err notfound (unknown or unpublished)"}}}},
"/att/revoked.txt":{"get":{"operationId":"attRevoked","summary":"Results revoked by audit or banned modules: a # header then one att1 line + reason per line (kept 1 y)","responses":{"200":{"description":"text/plain"}}}},
"/admin/blob":{"put":{"operationId":"adminBlob","summary":"Admin token: store a module above the 16 MiB public cap (raw body <= ADMIN_BLOB_MAX, owner asystem, pinned_by admin, wasmscan recorded); ?name=&ver=&note= also pins it","parameters":[{"name":"name","in":"query","schema":{"type":"string","maxLength":32}},{"name":"ver","in":"query","schema":{"type":"string","maxLength":32}},{"name":"note","in":"query","schema":{"type":"string","maxLength":120}}],"requestBody":{"content":{"application/octet-stream":{"schema":{"type":"string","format":"binary"}}}},"responses":{"200":{"description":"ok blob <hash> size=<n> kind=wasm owner=asystem pinned_by=admin [pin=<name>@<ver>]"},"401":{"description":"err auth admin"},"413":{"description":"err size"}}}}
}}`)
