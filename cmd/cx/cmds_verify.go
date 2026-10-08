package main

// cmds_verify.go: `cx verify <job|/att url>` (SPEC-v2 27.6, donor-signed results). It downloads a
// published job's attestation (GET /att/<job>.json: the signed att1 line, the server signature,
// and one donor tuple per agreeing replica), fetches the wasm/in/out (and fs) blobs, re-runs the
// module in internal/sandbox locally with the same ms/mb/fs, and checks three things independently:
//   - the server signature over the att1 line, against /.well-known/cx-key (cx-sig-v1 domain);
//   - each donor signature, against the donor pub the page lists (cx-dsig-v1 domain);
//   - sha256(local stdout) == the att line's o= output hash.
// It prints `match server=valid donors=2/2 local=same` on success (or the first mismatch) and exits
// non-zero on any failure. --no-run checks the signatures only. Pulling in the sandbox grows the cx
// binary by ~3 MiB (wazero), documented in the package brief.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/sandbox"
	"ekaii.fr/commons/internal/sign"
)

// verify budget defaults: ms/mb are not part of the attestation (they do not change a deterministic
// output), so a generous ceiling is used unless the caller narrows it with --ms/--mb.
const (
	verifyDefaultMs = 30000
	verifyDefaultMb = 256
	dsigDomain      = "cx-dsig-v1\x00" // mirrors internal/compute and cmd/cxw
)

func init() {
	register("compute", "verify", cmdVerify,
		u("<job|/att url> [--ms N --mb N --no-run]",
			"reproduce a published job from its attestation and check the server + donor signatures"))
}

// cmdVerify is `cx verify`.
func cmdVerify(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx verify <job|/att url> [--ms N --mb N --no-run]"
	var msStr, mbStr string
	var noRun bool
	pos, err := parseArgs(args, map[string]*string{"ms": &msStr, "mb": &mbStr}, map[string]*bool{"no-run": &noRun})
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fail(2, use)
	}
	base, job, err := attTarget(pos[0])
	if err != nil {
		return err
	}
	ms, err := atoiFlag("ms", msStr)
	if err != nil {
		return err
	}
	mb, err := atoiFlag("mb", mbStr)
	if err != nil {
		return err
	}
	if ms <= 0 {
		ms = verifyDefaultMs
	}
	if mb <= 0 {
		mb = verifyDefaultMb
	}
	// A /att URL points at its own host: aim every request there for this command.
	if base != "" {
		old := c.url
		c.url = base
		defer func() { c.url = old }()
	}

	att, err := c.fetchAtt(ctx, job)
	if err != nil {
		return err
	}
	f := parseAttLine(att.Line)
	if f["w"] == "" || f["o"] == "" {
		return fail(1, "err proto att line missing w=/o= (%q)", att.Line)
	}

	serverValid, err := c.checkServerSig(ctx, att.Line, att.Sig)
	if err != nil {
		return err
	}
	okDonors, nDonors := checkDonors(job, f, att.Rows)

	localState := "" // empty = not run (--no-run)
	localSame := true
	if !noRun {
		same, err := c.reproduce(ctx, f, ms, mb)
		if err != nil {
			return err
		}
		localSame = same
		localState = "differ"
		if same {
			localState = "same"
		}
	}

	line := fmt.Sprintf("server=%s donors=%d/%d", valid(serverValid), okDonors, nDonors)
	if localState != "" {
		line += " local=" + localState
	}
	ok := serverValid && okDonors == nDonors && (noRun || localSame)
	verdict := "match"
	if !ok {
		verdict = "mismatch"
	}
	c.print([]byte(verdict + " " + line))
	if !ok {
		return &exitErr{code: 3}
	}
	return nil
}

func valid(ok bool) string {
	if ok {
		return "valid"
	}
	return "invalid"
}

// attReply is the subset of GET /att/<job>.json cx verify reads (14.2, 27.6): the signed att1
// line, the server signature, and the agreeing-donor tuples as objects (donor, pub, dsig, lease).
type attReply struct {
	Line string     `json:"line"`
	Sig  string     `json:"sig"`
	Rows []donorRow `json:"rows"`
}

type donorRow struct {
	Donor string `json:"donor"`
	Pub   string `json:"pub"`
	Dsig  string `json:"dsig"`
	Lease string `json:"lease"`
}

func (c *cli) fetchAtt(ctx context.Context, job string) (*attReply, error) {
	var att attReply
	if err := c.getJSON(ctx, "GET", "/att/"+job+".json", nil, &att); err != nil {
		return nil, err
	}
	if att.Line == "" || att.Sig == "" {
		return nil, fail(1, "err proto att page carried no line/sig")
	}
	return &att, nil
}

// attTarget resolves the argument into an optional base URL and the job id, accepting a bare id, an
// `/att/<job>` path, or a full `https://host/att/<job>(.json)` URL.
func attTarget(arg string) (base, job string, err error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", "", fail(2, "err bad empty job")
	}
	if strings.Contains(arg, "://") {
		u, e := url.Parse(arg)
		if e != nil || u.Host == "" {
			return "", "", fail(2, "err bad url %q", arg)
		}
		base = strings.TrimRight(u.Scheme+"://"+u.Host, "/")
		job = path.Base(u.Path)
	} else {
		job = arg
		if i := strings.LastIndexByte(job, '/'); i >= 0 {
			job = job[i+1:]
		}
	}
	job = strings.TrimSuffix(strings.TrimSuffix(job, ".json"), ".md")
	if job == "" || job[0] != 'j' {
		return "", "", fail(2, "err bad job id %q", job)
	}
	return base, job, nil
}

// parseAttLine splits a canonical statement line ("att1 k=v k=v …") into its k=v fields.
func parseAttLine(line string) map[string]string {
	f := map[string]string{}
	toks := strings.Fields(line)
	for _, tok := range toks[min(1, len(toks)):] {
		if k, v, ok := strings.Cut(tok, "="); ok {
			f[k] = v
		}
	}
	return f
}

// checkServerSig verifies the att1 line's server signature against /.well-known/cx-key under the
// cx-sig-v1 domain, trying the current key and every published previous key.
func (c *cli) checkServerSig(ctx context.Context, line, sig string) (bool, error) {
	typ, _, _ := strings.Cut(line, " ")
	if !sign.ValidType(typ) {
		return false, fail(1, "err proto att line has no statement type")
	}
	raw, err := sign.DecodeSig(sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return false, nil
	}
	var wk struct {
		Pub  string `json:"pub"`
		Prev []struct {
			Pub string `json:"pub"`
		} `json:"prev"`
	}
	if err := c.getJSON(ctx, "GET", "/.well-known/cx-key", nil, &wk); err != nil {
		return false, err
	}
	msg := sign.Message(typ, line)
	keys := []string{wk.Pub}
	for _, p := range wk.Prev {
		keys = append(keys, p.Pub)
	}
	for _, k := range keys {
		pub, err := hex.DecodeString(strings.TrimSpace(k))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), msg, raw) {
			return true, nil
		}
	}
	return false, nil
}

// checkDonors verifies each listed donor signature against the pub the page lists, under the
// cx-dsig-v1 domain over the job's fingerprint (status:code:out); returns (valid, total).
func checkDonors(job string, f map[string]string, rows []donorRow) (ok, total int) {
	fp := fingerprintOf(f)
	for _, r := range rows {
		total++
		pub, perr := hex.DecodeString(strings.TrimSpace(r.Pub))
		dsig, derr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(r.Dsig))
		if perr != nil || derr != nil || len(pub) != ed25519.PublicKeySize || len(dsig) != ed25519.SignatureSize {
			continue
		}
		msg := []byte(dsigDomain + job + "\x00" + r.Lease + "\x00" + fp)
		if ed25519.Verify(ed25519.PublicKey(pub), msg, dsig) {
			ok++
		}
	}
	return ok, total
}

// fingerprintOf rebuilds the replica fingerprint `status:code:out` from the att line, exactly as
// the gateway signs it: o="-" means no output.
func fingerprintOf(f map[string]string) string {
	code, _ := strconv.Atoi(f["c"])
	out := f["o"]
	if out == "-" {
		out = ""
	}
	return f["s"] + ":" + strconv.Itoa(code) + ":" + out
}

// reproduce re-runs the job's module locally with the same input, fs and limits, then compares
// sha256(stdout) with the att line's o=. The sandbox parses and mounts the fs zip read-only (27.6).
func (c *cli) reproduce(ctx context.Context, f map[string]string, ms, mb int) (bool, error) {
	wasm, err := c.getBlob(ctx, f["w"])
	if err != nil {
		return false, err
	}
	in, err := c.getBlob(ctx, f["i"])
	if err != nil {
		return false, err
	}
	opts := sandbox.Options{MaxWasm: max(sandbox.MaxWasm, len(wasm))} // honour a pinned module's size
	if fs := f["f"]; fs != "" {
		blob, err := c.getBlob(ctx, fs)
		if err != nil {
			return false, err
		}
		opts.FS = blob
	}
	r, err := sandbox.New("", 2)
	if err != nil {
		return false, fail(1, "err sandbox %v", err)
	}
	defer r.Close(ctx)
	res := r.RunOpts(ctx, wasm, in, ms, mb, opts)
	local := "-"
	if res.Status == sandbox.StatusOK || res.Status == sandbox.StatusExit {
		local = sha256hex(res.Out)
	}
	return local == f["o"], nil
}
