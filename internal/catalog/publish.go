package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
	"ekaii.fr/commons/internal/wasmscan"
)

// publishIn is the body of POST /v1/svc, POST /admin/svc and op svp.
type publishIn struct {
	Name     string          `json:"name"`
	Ver      int             `json:"ver,omitempty"`
	Wasm     string          `json:"wasm"`
	Manifest json.RawMessage `json:"manifest"`
}

// publishOpts selects the path: system publishes under core.SystemID with reserved names
// allowed, no level or cap checks and KATs as system jobs (operator and seed paths).
type publishOpts struct {
	system  bool
	pinSeed bool // SeedSystem: a module above 4 MiB is inserted into pins (note 'seed') in the tx
}

// errPinRequest marks a publish that recorded a pin request instead (15.2).
var errPinRequest = errors.New("pin request recorded")

// pinRequest is what the handler reports after errPinRequest.
type pinRequest struct {
	name, hash string
	size       int64
}

// --- manifest -----------------------------------------------------------------------------------

// parseManifest validates and normalises a manifest (15.1, 27.6): size, field shapes, caps, scrub
// (tier 1 rejects, tier 2 masks), lexicon score/flags and hazards on the user-text fields. The
// returned raw form is the canonical JSON stored in service_versions.manifest.
func parseManifest(raw json.RawMessage) (m Manifest, canon json.RawMessage, lexicon int, flags, hazard []string, err error) {
	if len(raw) == 0 || string(raw) == "null" {
		return m, nil, 0, nil, nil, core.Bad("manifest required")
	}
	if len(raw) > maxManifest {
		return m, nil, 0, nil, nil, core.E(413, "size", "manifest over 4 KiB")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, nil, 0, nil, nil, core.Bad("manifest: " + truncate(err.Error(), 120))
	}
	bad := func(msg string) (Manifest, json.RawMessage, int, []string, []string, error) {
		return m, nil, 0, nil, nil, core.Bad("manifest: " + msg)
	}
	switch m.ABI {
	case "":
		m.ABI = "text"
	case "json", "raw", "text":
	default:
		return bad("abi must be json, raw or text")
	}
	m.Desc, m.Usage = scrub.Normalize(strings.TrimSpace(m.Desc)), scrub.Normalize(strings.TrimSpace(m.Usage))
	if !doc.OneLine(m.Desc) || len(m.Desc) > maxDesc {
		return bad(fmt.Sprintf("desc must be one line <= %d bytes", maxDesc))
	}
	m.Usage = doc.CleanMulti(m.Usage)
	if len(m.Usage) > maxUsage {
		return bad(fmt.Sprintf("usage <= %d bytes", maxUsage))
	}
	for _, f := range []struct {
		name string
		v    *string
	}{{"in", &m.In}, {"out", &m.Out}} {
		*f.v = strings.TrimSpace(*f.v)
		if !doc.OneLine(*f.v) || len(*f.v) > maxLine {
			return bad(f.name + " must be one line <= 200 bytes")
		}
	}
	if len(m.Examples) > maxExamples {
		return bad("examples <= 3")
	}
	for i := range m.Examples {
		e := &m.Examples[i]
		e.In, e.Out = doc.CleanMulti(e.In), doc.CleanMulti(e.Out)
		if len(e.In) > maxExample || len(e.Out) > maxExample {
			return bad("example sides <= 1 KiB")
		}
	}
	if m.MsHint < 0 || m.MsHint > maxMs || m.MbHint < 0 || m.MbHint > maxMb {
		return bad(fmt.Sprintf("ms_hint 1..%d, mb_hint 1..%d", maxMs, maxMb))
	}
	if m.Fee < 0 || m.Fee > maxFee {
		return bad("fee 0..2")
	}
	if len(m.Tests) == 0 || len(m.Tests) > maxTests {
		return bad(fmt.Sprintf("1..%d tests", maxTests))
	}
	for i, t := range m.Tests {
		switch {
		case t.In != "" && t.InText != "":
			return bad(fmt.Sprintf("test %d: in or in_text, not both", i+1))
		case t.In != "" && !hashRe.MatchString(t.In):
			return bad(fmt.Sprintf("test %d: in must be a sha256 hex", i+1))
		case t.In == "" && t.InText == "":
			return bad(fmt.Sprintf("test %d: in or in_text required", i+1))
		case !hashRe.MatchString(t.OutSHA256):
			return bad(fmt.Sprintf("test %d: out_sha256 must be a sha256 hex", i+1))
		}
	}
	if m.FS != "" && !hashRe.MatchString(m.FS) {
		return bad("fs must be a sha256 hex")
	}
	if len(m.InputSchema) > 0 {
		var buf bytes.Buffer
		if err := json.Compact(&buf, m.InputSchema); err != nil {
			return bad("input_schema: " + truncate(err.Error(), 80))
		}
		if buf.Len() > maxManifest {
			return bad("input_schema over 4 KiB")
		}
		if err := validateSchema(buf.Bytes()); err != nil {
			return bad("input_schema: " + err.Error())
		}
		m.InputSchema = buf.Bytes()
	}
	fields := map[string]*string{"desc": &m.Desc, "usage": &m.Usage}
	for i := range m.Examples {
		fields["examples."+strconv.Itoa(i)+".in"] = &m.Examples[i].In
		fields["examples."+strconv.Itoa(i)+".out"] = &m.Examples[i].Out
	}
	if _, serr := scrub.RejectOrMask(fields); serr != nil {
		return m, nil, 0, nil, nil, serr
	}
	var text strings.Builder
	text.WriteString(m.Desc + "\n" + m.Usage + "\n")
	for _, e := range m.Examples {
		text.WriteString(e.In + "\n" + e.Out + "\n")
	}
	lexicon, flags, _ = scrub.Flags(text.String())
	hazard = scrub.Hazards(text.String())
	canon, err = json.Marshal(m)
	if err != nil {
		return m, nil, 0, nil, nil, err
	}
	if len(canon) > maxManifest {
		return m, nil, 0, nil, nil, core.E(413, "size", "manifest over 4 KiB")
	}
	return m, canon, lexicon, flags, hazard, nil
}

// validateSchema checks the shape of a JSON Schema object (27.7 input_schema): an object whose
// type (if any) is "object", whose properties are objects and whose required names exist.
func validateSchema(raw []byte) error {
	var sch map[string]json.RawMessage
	if err := json.Unmarshal(raw, &sch); err != nil || sch == nil {
		return errors.New("must be a JSON object")
	}
	if t, ok := sch["type"]; ok {
		var typ string
		if json.Unmarshal(t, &typ) != nil || typ != "object" {
			return errors.New("type must be \"object\"")
		}
	}
	props := map[string]json.RawMessage{}
	if p, ok := sch["properties"]; ok {
		if json.Unmarshal(p, &props) != nil || props == nil {
			return errors.New("properties must be an object")
		}
		for name, v := range props {
			var o map[string]json.RawMessage
			if json.Unmarshal(v, &o) != nil || o == nil {
				return errors.New("property " + doc.SafeLine(truncate(name, 40)) + " must be an object")
			}
		}
	}
	if r, ok := sch["required"]; ok {
		var req []string
		if json.Unmarshal(r, &req) != nil {
			return errors.New("required must be an array of names")
		}
		for _, n := range req {
			if _, ok := props[n]; !ok && len(props) > 0 {
				return errors.New("required name " + doc.SafeLine(truncate(n, 40)) + " not in properties")
			}
		}
	}
	return nil
}

// --- blobs --------------------------------------------------------------------------------------

type blobInfo struct {
	hash, owner, kind, pinnedBy string
	size                        int64
	private                     bool
}

func loadBlob(ctx context.Context, q core.Q, hash string) (*blobInfo, error) {
	b := &blobInfo{hash: hash}
	err := q.QueryRow(ctx, `SELECT size, owner_root, kind, pinned_by, private FROM blobs WHERE hash = $1`, hash).
		Scan(&b.size, &b.owner, &b.kind, &b.pinnedBy, &b.private)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return b, err
}

type moduleMeta struct {
	kind, badImport, banned, parseErr, fsUnusable string
	importCount                                   int
	minPages                                      int64
	memory64, hasStart, truncated, found          bool
	secretKinds                                   []string
}

func loadMeta(ctx context.Context, q core.Q, hash string) (*moduleMeta, error) {
	m := &moduleMeta{found: true}
	err := q.QueryRow(ctx, `SELECT kind, import_count, bad_import, min_pages, memory64, has_start, truncated, banned, parse_err, fs_unusable, secret_kinds
		FROM blob_meta WHERE hash = $1`, hash).
		Scan(&m.kind, &m.importCount, &m.badImport, &m.minPages, &m.memory64, &m.hasStart, &m.truncated, &m.banned, &m.parseErr, &m.fsUnusable, &m.secretKinds)
	if errors.Is(err, pgx.ErrNoRows) {
		return &moduleMeta{}, nil
	}
	return m, err
}

// checkModule applies the publish rules to the wasm blob (15.2, 27.6): owned by the publisher
// (any owner on the operator path), a parsed module, not banned, no secret in its data segments,
// and wasmscan's submit rules for mb. Rows without blob_meta (v1 uploads) are scanned from disk.
func (s *svc) checkModule(ctx context.Context, q core.Q, root, hash string, mb int, system bool) (*blobInfo, error) {
	if !hashRe.MatchString(hash) {
		return nil, core.Bad("wasm must be a sha256 hex")
	}
	b, err := loadBlob(ctx, q, hash)
	if err != nil {
		return nil, err
	}
	if b == nil || b.private || (!system && b.owner != root) {
		return nil, core.E(404, "notfound", "wasm blob "+hash[:12])
	}
	if b.kind != "wasm" {
		return nil, core.Bad("not a wasm module (no \\0asm magic)")
	}
	m, err := loadMeta(ctx, q, hash)
	if err != nil {
		return nil, err
	}
	var info wasmscan.Info
	switch {
	case m.found:
		switch {
		case m.banned != "":
			return nil, core.Bad("module " + m.banned)
		case m.parseErr != "":
			return nil, core.Bad("module " + strings.TrimPrefix(m.parseErr, "wasm: "))
		case len(m.secretKinds) > 0:
			return nil, core.E(400, "scrub", "module data segment "+strings.Join(m.secretKinds, ","))
		}
		info = wasmscan.Info{Size: int(b.size), ImportCount: m.importCount, BadImport: m.badImport, MinPages: uint32(min(m.minPages, 1<<32-1)),
			Memory64: m.memory64, HasStart: m.hasStart, Truncated: m.truncated}
	default:
		body, err := os.ReadFile(filepath.Join(s.d.Cfg.DataDir, "blobs", hash[:2], hash))
		if err != nil {
			return nil, core.E(404, "notfound", "wasm blob "+hash[:12])
		}
		if info, err = wasmscan.Parse(body, 0); err != nil {
			return nil, core.Bad("module " + strings.TrimPrefix(err.Error(), "wasm: "))
		}
	}
	if mb == 0 {
		mb = defMb
	}
	if err := info.Check(mb); err != nil {
		var we *wasmscan.Error
		if errors.As(err, &we) {
			return nil, core.E(we.Status, we.Code, we.Msg)
		}
		return nil, core.Bad(err.Error())
	}
	return b, nil
}

// checkFS validates a manifest fs blob: a usable zip owned by the publisher.
func checkFS(ctx context.Context, q core.Q, root, hash string, system bool) error {
	b, err := loadBlob(ctx, q, hash)
	if err != nil {
		return err
	}
	if b == nil || b.private || (!system && b.owner != root) {
		return core.E(404, "notfound", "fs blob "+hash[:12])
	}
	m, err := loadMeta(ctx, q, hash)
	if err != nil {
		return err
	}
	switch {
	case !m.found || m.kind != "zip":
		return core.Bad("fs must be a zip blob")
	case m.fsUnusable != "":
		return core.Bad("fs " + m.fsUnusable)
	}
	return nil
}

func pinned(ctx context.Context, q core.Q, hash string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pins WHERE hash = $1)`, hash).Scan(&ok)
	return ok, err
}

// katCost is the credit reservation the KATs of a manifest need (compute's 3 per second).
func katCost(m *Manifest) int64 {
	ms := m.MsHint
	if ms == 0 {
		ms = defMs
	}
	return int64(len(m.Tests)) * int64((ms+999)/1000) * 3
}

// --- publish ------------------------------------------------------------------------------------

// publish is the shared path of POST /v1/svc, svp, POST /admin/svc and SeedSystem: validation,
// name rules, caps, the rows (service, version, pins) in one tx, then the KATs. A module above
// 4 MiB without a pin records a pin request for L2 roots (errPinRequest) or answers err quota.
func (s *svc) publish(ctx context.Context, id *core.Ident, in publishIn, o publishOpts) (*Version, *pinRequest, error) {
	name := strings.TrimSpace(in.Name)
	if err := checkName(name, o.system); err != nil {
		return nil, nil, err
	}
	m, canon, lexicon, flags, hazard, err := parseManifest(in.Manifest)
	if err != nil {
		return nil, nil, err
	}
	root := id.Root
	var st trust.Standing
	if !o.system {
		if core.Level(ctx, s.d.DB, root) < 1 {
			return nil, nil, core.E(403, "auth", "publishing needs L1 (a root 24 h old with rep >= 1 or a vouch)")
		}
		if st, err = trust.Load(ctx, s.d.DB, root); err != nil {
			if errors.Is(err, core.ErrNotFound) {
				return nil, nil, core.ErrBadToken
			}
			return nil, nil, err
		}
	}
	wasm, err := s.checkModule(ctx, s.d.DB, root, in.Wasm, m.MbHint, o.system)
	if err != nil {
		return nil, nil, err
	}
	if wasm.size > unpinnedWasm && !o.pinSeed {
		ok, err := pinned(ctx, s.d.DB, wasm.hash)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			if o.system {
				return nil, nil, core.Bad("module over 4 MiB: pin it first (POST /admin/pin)")
			}
			pin, err := s.requestPin(ctx, st, name, wasm)
			return nil, pin, err
		}
	}
	if m.FS != "" {
		if err := checkFS(ctx, s.d.DB, root, m.FS, o.system); err != nil {
			return nil, nil, err
		}
	}
	if !o.system && id.Credits < katCost(&m) {
		return nil, nil, core.E(402, "credits", fmt.Sprintf("need %d credits for %d tests", katCost(&m), len(m.Tests)))
	}
	ip, _, _ := core.ClientFrom(ctx)
	var v *Version
	created := false
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var owner string
		var stable int
		err := tx.QueryRow(ctx, `SELECT owner_root, stable_ver FROM services WHERE name = $1 FOR UPDATE`, name).Scan(&owner, &stable)
		exists := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if exists && owner != root {
			return core.E(409, "taken", "name owned by another root")
		}
		if !exists {
			near, err := nearLiveName(ctx, tx, name)
			if err != nil {
				return err
			}
			if near != "" {
				return core.E(409, "taken", "name too close to "+near)
			}
			if !o.system {
				var n int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM services WHERE owner_root = $1`, root).Scan(&n); err != nil {
					return err
				}
				if n >= trust.Cap("services", st.CapLevel()) {
					return core.E(429, "quota", "service names")
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO services (name, owner_root, "desc", usage) VALUES ($1, $2, $3, $4)`, name, root, m.Desc, m.Usage); err != nil {
				return err
			}
			created = true
		} else if _, err := tx.Exec(ctx, `UPDATE services SET "desc" = $2, usage = $3 WHERE name = $1`, name, m.Desc, m.Usage); err != nil {
			return err
		}
		if !o.system {
			if err := trust.UseCap(ctx, tx, st, "service_versions"); err != nil {
				return err
			}
		}
		var maxVer int
		var dup int
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(ver), 0), coalesce((SELECT ver FROM service_versions WHERE name = $1 AND wasm = $2), 0)
			FROM service_versions WHERE name = $1`, name, wasm.hash).Scan(&maxVer, &dup); err != nil {
			return err
		}
		if dup > 0 {
			return core.E(409, "dup", fmt.Sprintf("%s@%d has the same module", name, dup))
		}
		ver := in.Ver
		switch {
		case ver == 0:
			ver = maxVer + 1
		case ver <= maxVer:
			return core.Bad("ver must be > " + strconv.Itoa(maxVer))
		}
		if _, err := tx.Exec(ctx, `INSERT INTO service_versions (name, ver, wasm, size, fs, manifest, lexicon, flags, hazard, tested)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, name, ver, wasm.hash, wasm.size, m.FS, canon, lexicon, strOrEmpty(flags), strOrEmpty(hazard),
			fmt.Sprintf("%d tests queued", len(m.Tests))); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE blobs SET pinned_by = 'svc', last_ref = now(), used_at = coalesce(used_at, now()) WHERE hash IN ($1, $2) AND pinned_by = ''`, wasm.hash, m.FS); err != nil {
			return err
		}
		if o.pinSeed && wasm.size > unpinnedWasm {
			if _, err := tx.Exec(ctx, `INSERT INTO pins (hash, name, ver, size, note) VALUES ($1, $2, $3, $4, 'seed') ON CONFLICT (hash) DO NOTHING`,
				wasm.hash, name, strconv.Itoa(ver), wasm.size); err != nil {
				return err
			}
		}
		if o.system && stable == 0 {
			if _, err := tx.Exec(ctx, `UPDATE services SET stable_ver = $2, stable_at = now() WHERE name = $1`, name, ver); err != nil {
				return err
			}
		}
		ref := name + "@" + strconv.Itoa(ver)
		if err := core.Origin(ctx, tx, "svc", ref, root, id.ID, ip); err != nil {
			return err
		}
		if err := core.Event(ctx, tx, "svc", ref, "", "service "+ref+" published by "+root); err != nil {
			return err
		}
		v, err = loadVersion(ctx, tx, name, ver)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	ids, err := s.submitKATs(ctx, v)
	if err != nil {
		if errors.Is(err, compute.ErrUnfunded) {
			s.d.DB.Exec(ctx, `UPDATE service_versions SET tested = 'tests unfunded: POST /admin/credits {id:"asystem"}' WHERE name = $1 AND ver = $2`, v.Name, v.Ver)
			return v, nil, nil
		}
		s.compensate(ctx, v, created)
		return nil, nil, err
	}
	if _, err := s.d.DB.Exec(ctx, `UPDATE service_versions SET kat_jobs = $3 WHERE name = $1 AND ver = $2`, v.Name, v.Ver, ids); err != nil {
		return nil, nil, err
	}
	v.KatJobs = ids
	return v, nil, nil
}

// submitKATs queues every test of a version (publisher-funded; system jobs for the system root).
func (s *svc) submitKATs(ctx context.Context, v *Version) ([]string, error) {
	specs := make([]compute.Spec, 0, len(v.Manifest.Tests))
	for _, t := range v.Manifest.Tests {
		sp := compute.Spec{Wasm: v.Wasm, In: t.In, InText: t.InText, FS: v.FS, Ms: v.Manifest.MsHint, Mb: v.Manifest.MbHint, Svc: v.Ref(), Kind: "kat"}
		if sp.Ms == 0 {
			sp.Ms = defMs
		}
		if sp.Mb == 0 {
			sp.Mb = defMb
		}
		specs = append(specs, sp)
	}
	if v.OwnerRoot == core.SystemID {
		return compute.SystemSubmit(ctx, s.d, specs, "kat")
	}
	return compute.Submit(ctx, s.d, &core.Ident{ID: v.OwnerRoot, Root: v.OwnerRoot, Created: v.ServiceCreated}, specs)
}

// compensate removes a version whose KATs could not be queued (the publish is reported failed).
func (s *svc) compensate(ctx context.Context, v *Version, created bool) {
	core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM service_versions WHERE name = $1 AND ver = $2`, v.Name, v.Ver); err != nil {
			return err
		}
		if created {
			if _, err := tx.Exec(ctx, `DELETE FROM services WHERE name = $1`, v.Name); err != nil {
				return err
			}
		}
		return unpinVersions(ctx, tx, []string{v.Wasm, v.FS})
	})
}

// requestPin records a pin request for a module above 4 MiB: L2+ roots, one per week per root,
// delivered to the operator inbox as an ops event; everyone else gets err quota.
func (s *svc) requestPin(ctx context.Context, st trust.Standing, name string, b *blobInfo) (*pinRequest, error) {
	if st.Level() < 2 {
		return nil, core.E(429, "quota", "pin request")
	}
	var n int
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FROM service_pin_requests WHERE root = $1 AND created > now() - interval '7 days'`, st.Root).Scan(&n); err != nil {
		return nil, err
	}
	if n >= trust.Cap("pins", st.CapLevel()) {
		return nil, core.E(429, "quota", "pin request")
	}
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO service_pin_requests (root, name, hash, size) VALUES ($1, $2, $3, $4)`, st.Root, name, b.hash, b.size); err != nil {
			return err
		}
		return core.Event(ctx, tx, "ops", "pin:"+b.hash, "", fmt.Sprintf("pin request %s %s size=%d by %s", name, b.hash[:12], b.size, st.Root))
	})
	if err != nil {
		return nil, err
	}
	return &pinRequest{name: name, hash: b.hash, size: b.size}, errPinRequest
}

func strOrEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// publishReply renders the publish outcome (15.2: `ok name@ver pending`).
func publishReply(v *Version) (string, map[string]any, []doc.Action) {
	line := fmt.Sprintf("ok %s %s", v.Ref(), v.State)
	if len(v.KatJobs) > 0 {
		line += fmt.Sprintf(" kats=%d", len(v.KatJobs))
	} else if v.Tested != "" {
		line += " " + doc.SafeLine(v.Tested)
	}
	j := map[string]any{"ok": true, "name": v.Name, "ver": v.Ver, "state": v.State, "wasm": v.Wasm, "kats": v.KatJobs}
	next := doc.Next(doc.GET("/v1/svc/"+v.Ref(), "status"), doc.GET("/svc/"+v.Name, "page"), doc.POST("/v1/svc/"+v.Ref(), `{"in_text":"…"}`))
	return line, j, next
}

func pinReply(p *pinRequest) (string, map[string]any) {
	return fmt.Sprintf("pin requested %s %s size=%d (operator review; publish again once pinned)", p.name, p.hash[:12], p.size),
		map[string]any{"pin_requested": true, "name": p.name, "wasm": p.hash, "size": p.size}
}

func (s *svc) hPublish(w http.ResponseWriter, r *http.Request) {
	id, err := s.authWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in publishIn
	if err := core.Decode(w, r, 64<<10, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	v, pin, err := s.publish(r.Context(), id, in, publishOpts{})
	if errors.Is(err, errPinRequest) {
		line, j := pinReply(pin)
		d := &doc.Doc{Head: line, Next: doc.Next(doc.GET("/v1/pins", ""), doc.GET("/v1/me", ""))}
		if core.WantJSON(r) {
			core.JSON(w, 202, j)
			return
		}
		doc.Reply(w, r, 202, d)
		return
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	line, j, next := publishReply(v)
	if core.WantJSON(r) {
		j["next"] = nextJSON(next)
		core.JSON(w, 201, j)
		return
	}
	doc.TailStatus(w, r, 201, line, next...)
}

func (s *svc) opPublish(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if err := s.checkIdent(id); err != nil {
		return "", err
	}
	var in publishIn
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	v, pin, err := s.publish(ctx, id, in, publishOpts{})
	if errors.Is(err, errPinRequest) {
		line, _ := pinReply(pin)
		return line, nil
	}
	if err != nil {
		return "", err
	}
	line, _, _ := publishReply(v)
	return line, nil
}

func nextJSON(acts []doc.Action) []string {
	out := make([]string, 0, len(acts))
	for _, a := range acts {
		out = append(out, a.String())
	}
	return out
}

// --- stable pointer -----------------------------------------------------------------------------

// setStable moves the stable pointer (15.2, 27.6): owner only, once per hour, to a verified
// version that is 24 h old or was called by >= 3 other roots; logged.
func (s *svc) setStable(ctx context.Context, id *core.Ident, name string, ver int) (*Version, error) {
	if !nameRe.MatchString(name) {
		return nil, notPublished(name)
	}
	if ver <= 0 {
		return nil, core.Bad("ver must be a positive integer")
	}
	var v *Version
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		sv, err := scanService(tx.QueryRow(ctx, `SELECT `+serviceCols+` FROM services WHERE name = $1 FOR UPDATE`, name))
		if err != nil {
			return err
		}
		if sv == nil || (sv.Hidden && sv.OwnerRoot != id.Root) {
			return notPublished(name)
		}
		if sv.OwnerRoot != id.Root {
			return core.E(403, "auth", "owner only")
		}
		if sv.StableAt != nil && time.Since(*sv.StableAt) < time.Hour && sv.StableVer != 0 {
			return core.E(429, "rate", "stable pointer moves once per hour")
		}
		if v, err = loadVersion(ctx, tx, name, ver); err != nil {
			return err
		}
		if v == nil {
			return core.E(404, "notfound", fmt.Sprintf("%s@%d", name, ver))
		}
		if v.State != "verified" {
			return core.E(409, "bad", fmt.Sprintf("%s is %s: stable needs a verified version", v.Ref(), v.State))
		}
		var others int
		if err := tx.QueryRow(ctx, `SELECT count(DISTINCT root) FROM service_calls WHERE name = $1 AND ver = $2 AND root <> $3`, name, ver, sv.OwnerRoot).Scan(&others); err != nil {
			return err
		}
		if time.Since(v.Created) < stableAgeH*time.Hour && others < stableCalls {
			return core.E(409, "bad", fmt.Sprintf("%s must be %d h old or called by %d other roots (age %dh, roots %d)", v.Ref(), stableAgeH, stableCalls, int(time.Since(v.Created).Hours()), others))
		}
		if _, err := tx.Exec(ctx, `UPDATE services SET stable_ver = $2, stable_at = now() WHERE name = $1`, name, ver); err != nil {
			return err
		}
		v.StableVer = ver
		if err := core.Audit(ctx, tx, id.ID, "svc.stable", v.Ref(), ver); err != nil {
			return err
		}
		return core.Event(ctx, tx, "svc", v.Ref(), "", "service "+name+" stable -> "+strconv.Itoa(ver))
	})
	return v, err
}

func (s *svc) hStable(w http.ResponseWriter, r *http.Request) {
	id, err := s.authWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		Ver int `json:"ver"`
	}
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	v, err := s.setStable(r.Context(), id, r.PathValue("name"), in.Ver)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	line := fmt.Sprintf("ok %s stable=%d", v.Name, v.Ver)
	if core.WantJSON(r) {
		core.JSON(w, 200, map[string]any{"ok": true, "name": v.Name, "stable": v.Ver})
		return
	}
	doc.Tail(w, r, line, doc.GET("/v1/svc/"+v.Name, ""), doc.GET("/svc/"+v.Name, ""))
}
