package core

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/pow"
)

const (
	challengeTTL  = 10 * time.Minute
	regPerIP      = 5 // registrations per IP group per day at the 100-credit tier (3.2)
	regTier2      = 10
	regPerSuper   = 4 * regPerIP // hard daily cap per super-group
	regHostingCap = 50           // soft per-group ceiling for hosting ASNs
	regASNDaily   = 200          // per hosting ASN per day (27.8)
	MaxRegBits    = 30
	maxSubkeyTTLh = 720
	defSubkeyTTLh = 168
	urlTTLh       = 2160 // url-class tokens: 90 d default and maximum (27.2)
	registerBody  = 20 << 10
)

// Date formats a time as YYYY-MM-DD, or "never" for zero.
func Date(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02")
}

func (d *Deps) regPerHour() int {
	if d.Cfg.RegPerHour > 0 {
		return d.Cfg.RegPerHour
	}
	return DefaultRegPerHour
}

// regBitsFor is the registration curve (3.1): base + floor(group regs in 24 h / 4), +2 under
// global pressure (hourly registrations above a third of REG_PER_HOUR: 100 at the default 300),
// +2 more above two thirds, capped at MaxRegBits.
func regBitsFor(base, groupDay, hour, perHour int) int {
	bits := base + groupDay/4
	if hour > perHour/3 {
		bits += 2
	}
	if hour > 2*perHour/3 {
		bits += 2
	}
	if bits > MaxRegBits {
		bits = MaxRegBits
	}
	return bits
}

// RegBits is the adaptive registration difficulty an IP group is asked for right now.
func (d *Deps) RegBits(ctx context.Context, group string) (int, error) {
	var n, hour int
	if err := d.DB.QueryRow(ctx, `SELECT count(*) FILTER (WHERE ip = $1), count(*) FILTER (WHERE at > now() - interval '1 hour')
		FROM reg_ips WHERE at > now() - interval '24 hours'`, group).Scan(&n, &hour); err != nil {
		return 0, err
	}
	return regBitsFor(d.Cfg.PowBits, n, hour, d.regPerHour()), nil
}

// hChallenge serves GET|POST /v1/challenge?for=reg|w (3.1): stateless HMAC challenges whose bits
// and purpose are authenticated inside the challenge; never cached.
func (d *Deps) hChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()
	exp := time.Now().Add(challengeTTL).Truncate(time.Second)
	switch p := r.URL.Query().Get("for"); p {
	case "", "reg":
		if !d.CheckFrozen(w, r, "reg") {
			return
		}
		bits, err := d.RegBits(ctx, d.IPGroup(r))
		if err != nil {
			Fail(w, r, err)
			return
		}
		c := pow.New(d.Cfg.ServerSecret, exp, bits, pow.PurposeReg)
		text := fmt.Sprintf("c=%s bits=%d exp=%d for=reg", c, bits, exp.Unix())
		j := map[string]any{"c": c, "bits": bits, "exp": exp.Unix(), "for": "reg"}
		if id := ChallengeID(ctx, c); id != "" {
			text += " id=" + id
			j["id"] = id
		}
		OK(w, r, text, j)
	case "w":
		if !d.CheckFrozen(w, r, "write") {
			return
		}
		bits := d.AnonBits(ctx, d.IPSuper(r))
		if bits > 40 {
			bits = 40
		}
		c := pow.New(d.Cfg.ServerSecret, exp, bits, pow.PurposeWrite)
		OK(w, r, fmt.Sprintf("c=%s bits=%d exp=%d for=w", c, bits, exp.Unix()),
			map[string]any{"c": c, "bits": bits, "exp": exp.Unix(), "for": "w"})
	default:
		Fail(w, r, Bad("for must be reg or w"))
	}
}

// trustedASN returns the edge-provided ASN when TRUST_ASN is on and the companion header matches
// EDGE_SECRET (3.2); 0 otherwise.
func (d *Deps) trustedASN(r *http.Request) int64 {
	if !d.Cfg.TrustASN || d.Cfg.EdgeSecret == "" {
		return 0
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CX-Edge")), []byte(d.Cfg.EdgeSecret)) != 1 {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(r.Header.Get("X-ASN")), 10, 64)
	if err != nil || n <= 0 || n > 1<<32 {
		return 0
	}
	return n
}

func (d *Deps) licenseID() string {
	if d.Cfg.LicenseContent == "" {
		return "CC0-1.0"
	}
	return d.Cfg.LicenseContent
}

func (d *Deps) hRegister(w http.ResponseWriter, r *http.Request) {
	if !d.CheckFrozen(w, r, "reg") {
		return
	}
	var in struct {
		C      string          `json:"c"`
		Nonce  string          `json:"nonce"`
		Name   string          `json:"name"`
		Bundle json.RawMessage `json:"bundle"`
	}
	if err := Decode(w, r, registerBody, &in); err != nil {
		Fail(w, r, err)
		return
	}
	if err := checkRegName(in.Name); err != nil {
		Fail(w, r, err)
		return
	}
	res, err := d.register(r.Context(), regInput{ip: d.ClientIP(r), c: in.C, nonce: in.Nonce, name: in.Name, bundle: in.Bundle, asn: d.trustedASN(r)})
	if err != nil {
		Fail(w, r, err)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "id=%s token=%s credits=%d", res.id, res.token, res.credits)
	if res.tier > 1 {
		fmt.Fprintf(&b, " tier=%d", res.tier)
	}
	fmt.Fprintf(&b, " recovery=%s license=%s aup=/aup.txt", res.recovery, d.licenseID())
	Text(w, r, 201, b.String(), map[string]any{"id": res.id, "token": res.token, "credits": res.credits, "tier": res.tier,
		"recovery": res.recovery, "license": d.licenseID(), "aup": "/aup.txt"})
}

func checkRegName(name string) error {
	if !ValidName(name) {
		return Bad("name must match [a-zA-Z0-9._-]{1,32}")
	}
	if Reserved(name) {
		return Bad("name reserved")
	}
	return nil
}

// RegisterWithChallenge is the registration core for other entry points (the OAuth consent page,
// 19.4): verifies the PoW, applies every registration cap and mints the root.
func RegisterWithChallenge(ctx context.Context, d *Deps, ip, c, nonce, name string) (id, token, recovery string, err error) {
	if err := checkRegName(name); err != nil {
		return "", "", "", err
	}
	res, err := d.register(ctx, regInput{ip: ip, c: c, nonce: nonce, name: name})
	if err != nil {
		return "", "", "", err
	}
	return res.id, res.token, res.recovery, nil
}

type regInput struct {
	ip, c, nonce, name string
	bundle             json.RawMessage
	asn                int64
}

type regResult struct {
	id, token, recovery string
	credits             int64
	tier                int
}

// register applies 3.2: PoW v2 (purpose reg, the challenge's own bits), the per-group tier, the
// global hourly cap, the super-group daily (4x) and hourly (10 % of REG_PER_HOUR) caps, the ASN
// policy, then mints the root with its cohort and recovery code and stores an optional key bundle.
func (d *Deps) register(ctx context.Context, in regInput) (regResult, error) {
	var out regResult
	info, err := pow.VerifyV2(d.Cfg.ServerSecret, in.c, time.Now())
	if err != nil {
		return out, E(400, "pow", err.Error())
	}
	if info.Purpose != pow.PurposeReg {
		return out, E(400, "pow", "challenge purpose "+info.Purpose.String()+", need reg")
	}
	bits := info.Bits
	if bits == 0 {
		bits = d.Cfg.PowBits // v1 challenge
	}
	if !pow.Check(in.c, in.nonce, bits) {
		return out, ErrPow
	}
	wantID := ChallengeID(ctx, in.c)
	if wantID != "" && !ValidIDPrefix(wantID, 'a') {
		return out, errors.New("challenge id seam returned an invalid id")
	}
	group, super := IPGroup(in.ip), IPSuper(in.ip)
	perHour := d.regPerHour()
	now := time.Now()
	err = Tx(ctx, d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO used_challenges (c, exp) VALUES ($1, $2)`, in.c, info.Exp); err != nil {
			if IsUniqueViolation(err) {
				return E(400, "pow", "challenge already used")
			}
			return err
		}
		class := ""
		if in.asn != 0 {
			if err := tx.QueryRow(ctx, `SELECT class FROM asn_policy WHERE asn = $1`, in.asn).Scan(&class); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if class == "blocked" {
				return E(429, "quota", "asn")
			}
		}
		var n, hour int
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE ip = $1), count(*) FILTER (WHERE at > now() - interval '1 hour')
			FROM reg_ips WHERE at > now() - interval '24 hours'`, group).Scan(&n, &hour); err != nil {
			return err
		}
		if class == "hosting" && n >= regHostingCap {
			return E(429, "quota", "registrations per ip per day")
		}
		if hour >= perHour {
			return E(429, "quota", "registrations per hour (global), retry later")
		}
		var s int
		if err := tx.QueryRow(ctx, `INSERT INTO reg_supers (super, day, n) VALUES ($1, current_date, 1)
			ON CONFLICT (super, day) DO UPDATE SET n = reg_supers.n + 1 RETURNING n`, super).Scan(&s); err != nil {
			return err
		}
		var sh int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM reg_ips WHERE super = $1 AND at > now() - interval '1 hour'`, super).Scan(&sh); err != nil {
			return err
		}
		if s > regPerSuper || sh >= max(1, perHour/10) {
			return E(429, "quota", "registrations super-group")
		}
		if in.asn != 0 {
			var an int
			if err := tx.QueryRow(ctx, `INSERT INTO reg_asn (asn, day, n) VALUES ($1, current_date, 1)
				ON CONFLICT (asn, day) DO UPDATE SET n = reg_asn.n + 1 RETURNING n`, in.asn).Scan(&an); err != nil {
				return err
			}
			if class == "hosting" && an > regASNDaily {
				return E(429, "quota", "asn hosting")
			}
		}
		out.tier, out.credits = 1, 100
		if n >= regPerIP {
			out.tier, out.credits = 2, regTier2
		}
		if _, err := tx.Exec(ctx, `INSERT INTO reg_ips (ip, super, asn) VALUES ($1, $2, $3)`, group, super, in.asn); err != nil {
			return err
		}
		id := wantID
		if id == "" {
			id = NewID('a')
		}
		spec := rootSpec{id: id, name: in.name, ip: in.ip, cohort: group + "|" + strconv.FormatInt(now.Unix()/600, 10),
			ipClass: class, asn: in.asn, credits: out.credits}
		if out.id, out.token, out.recovery, err = createRoot(ctx, tx, spec); err != nil {
			return err
		}
		if err := RegisterBundle(ctx, tx, out.id, in.bundle); err != nil {
			return err
		}
		if in.asn != 0 && class == "" {
			return d.autoClassifyASN(ctx, tx, in.asn)
		}
		return nil
	})
	return out, err
}

// autoClassifyASN writes asn_policy(hosting, note auto) for an ASN that produced >= 20 registrations
// from >= 10 distinct super-groups within its first day (27.8).
func (d *Deps) autoClassifyASN(ctx context.Context, q Q, asn int64) error {
	var n, distinct int
	var older bool
	if err := q.QueryRow(ctx, `SELECT count(*), count(DISTINCT super),
		EXISTS (SELECT 1 FROM identities WHERE asn = $1 AND created < now() - interval '24 hours')
		FROM reg_ips WHERE asn = $1 AND at > now() - interval '24 hours'`, asn).Scan(&n, &distinct, &older); err != nil {
		return err
	}
	if older || n < 20 || distinct < 10 {
		return nil
	}
	tag, err := q.Exec(ctx, `INSERT INTO asn_policy (asn, class, note) VALUES ($1, 'hosting', 'auto') ON CONFLICT (asn) DO NOTHING`, asn)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	return Event(ctx, q, "ops", "asn:"+strconv.FormatInt(asn, 10), "", fmt.Sprintf("asn %d auto-classified hosting (%d registrations, %d networks)", asn, n, distinct))
}

func (d *Deps) hSubkey(w http.ResponseWriter, r *http.Request) {
	me, err := d.AuthWrite(r)
	if err != nil {
		Fail(w, r, err)
		return
	}
	var in struct {
		Name    string   `json:"name"`
		Credits int64    `json:"credits"`
		TTLh    int      `json:"ttl_h"`
		Scopes  []string `json:"scopes"`
		Class   string   `json:"class"`
	}
	if err := Decode(w, r, 4<<10, &in); err != nil {
		Fail(w, r, err)
		return
	}
	if in.Name == "" {
		in.Name = me.Name
	}
	if !ValidName(in.Name) {
		Fail(w, r, Bad("name must match [a-zA-Z0-9._-]{1,32}"))
		return
	}
	maxTTL, defTTL := maxSubkeyTTLh, defSubkeyTTLh
	if in.Class == "url" {
		maxTTL, defTTL = urlTTLh, urlTTLh
	}
	if in.TTLh == 0 {
		in.TTLh = defTTL
	}
	if in.TTLh < 1 || in.TTLh > maxTTL {
		Fail(w, r, Bad(fmt.Sprintf("ttl_h must be 1..%d", maxTTL)))
		return
	}
	if in.Credits < 0 {
		Fail(w, r, Bad("credits must be >= 0"))
		return
	}
	exp := time.Now().Add(time.Duration(in.TTLh) * time.Hour).Truncate(time.Second)
	if !me.Exp.IsZero() && me.Exp.Before(exp) {
		exp = me.Exp
	}
	ctx := r.Context()
	var id, tok, class string
	var scopes []string
	err = Tx(ctx, d.DB, func(tx pgx.Tx) error {
		id, tok, scopes, class, err = createSubkey(ctx, tx, me, SubkeyOpts{Name: in.Name, Credits: in.Credits, Exp: exp, Scopes: in.Scopes, Class: in.Class})
		if err == nil {
			err = Audit(ctx, tx, me.ID, "subkey", id, 0)
		}
		return err
	})
	if err != nil {
		Fail(w, r, err)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "id=%s token=%s credits=%d exp=%s", id, tok, in.Credits, Date(exp))
	j := map[string]any{"id": id, "token": tok, "credits": in.Credits, "exp": exp.UTC().Format(time.RFC3339)}
	if scopes != nil {
		b.WriteString(" scopes=" + strings.Join(scopes, ","))
		j["scopes"] = scopes
	}
	if class != "full" {
		b.WriteString(" class=" + class)
		j["class"] = class
	}
	if class == "url" {
		u := d.Cfg.PublicURL + "/v1/me/resume?t=" + tok
		b.WriteString("\nurl: " + u)
		j["url"] = u
	}
	Text(w, r, 201, b.String(), j)
}

func (d *Deps) hSubkeyRevoke(w http.ResponseWriter, r *http.Request) {
	me, err := d.Auth(r)
	if err != nil {
		Fail(w, r, err)
		return
	}
	target := r.PathValue("id")
	if !ValidIDPrefix(target, 'a') || target == me.ID {
		Fail(w, r, Bad("bad subkey id"))
		return
	}
	ctx := r.Context()
	var n int64
	err = Tx(ctx, d.DB, func(tx pgx.Tx) error {
		ok, err := IsAncestor(ctx, tx, me.ID, target)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		if n, err = RevokeTree(ctx, tx, target, me.ID); err != nil {
			return err
		}
		return Audit(ctx, tx, me.ID, "revoke", target, int(n))
	})
	if err != nil {
		Fail(w, r, err)
		return
	}
	OK(w, r, fmt.Sprintf("ok revoked=%d", n), map[string]any{"ok": true, "revoked": n})
}

// meExtra are the root-level fields hMe reads beyond the Ident.
type meExtra struct {
	recovery, mk, publicStats bool
	erasing                   *time.Time
	ipClass, family, model    string
	cutoff                    string
	asn                       int64
}

func (d *Deps) loadMeExtra(ctx context.Context, root string) (meExtra, error) {
	var x meExtra
	err := d.DB.QueryRow(ctx, `SELECT recovery_hash IS NOT NULL, erasing_at, ip_class, asn, mk_wrapped IS NOT NULL, family, model, cutoff, public_stats
		FROM identities WHERE id = $1`, root).Scan(&x.recovery, &x.erasing, &x.ipClass, &x.asn, &x.mk, &x.family, &x.model, &x.cutoff, &x.publicStats)
	return x, err
}

func (d *Deps) hMe(w http.ResponseWriter, r *http.Request) {
	me, err := d.Auth(r)
	if err != nil {
		Fail(w, r, err)
		return
	}
	ctx := r.Context()
	x, err := d.loadMeExtra(ctx, me.Root)
	if err != nil {
		Fail(w, r, err)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "id=%s name=%s root=%s credits=%d rep=%d exp=%s", me.ID, me.Name, me.Root, me.Credits, me.Rep, Date(me.Exp))
	if me.Banned {
		b.WriteString(" banned=1")
	}
	j := map[string]any{"id": me.ID, "name": me.Name, "root": me.Root, "credits": me.Credits, "rep": me.Rep, "banned": me.Banned,
		"created": me.Created.UTC().Format(time.RFC3339), "class": me.Class}
	if !me.Exp.IsZero() {
		j["exp"] = me.Exp.UTC().Format(time.RFC3339)
	}
	// v2 appended fields (3.2, 3.4, 3.5, 3.6, 26.4, 27.8).
	lvl := Level(ctx, d.DB, me.Root)
	fmt.Fprintf(&b, " lvl=L%d", lvl)
	j["lvl"] = lvl
	ipclass := x.ipClass
	if ipclass == "" {
		ipclass = "unknown"
	}
	b.WriteString(" ipclass=" + ipclass)
	j["ipclass"] = ipclass
	if x.asn != 0 {
		fmt.Fprintf(&b, " net=asn:%d", x.asn)
		j["asn"] = x.asn
	}
	if me.ID == me.Root {
		rec := "unset"
		if x.recovery {
			rec = "set"
		}
		b.WriteString(" recovery=" + rec)
		j["recovery"] = x.recovery
	}
	if me.Scopes != nil {
		b.WriteString(" scopes=" + strings.Join(me.Scopes, ","))
		j["scopes"] = me.Scopes
	}
	if me.Class != "full" {
		b.WriteString(" class=" + me.Class)
	}
	if x.erasing != nil {
		b.WriteString(" erasing=" + Date(*x.erasing))
		j["erasing"] = x.erasing.UTC().Format(time.RFC3339)
	}
	if !x.mk {
		b.WriteString(" seal=unset")
	}
	j["seal"] = x.mk
	if x.family != "" {
		b.WriteString(" family=" + x.family)
		j["family"] = x.family
	}
	if x.model != "" {
		b.WriteString(" model=" + x.model)
		j["model"] = x.model
	}
	if x.cutoff != "" {
		b.WriteString(" cutoff=" + x.cutoff)
		j["cutoff"] = x.cutoff
	}
	if x.publicStats {
		b.WriteString(" public_stats=1")
	}
	j["public_stats"] = x.publicStats
	extra := d.MeLines(ctx, me)
	for _, l := range extra {
		b.WriteString("\n" + cleanLine(l, 200))
	}
	if len(extra) > 0 {
		j["extra"] = extra
	}
	OK(w, r, b.String(), j)
}
