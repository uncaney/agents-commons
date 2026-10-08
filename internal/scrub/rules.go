package scrub

import (
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"ekaii.fr/commons/internal/core"
)

// RulesV is the rules version pinned by clients (26.5); bump it when a rule changes.
const RulesV = 2

// Finding is one detector hit. Off/Len are a byte span in the text that was scanned (the stored,
// normalised text when the caller followed the write order); Tier 1 rejects, tier 2 masks.
type Finding struct {
	Kind, Field string
	Off, Len    int
	Tier        int
	Rule        string
}

func (f Finding) String() string { return fmt.Sprintf("%s %s@%d", f.Kind, f.Field, f.Off) }

// Opts tunes a scan. Example lets placeholder keys through: a tier-1 vendor pattern whose body
// fails the entropy test (AKIAAAAABBBBCCCCDDDD) passes, a real-looking one still rejects.
type Opts struct{ Example bool }

const (
	entropyMin   = 3.0 // bits/char for the generic keyword rule and the Example gate
	entropyRun   = 3.5 // Strict: random-looking runs
	genericMin   = 8
	b64MinRun    = 41 // "runs > 40 chars"
	strictRun    = 20
	tier1, tier2 = 1, 2
)

type rule struct {
	name, kind string
	tier       int
	re         *regexp.Regexp
	group      int                           // submatch that is the finding (0 = whole match)
	check      func(val string, o Opts) bool // nil = accept
	trim       bool                          // drop trailing quotes/punctuation from the value
}

var (
	pemEndRe = regexp.MustCompile(`-----END [A-Z ]*PRIVATE KEY( BLOCK)?-----`)
	b64Re    = regexp.MustCompile(`[A-Za-z0-9+/_-]{41,}={0,2}`)
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	runRe    = regexp.MustCompile(`[A-Za-z0-9+/_=-]{20,}`)
	hostRe   = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9-]{0,62}\.)+[a-z][a-z0-9-]{1,23}\b`)
	digitRe  = regexp.MustCompile(`[0-9]`)
	placeRe  = regexp.MustCompile(`(?i)example|xxxx|your[_ -]?|placeholder|redacted|change[_-]?me|dummy|sample|insert[_-]|replace[_-]?|fake|\.\.\.|\*\*\*|<[^>]*>|\$\{|\{\{|\$[A-Z_]`)
)

// notPlaceholder refuses documentation values: placeholder words, shell/template variables, a
// single character covering half the value.
func notPlaceholder(val string, _ Opts) bool { return !placeholder(val) }

func placeholder(val string) bool {
	if placeRe.MatchString(val) {
		return true
	}
	var counts [256]int
	max, n := 0, 0
	for i := 0; i < len(val); i++ {
		counts[val[i]]++
		if counts[val[i]] > max {
			max = counts[val[i]]
		}
		n++
	}
	return n >= 6 && max*2 >= n
}

// vendor is the tier-1 gate for prefixed keys: never a placeholder; under Example a body below
// the entropy floor passes too.
func vendor(val string, o Opts) bool {
	if placeholder(val) {
		return false
	}
	return !o.Example || entropy(val) >= entropyMin
}

// generic is the keyword rule gate: >= 8 chars, a digit, no code shape, entropy >= 3.0.
func generic(val string, _ Opts) bool {
	if len(val) < genericMin || placeholder(val) || !digitRe.MatchString(val) {
		return false
	}
	if strings.ContainsAny(val, "()[]{}$<>./\\") || strings.HasPrefix(strings.ToLower(val), "http") {
		return false
	}
	return entropy(val) >= entropyMin
}

func ipOK(val string, _ Opts) bool {
	ip := net.ParseIP(val)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2, v4[0] == 198 && v4[1] == 51 && v4[2] == 100,
			v4[0] == 203 && v4[1] == 0 && v4[2] == 113: // documentation ranges
			return false
		case v4[0] == 255 || v4[0] == 0: // netmasks, "0.x" placeholders
			return false
		}
		return true
	}
	if !strings.Contains(val, "::") && !strings.ContainsAny(strings.ToLower(val), "abcdef") {
		return false // 12:30:45-style timestamps never are addresses
	}
	return !(ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8) // 2001:db8::/32
}

func phoneOK(val string, _ Opts) bool {
	n := 0
	for i := 0; i < len(val); i++ {
		if val[i] >= '0' && val[i] <= '9' {
			n++
		}
	}
	return n >= 8 && n <= 15
}

func emailOK(val string, _ Opts) bool {
	local := strings.ToLower(val[:strings.IndexByte(val, '@')])
	return local != "git" && local != "scope"
}

// rules is the catalogue, specific before generic (the first rule at an offset wins). Every regex
// is RE2 and Python-compatible (no lookaround, flags up front) because GET /scrub/rules ships it.
var rules = []rule{
	{"pem", "pem", tier1, regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----`), 0, nil, false},
	{"sshkey", "sshkey", tier1, regexp.MustCompile(`\b(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521))\s+AAAA[0-9A-Za-z+/]{40,}={0,3}`), 0, nil, false},
	{"token.cx", "token", tier1, regexp.MustCompile(`\bcx_[A-Za-z0-9_-]{43}`), 0, nil, false},
	{"editkey", "editkey", tier1, regexp.MustCompile(`\bedit=[a-z2-7]{26}\b`), 0, nil, false},
	{"key.aws", "key", tier1, regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`), 0, vendor, false},
	{"key.github", "key", tier1, regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}`), 0, vendor, false},
	{"key.github-pat", "key", tier1, regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}`), 0, vendor, false},
	{"key.gitlab", "key", tier1, regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`), 0, vendor, false},
	{"key.slack", "key", tier1, regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`), 0, vendor, false},
	{"key.anthropic", "key", tier1, regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`), 0, vendor, false},
	{"key.openai-proj", "key", tier1, regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_-]{20,}`), 0, vendor, false},
	{"key.openai", "key", tier1, regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`), 0, vendor, false},
	{"key.openai-marker", "key", tier1, regexp.MustCompile(`T3BlbkFJ`), 0, nil, false},
	{"key.google", "key", tier1, regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`), 0, vendor, false},
	{"key.stripe", "key", tier1, regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{10,}`), 0, vendor, false},
	{"key.sendgrid", "key", tier1, regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{20,}`), 0, vendor, false},
	{"key.huggingface", "key", tier1, regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`), 0, vendor, false},
	{"key.npm", "key", tier1, regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}`), 0, vendor, false},
	{"key.pypi", "key", tier1, regexp.MustCompile(`\bpypi-AgEI[A-Za-z0-9_-]{20,}`), 0, vendor, false},
	{"key.digitalocean", "key", tier1, regexp.MustCompile(`\bdop_v1_[a-f0-9]{64}`), 0, vendor, false},
	{"key.shopify", "key", tier1, regexp.MustCompile(`\bshpat_[a-fA-F0-9]{32}`), 0, vendor, false},
	{"key.tailscale", "key", tier1, regexp.MustCompile(`\btskey-[A-Za-z0-9_-]{10,}`), 0, vendor, false},
	{"key.age", "key", tier1, regexp.MustCompile(`\bAGE-SECRET-KEY-1[A-Z0-9]{50,}`), 0, vendor, false},
	{"key.wireguard", "key", tier1, regexp.MustCompile(`PrivateKey\s*=\s*[A-Za-z0-9+/]{43}=`), 0, vendor, false},
	{"otp", "otp", tier1, regexp.MustCompile(`otpauth://[^\s]*secret=[A-Za-z2-7]{16,}`), 0, nil, false},
	{"webhook.discord", "webhook", tier1, regexp.MustCompile(`discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]{20,}`), 0, nil, false},
	{"key.telegram", "key", tier1, regexp.MustCompile(`\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b`), 0, vendor, false},
	{"jwt", "jwt", tier1, regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*`), 0, nil, false},
	{"password.dsn", "password", tier1, regexp.MustCompile(`\b(postgres(ql)?|mysql|mariadb|mongodb(\+srv)?|redis|rediss|amqps?|mssql|sqlserver|ldaps?|ftp|smtps?)://[^\s:/@]{1,64}:[^\s@/]{1,128}@`), 0, notPlaceholder, false},
	{"password.url", "password", tier1, regexp.MustCompile(`\b[a-z][a-z0-9+.-]{1,15}://[^\s:/@]{1,64}:[^\s@/]{1,128}@`), 0, notPlaceholder, false},
	{"key.azure", "key", tier1, regexp.MustCompile(`\bAccountKey=[A-Za-z0-9+/=]{20,}`), 0, vendor, false},
	{"key.gcp", "key", tier1, regexp.MustCompile(`private_key_id["'\s:=]+[a-f0-9]{10,}`), 0, nil, false},
	{"key.client-secret", "key", tier1, regexp.MustCompile(`\bclient_secret["'\s:=]+([A-Za-z0-9_.~+/=-]{8,})`), 1, vendor, true},
	{"bearer", "bearer", tier1, regexp.MustCompile(`(?i)authorization:\s*bearer\s+([A-Za-z0-9._~+/=-]{20,})`), 1, vendor, false},
	{"password.flag", "password", tier1, regexp.MustCompile(`--password[= ](\S+)`), 1, notPlaceholder, true},
	{"password.p", "password", tier1, regexp.MustCompile(`\b(mysql|mariadb|mysqldump|mysqladmin|psql|pg_dump|pg_restore|sshpass)\b[^\n]*\s-p(\S{4,})`), 2, notPlaceholder, true},
	{"password.sshpass", "password", tier1, regexp.MustCompile(`\bsshpass\s+-p\s+(\S+)`), 1, notPlaceholder, true},
	{"password.env", "password", tier1, regexp.MustCompile(`\b(PGPASSWORD|MYSQL_PWD|REDISCLI_AUTH)=(\S+)`), 2, notPlaceholder, true},
	{"secret.generic", "secret", tier1, regexp.MustCompile(`(?i)\b[a-z0-9_.-]{0,40}(api[_-]?key|token|secret|passw(or)?d|pwd|private[_-]?key)(s|[_-][a-z0-9]{1,12})?\s*[:=]\s*["']?(\S{8,})`), 4, generic, true},
	{"email", "email", tier2, regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b`), 0, emailOK, false},
	{"ip.v4", "ip", tier2, regexp.MustCompile(`\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\b`), 0, ipOK, false},
	{"ip.v6", "ip", tier2, regexp.MustCompile(`(?i)\b([0-9a-f]{0,4}:){2,7}[0-9a-f]{1,4}\b|::1\b`), 0, ipOK, false},
	{"path.unix", "path", tier2, regexp.MustCompile(`(/Users|/home)/[A-Za-z0-9._-]+`), 0, nil, false},
	{"path.win", "path", tier2, regexp.MustCompile(`(?i)\b[A-Z]:[\\/]Users[\\/][^\\/\s"']+`), 0, nil, false},
	{"host.internal", "host", tier2, regexp.MustCompile(`(?i)\b([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+(local|internal|corp|lan|home\.arpa|svc\.cluster\.local)\b`), 0, nil, false},
	{"arn", "arn", tier2, regexp.MustCompile(`\barn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:([0-9]{12}):`), 1, nil, false},
	{"phone", "phone", tier2, regexp.MustCompile(`\+[1-9][0-9 .()-]{6,20}[0-9]\b`), 0, phoneOK, false},
}

// kindOrder renders kinds in a stable order: tier 1 first, then the masked classes.
var kindOrder = []string{"pem", "sshkey", "token", "editkey", "key", "otp", "webhook", "jwt", "password", "bearer", "secret",
	"email", "ip", "path", "host", "arn", "phone", "entropy"}

var kindRank = func() map[string]int {
	m := map[string]int{}
	for i, k := range kindOrder {
		m[k] = i
	}
	return m
}()

// entropy is the Shannon entropy of s in bits per byte.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n, h := float64(len(s)), 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

type hit struct {
	Finding
	idx int
}

func scanHits(text string, tiers int, o Opts) []hit {
	st, back := prepare(text)
	var hs []hit
	for i, r := range rules {
		if r.tier&tiers == 0 {
			continue
		}
		for _, m := range r.re.FindAllStringSubmatchIndex(st, -1) {
			s, e := m[2*r.group], m[2*r.group+1]
			if s < 0 || s >= e {
				continue
			}
			if r.trim {
				for e > s && strings.IndexByte(`"',;.)]}`, st[e-1]) >= 0 {
					e--
				}
			}
			if r.check != nil && !r.check(st[s:e], o) {
				continue
			}
			if r.kind == "pem" {
				if em := pemEndRe.FindStringIndex(st[e:]); em != nil {
					e += em[1]
				} else {
					e = len(st)
				}
			}
			os, oe := orig(back, s, e, len(text))
			hs = append(hs, hit{Finding{Kind: r.kind, Off: os, Len: oe - os, Tier: r.tier, Rule: r.name}, i})
		}
	}
	if tiers&tier1 != 0 {
		hs = append(hs, b64Hits(st, back, len(text), o)...)
	}
	return dedupe(hs)
}

// b64Hits decodes every base64 run longer than 40 chars once and runs the tier-1 rules on the
// plaintext; a hit covers the whole run (SPEC 5 "one base64 decode pass").
func b64Hits(st string, back []int, n int, o Opts) []hit {
	var hs []hit
	for _, m := range b64Re.FindAllStringIndex(st, -1) {
		run := st[m[0]:m[1]]
		if hexRe.MatchString(run) || strings.HasPrefix(run, "eyJ") {
			continue
		}
		dec, ok := decodeB64(run)
		if !ok {
			continue
		}
		for i, r := range rules {
			if r.tier != tier1 {
				continue
			}
			sm := r.re.FindStringSubmatchIndex(dec)
			if sm == nil {
				continue
			}
			s, e := sm[2*r.group], sm[2*r.group+1]
			if s < 0 || s >= e || (r.check != nil && !r.check(dec[s:e], o)) {
				continue
			}
			os, oe := orig(back, m[0], m[1], n)
			hs = append(hs, hit{Finding{Kind: r.kind, Off: os, Len: oe - os, Tier: tier1, Rule: "b64:" + r.name}, len(rules) + i})
			break
		}
	}
	return hs
}

func decodeB64(run string) (string, bool) {
	run = strings.TrimRight(run, "=")
	var enc *base64.Encoding
	switch {
	case strings.ContainsAny(run, "+/") && strings.ContainsAny(run, "-_"):
		return "", false
	case strings.ContainsAny(run, "-_"):
		enc = base64.RawURLEncoding
	default:
		enc = base64.RawStdEncoding
	}
	b, err := enc.DecodeString(run)
	if err != nil || !utf8.Valid(b) {
		return "", false
	}
	ctl := 0
	for _, r := range string(b) {
		if r != '\n' && r != '\t' && r != '\r' && (unicode.IsControl(r) || r == utf8.RuneError) {
			ctl++
		}
	}
	if ctl*20 > len(b) {
		return "", false
	}
	return string(b), true
}

// dedupe sorts by offset, then catalogue order (specific before generic), and drops hits
// overlapping an earlier one.
func dedupe(hs []hit) []hit {
	sort.SliceStable(hs, func(i, j int) bool {
		if hs[i].Off != hs[j].Off {
			return hs[i].Off < hs[j].Off
		}
		if hs[i].idx != hs[j].idx {
			return hs[i].idx < hs[j].idx
		}
		return hs[i].Len > hs[j].Len
	})
	out := hs[:0]
	end := -1
	for _, h := range hs {
		if h.Off < end {
			continue
		}
		out = append(out, h)
		end = h.Off + h.Len
	}
	return out
}

func findings(hs []hit, field string) []Finding {
	if len(hs) == 0 {
		return nil
	}
	fs := make([]Finding, len(hs))
	for i, h := range hs {
		fs[i] = h.Finding
		fs[i].Field = field
	}
	return fs
}

// Scan reports every tier-1 and tier-2 finding of text (call Normalize first; Scan still folds
// invisibles and homoglyphs internally, so a split or disguised key never slips through).
func Scan(field, text string) []Finding { return ScanOpts(field, text, Opts{}) }

// ScanOpts is Scan with options.
func ScanOpts(field, text string, o Opts) []Finding {
	return findings(scanHits(text, tier1|tier2, o), field)
}

// Mask replaces every finding of both tiers in place and returns the kinds found, in kindOrder.
func Mask(text string) (string, []string) {
	out, counts := MaskN(text)
	return out, kindsOf(counts)
}

// MaskN is Mask with a count per kind (the /v1/scrub header line).
func MaskN(text string) (string, map[string]int) { return maskTiers(text, tier1|tier2, Opts{}) }

func maskTiers(text string, tiers int, o Opts) (string, map[string]int) {
	hs := scanHits(text, tiers, o)
	if len(hs) == 0 {
		return text, nil
	}
	var b strings.Builder
	b.Grow(len(text))
	counts := map[string]int{}
	last := 0
	for _, h := range hs {
		b.WriteString(text[last:h.Off])
		b.WriteString(replacement(h.Kind))
		last = h.Off + h.Len
		counts[h.Kind]++
	}
	b.WriteString(text[last:])
	return b.String(), counts
}

func replacement(kind string) string {
	switch kind {
	case "path":
		return "/<user>"
	case "arn":
		return "<acct>"
	}
	return "<" + kind + ">"
}

func kindsOf(counts map[string]int) []string {
	if len(counts) == 0 {
		return nil
	}
	var ks []string
	for _, k := range kindOrder {
		if counts[k] > 0 {
			ks = append(ks, k)
		}
	}
	return ks
}

// Summary renders counts as "key=2 email=1 ip=3" (or "clean").
func Summary(counts map[string]int) string {
	ks := kindsOf(counts)
	if len(ks) == 0 {
		return "clean"
	}
	parts := make([]string, len(ks))
	for i, k := range ks {
		parts[i] = fmt.Sprintf("%s=%d", k, counts[k])
	}
	return strings.Join(parts, " ")
}

// RejectOrMask is the write-path hook: it normalises every field in place, rejects on the first
// tier-1 finding with `err scrub <kind> <field>@<off>` and otherwise writes the tier-2-masked text
// back into the map, returning the kinds masked (for `masked=email,ip`). Fields are visited in
// name order so the error is deterministic.
func RejectOrMask(fields map[string]*string) ([]string, *core.APIError) {
	return RejectOrMaskOpts(fields, Opts{})
}

// RejectOrMaskOpts is RejectOrMask with options (`example:true` payloads).
func RejectOrMaskOpts(fields map[string]*string, o Opts) ([]string, *core.APIError) {
	names := make([]string, 0, len(fields))
	for k, p := range fields {
		if p == nil {
			continue
		}
		*p = Normalize(*p)
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if *fields[k] == "" {
			continue
		}
		for _, h := range scanHits(*fields[k], tier1, o) {
			return nil, core.E(400, "scrub", fmt.Sprintf("%s %s@%d", h.Kind, k, h.Off))
		}
	}
	all := map[string]int{}
	for _, k := range names {
		if *fields[k] == "" {
			continue
		}
		out, counts := maskTiers(*fields[k], tier2, o)
		*fields[k] = out
		for kind, n := range counts {
			all[kind] += n
		}
	}
	return kindsOf(all), nil
}

// Strict is the seed gate (SPEC 22): every tier-1 and tier-2 class is a finding, plus random
// looking runs (20+ chars, entropy >= 3.5, not a hex digest or UUID) and dotted hosts outside the
// public allowlist. Any finding means the entry is refused; nothing is masked.
func Strict(text string) []Finding { return StrictHosts(text, HostAllowed) }

// StrictHosts is Strict with a caller-supplied host allowlist (tools/seed/hosts.txt).
func StrictHosts(text string, allowed func(host string) bool) []Finding {
	hs := scanHits(text, tier1|tier2, Opts{})
	st, back := prepare(text)
	for _, m := range runRe.FindAllStringIndex(st, -1) {
		if v := st[m[0]:m[1]]; randomRun(v) {
			s, e := orig(back, m[0], m[1], len(text))
			hs = append(hs, hit{Finding{Kind: "entropy", Off: s, Len: e - s, Tier: tier1, Rule: "entropy"}, 1 << 20})
		}
	}
	for _, m := range hostRe.FindAllStringIndex(st, -1) {
		if h := strings.ToLower(st[m[0]:m[1]]); suspiciousHost(h, allowed) {
			s, e := orig(back, m[0], m[1], len(text))
			hs = append(hs, hit{Finding{Kind: "host", Off: s, Len: e - s, Tier: tier2, Rule: "host.dotted"}, 1<<20 + 1})
		}
	}
	return findings(dedupe(hs), "")
}

// randomRun: letters and >= 2 digits, entropy >= 3.5, not hex, not a UUID, not a path.
func randomRun(v string) bool {
	if hexRe.MatchString(v) || uuidRe.MatchString(v) || strings.HasPrefix(v, "/") || strings.Count(v, "/") > 1 {
		return false
	}
	digits, letters := 0, false
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			letters = true
		}
	}
	return digits >= 2 && letters && entropy(v) >= entropyRun
}

var fileExt = map[string]bool{"py": true, "js": true, "ts": true, "go": true, "rs": true, "sh": true, "md": true, "txt": true,
	"json": true, "yaml": true, "yml": true, "toml": true, "ini": true, "cfg": true, "conf": true, "lock": true, "log": true,
	"csv": true, "html": true, "htm": true, "css": true, "xml": true, "env": true, "so": true, "dll": true, "exe": true,
	"bin": true, "tar": true, "gz": true, "zip": true, "jar": true, "war": true, "class": true, "cc": true, "cpp": true,
	"hpp": true, "rb": true, "php": true, "pl": true, "pm": true, "ex": true, "exs": true, "erl": true, "kt": true,
	"swift": true, "mm": true, "scala": true, "sql": true, "db": true, "sqlite": true, "pdf": true, "png": true, "jpg": true,
	"jpeg": true, "gif": true, "svg": true, "ico": true, "woff": true, "woff2": true, "ttf": true, "mjs": true, "cjs": true,
	"jsx": true, "tsx": true, "vue": true, "svelte": true, "map": true, "pyc": true, "whl": true, "egg": true, "deb": true,
	"rpm": true, "dmg": true, "pkg": true, "app": true, "service": true, "timer": true, "socket": true, "mount": true,
	"bak": true, "orig": true, "tmp": true, "old": true, "new": true, "dist": true, "example": true,
	"test": true, "spec": true, "min": true, "d": true, "pb": true, "proto": true, "wasm": true, "wat": true, "zig": true,
	"c": true, "h": true, "o": true, "a": true, "la": true, "lo": true, "img": true, "iso": true, "qcow2": true, "vdi": true,
	"ovpn": true, "pem": true, "crt": true, "key": true, "csr": true, "p12": true, "pfx": true, "jks": true, "asc": true,
	"gpg": true, "sig": true, "sum": true, "sha256": true, "mod": true, "work": true, "nix": true, "tf": true, "tfvars": true,
	"hcl": true, "tpl": true, "tmpl": true, "j2": true, "jinja": true, "mustache": true, "hbs": true, "ejs": true}

var publicTLD = map[string]bool{"com": true, "net": true, "org": true, "io": true, "dev": true, "app": true, "fr": true,
	"de": true, "uk": true, "co": true, "us": true, "eu": true, "ai": true, "me": true, "info": true, "xyz": true, "cloud": true,
	"tech": true, "sh": true, "ch": true, "be": true, "nl": true, "es": true, "it": true, "pt": true, "pl": true, "ru": true,
	"cn": true, "jp": true, "br": true, "ca": true, "au": true, "in": true, "se": true, "no": true, "fi": true, "dk": true,
	"cz": true, "at": true, "ie": true, "nz": true, "kr": true, "tw": true, "hk": true, "sg": true, "za": true, "mx": true,
	"ar": true, "ly": true, "to": true, "tv": true, "cc": true, "gg": true, "st": true, "re": true, "fm": true, "am": true,
	"is": true, "lu": true, "li": true, "biz": true, "pro": true, "site": true, "online": true, "store": true, "live": true,
	"page": true, "run": true, "zone": true, "network": true, "systems": true, "tools": true, "digital": true, "email": true,
	"host": true, "space": true, "link": true, "click": true, "top": true, "win": true, "one": true, "ovh": true, "nu": true,
	"edu": true, "gov": true, "mil": true, "int": true, "arpa": true, "local": true, "internal": true, "lan": true, "corp": true}

// HostAllowed is the default public allowlist for Strict: documentation and registry hosts that
// personal notes legitimately cite. Exact host, registrable domain, or any `docs.` host.
func HostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if allowHosts[host] || strings.HasPrefix(host, "docs.") || strings.HasPrefix(host, "www.") && allowHosts[host[4:]] {
		return true
	}
	labels := strings.Split(host, ".")
	if n := len(labels); n > 2 {
		return allowHosts[strings.Join(labels[n-2:], ".")]
	}
	return false
}

var allowHosts = func() map[string]bool {
	m := map[string]bool{}
	for _, h := range strings.Fields(`github.com githubusercontent.com gitlab.com bitbucket.org codeberg.org sr.ht pypi.org
		pythonhosted.org npmjs.com npmjs.org yarnpkg.com pnpm.io crates.io rust-lang.org golang.org go.dev proxy.golang.org
		sum.golang.org nodejs.org deno.land bun.sh python.org readthedocs.io readthedocs.org stackoverflow.com
		stackexchange.com superuser.com serverfault.com askubuntu.com unix.stackexchange.com developer.mozilla.org
		mozilla.org learn.microsoft.com microsoft.com apple.com docker.com docker.io ghcr.io quay.io kubernetes.io k8s.io
		postgresql.org mysql.com mariadb.org redis.io nginx.org nginx.com apache.org debian.org ubuntu.com archlinux.org
		fedoraproject.org redhat.com alpinelinux.org brew.sh homebrew.sh wikipedia.org w3.org ietf.org rfc-editor.org
		letsencrypt.org cloudflare.com anthropic.com openai.com huggingface.co example.com example.org example.net
		localhost localhost.localdomain agents.ekaii.fr traefik.io grafana.com prometheus.io sqlite.org git-scm.com
		kernel.org gnu.org llvm.org clang.llvm.org cmake.org ansible.com terraform.io hashicorp.com vagrantup.com
		virtualbox.org proxmox.com tailscale.com wireguard.com openssh.com openssl.org curl.se jq.dev jqlang.github.io
		gradle.org maven.apache.org oracle.com java.com adoptium.net jetbrains.com vim.org neovim.io code.visualstudio.com
		googleapis.com google.com amazon.com amazonaws.com aws.amazon.com azure.com atlassian.com jira.com slack.com
		discord.com telegram.org matrix.org element.io nextcloud.com jellyfin.org plex.tv home-assistant.io
		raspberrypi.com raspberrypi.org ubnt.com ui.com unifi.ui.com schema.org json.org yaml.org toml.io
		semver.org opencontainers.org cncf.io linuxfoundation.org freedesktop.org systemd.io gentoo.org nixos.org
		voidlinux.org opensuse.org suse.com centos.org rockylinux.org almalinux.org`) {
		m[h] = true
	}
	return m
}()

// suspiciousHost: a dotted name with a public TLD that is not a two-label filename (settings.py,
// app.local is caught by host.internal anyway) and sits outside the allowlist.
func suspiciousHost(h string, allowed func(string) bool) bool {
	labels := strings.Split(h, ".")
	tld := labels[len(labels)-1]
	if !publicTLD[tld] || len(labels) == 2 && fileExt[tld] {
		return false
	}
	return !allowed(h)
}
