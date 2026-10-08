package scrub

import (
	"regexp"
	"strings"
)

// Families lists the hazard families in render order (SPEC 4.5); GET /hazards.txt publishes them.
var Families = []string{"exec-remote", "destroy", "privilege", "tls-off", "exfil", "install-untrusted", "obfuscated-exec"}

// FamilyDesc is the one-line description per family.
var FamilyDesc = map[string]string{
	"exec-remote":       "download piped to a shell or interpreter (curl|wget|iwr ... | sh|bash|python|node|iex)",
	"destroy":           "rm -rf outside tmp, mkfs, dd of=/dev, DROP/TRUNCATE, git reset --hard, git push --force",
	"privilege":         "sudo + download, chmod 777, setcap, disabling SIP/Defender/SELinux/Gatekeeper",
	"tls-off":           "curl -k, verify=False, GIT_SSL_NO_VERIFY, rejectUnauthorized=0, NODE_TLS_REJECT_UNAUTHORIZED=0",
	"exfil":             "reads or uploads of ~/.ssh, .env, credentials files, keychains; printenv|env piped to the network",
	"install-untrusted": "pip/npm/cargo/go install from raw URLs or a non-default index",
	"obfuscated-exec":   "base64 -d | sh, eval of decoded strings, nested $(...) around them",
}

type hazardRule struct {
	family string
	re     *regexp.Regexp
	check  func(m []string) bool // optional, on the submatches
}

var hazardRules = []hazardRule{
	// exec-remote
	{"exec-remote", regexp.MustCompile(`(?i)\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|fetch)\b[^\n|;&]*\|\s*(sudo\s+(-\S+\s+)*)?(sh|bash|zsh|dash|ksh|fish|python[23]?|node|perl|ruby|php|pwsh|powershell|iex|invoke-expression)\b`), nil},
	{"exec-remote", regexp.MustCompile(`(?i)\b(sh|bash|zsh)\s+(-c\s+)?["']?\s*\$\(\s*(curl|wget)\b`), nil},
	{"exec-remote", regexp.MustCompile(`(?i)(\b(sh|bash|zsh|source)|^\.|\s\.)\s+<\(\s*(curl|wget)\b`), nil},
	{"exec-remote", regexp.MustCompile(`(?i)\b(iex|invoke-expression)\s*\(*\s*(\(?new-object\s+(system\.)?net\.webclient\)?\.downloadstring|iwr|irm|invoke-webrequest|invoke-restmethod)\b`), nil},
	// destroy
	{"destroy", regexp.MustCompile(`(?i)(^|[\s;&|(` + "`" + `])rm\s+(-[a-z-]+\s+)*(-[a-z]*r[a-z]*|--recursive)\s+(-[a-z-]+\s+)*(--\s+)?(\S+)`), destroyTarget},
	{"destroy", regexp.MustCompile(`(?i)\bmkfs(\.[a-z0-9]+)?\s`), nil},
	{"destroy", regexp.MustCompile(`(?i)\bdd\s+[^\n]*\bof=/dev/(sd|hd|nvme|disk|mmcblk|vd|xvd|mapper|rdisk)`), nil},
	{"destroy", regexp.MustCompile(`(?i)\b(drop|truncate)\s+(table|database|schema)\b`), nil},
	{"destroy", regexp.MustCompile(`(?i)\bgit\s+(\S+\s+)*reset\s+(\S+\s+)*--hard\b`), nil},
	{"destroy", regexp.MustCompile(`(?im)\bgit\s+(\S+\s+)*push\b[^\n]*\s(--force|-f)(\s|$)`), nil},
	// privilege
	{"privilege", regexp.MustCompile(`(?i)\bsudo\s+[^\n|;&]*\b(curl|wget|iwr|irm|invoke-webrequest)\b`), nil},
	{"privilege", regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n]*\|\s*sudo\b`), nil},
	{"privilege", regexp.MustCompile(`(?i)\bchmod\s+(-\S+\s+)*(0?777|a\+rwx|ugo\+rwx)\b`), nil},
	{"privilege", regexp.MustCompile(`(?i)\bsetcap\s`), nil},
	{"privilege", regexp.MustCompile(`(?i)\bcsrutil\s+disable\b|\bspctl\s+--master-disable\b`), nil},
	{"privilege", regexp.MustCompile(`(?i)\bset-mppreference\s+[^\n]*-disable(realtimemonitoring|ioavprotection|behaviormonitoring|antispyware|scriptscanning)\s+(\$true|1)\b|\bDisableAntiSpyware\b|\bnetsh\s+advfirewall\s+set\s+\w+\s+state\s+off\b`), nil},
	{"privilege", regexp.MustCompile(`(?i)\bsetenforce\s+0\b|\bSELINUX\s*=\s*disabled\b|\bselinux=0\b|\bsystemctl\s+(stop|disable|mask)\s+(apparmor|firewalld|ufw)\b|\bufw\s+disable\b`), nil},
	// tls-off
	{"tls-off", regexp.MustCompile(`(?m)(?i:\bcurl\b)[^\n|]*\s(-[a-jl-zA-JL-Z]*k[a-zA-Z]*|--insecure)(\s|$)`), nil},
	{"tls-off", regexp.MustCompile(`(?i)\bverify\s*=\s*false\b|\bssl[_-]?verify\s*[:=]\s*(false|0|none)\b|\b(ssl|tls)[_-]?verify(peer|host)?\s*[:=]\s*(false|0|none)\b|\bInsecureSkipVerify\s*:\s*true\b|\bCURLOPT_SSL_VERIFY(PEER|HOST)\s*(,|=>|=)\s*(false|0)\b|\bPYTHONHTTPSVERIFY\s*=\s*0\b`), nil},
	{"tls-off", regexp.MustCompile(`(?i)\bGIT_SSL_NO_VERIFY\s*=\s*(1|true)\b|\bhttp\.sslverify\s+false\b|\brejectUnauthorized\s*[:=]\s*(false|0)\b|\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0\b|--no-check-certificate\b|\bstrict-ssl\s*(=|\s)\s*false\b|--trusted-host\b|\bStrictHostKeyChecking=no\b|\bServerCertificateValidationCallback\s*=|-SkipCertificateCheck\b`), nil},
	// exfil
	{"exfil", regexp.MustCompile(`(?i)\b(cat|less|more|head|tail|type|get-content|gc|xxd|base64|strings|od|scp|rsync|tar|zip|nc|ncat)\b[^\n|;]*(~/\.ssh\b|\.ssh/(id_[a-z0-9]+|authorized_keys|config)|\bid_(rsa|ed25519|ecdsa|dsa)\b|(^|[\s/"'=])\.env(\.[a-z]+)?\b|\.aws/credentials|\.netrc|\.npmrc|\.pypirc|\.kube/config|\.docker/config\.json|\.gnupg|\.config/gh/hosts\.yml|keychain)`), nil},
	{"exfil", regexp.MustCompile(`(?i)\bsecurity\s+(find-generic-password|find-internet-password|dump-keychain|export)\b`), nil},
	{"exfil", regexp.MustCompile(`(?i)\b(printenv|env|set|export\s+-p|get-childitem\s+env:|gci\s+env:|dir\s+env:)\s*\|[^\n]*\b(curl|wget|nc|ncat|netcat|socat|ssh|mail|sendmail|telnet|openssl\s+s_client|invoke-webrequest|iwr|irm|invoke-restmethod)\b`), nil},
	{"exfil", regexp.MustCompile(`(?i)\bcurl\b[^\n]*\s(-d|--data(-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)\s*["']?@?[^\n]*(\.env\b|\.ssh/|id_rsa|id_ed25519|credentials|\.netrc|\.kube/config|keychain)`), nil},
	// install-untrusted
	{"install-untrusted", regexp.MustCompile(`(?i)\bpip[23]?\s+install(\s+\S+)*\s+(https?://\S+|git\+\S+|--index-url[= ]\S+|-i\s+\S+|--extra-index-url[= ]\S+|--find-links[= ]\S+|-f\s+\S+)`), untrustedIndex},
	{"install-untrusted", regexp.MustCompile(`(?i)\b(npm\s+(i|install|add)|yarn\s+(add|install)|pnpm\s+(add|install)|npx|bunx|bun\s+(add|install))(\s+\S+)*\s+(https?://\S+|git\+\S+|git://\S+|github:\S+|gitlab:\S+|bitbucket:\S+|--registry[= ]\S+)`), untrustedIndex},
	{"install-untrusted", regexp.MustCompile(`(?i)\bnpm\s+config\s+set\s+registry\s+(\S+)`), untrustedIndex},
	{"install-untrusted", regexp.MustCompile(`(?i)\bcargo\s+install(\s+\S+)*\s+(--git[= ]\S+|--index[= ]\S+|--registry[= ]\S+)`), untrustedIndex},
	{"install-untrusted", regexp.MustCompile(`(?i)\bGOPROXY\s*=\s*(\S+)|\bGOFLAGS\s*=\s*\S*-insecure|\bGOINSECURE\s*=\s*\S+|\bGONOSUMCHECK\s*=\s*1|\bGONOSUMDB\s*=\s*\S+\s+go\s+(install|get)\b`), untrustedIndex},
	{"install-untrusted", regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n]*(&&|;)\s*(sudo\s+)?(dpkg\s+-i|rpm\s+-[iU]\S*|installer\s+-pkg|apt(-get)?\s+install\s+\./)`), nil},
	{"install-untrusted", regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(apt-key\s+add|gpg\s+--dearmor|tee\s+/etc/apt/trusted\.gpg\.d/)`), nil},
	// obfuscated-exec
	{"obfuscated-exec", regexp.MustCompile(`(?i)\bbase64\s+(-d|--decode|-D|-di?)\b[^\n]*\|\s*(sudo\s+)?(sh|bash|zsh|python[23]?|node|perl|ruby|php|pwsh|powershell)\b`), nil},
	{"obfuscated-exec", regexp.MustCompile(`(?i)\beval\s*\(?\s*["'$(]*\s*(base64|atob|b64decode|FromBase64String|unhexlify|zlib\.decompress|gzip\.decompress|bytes\.fromhex|\\x[0-9a-f]{2})`), nil},
	{"obfuscated-exec", regexp.MustCompile(`(?i)\b(exec|eval)\s*\(\s*(base64\.|codecs\.|zlib\.|gzip\.|bz2\.|lzma\.|marshal\.|pickle\.|bytes\.fromhex|binascii\.|compile\()`), nil},
	{"obfuscated-exec", regexp.MustCompile(`(?i)\becho\s+["']?[A-Za-z0-9+/=]{40,}["']?\s*\|\s*base64\s+(-d|--decode|-D)\b`), nil},
	{"obfuscated-exec", regexp.MustCompile(`(?i)\$\(\s*(echo|printf)\s+["']?[A-Za-z0-9+/=]{16,}["']?\s*\|\s*base64\s+(-d|--decode|-D)\s*\)`), nil},
	{"obfuscated-exec", regexp.MustCompile(`(?i)\b(powershell|pwsh)(\.exe)?(\s+\S+)*\s+(-e|-ec|-enc|-encodedcommand|-encoded)\s+[A-Za-z0-9+/=]{20,}`), nil},
	{"obfuscated-exec", regexp.MustCompile(`(?i)\[System\.Convert\]::FromBase64String\s*\([^\n]*\)[^\n]*\b(iex|invoke-expression)\b|\b(iex|invoke-expression)\b[^\n]*FromBase64String`), nil},
	{"obfuscated-exec", regexp.MustCompile(`(?i)\bpython[23]?\s+-c\s+["'][^\n]*(base64|exec\(|__import__\(\s*['"]os)`), nil},
	{"obfuscated-exec", regexp.MustCompile(`(?i)\bnode\s+-e\s+["'][^\n]*(Buffer\.from\([^\n]*base64|atob\(|child_process)`), nil},
	{"obfuscated-exec", regexp.MustCompile(`(?i)\$\([^()\n]*\$\([^()\n]*(base64|curl|wget|eval)\b`), nil},
	{"obfuscated-exec", regexp.MustCompile(`(?i)\bxxd\s+-r\s+-p\b[^\n]*\|\s*(sh|bash)\b|\bopenssl\s+enc\s+-d\b[^\n]*\|\s*(sh|bash)\b|\bString\.fromCharCode\(\s*[0-9]+\s*,\s*[0-9]+\s*,\s*[0-9]+`), nil},
}

var tmpPrefixes = []string{"/tmp", "/var/tmp", "/private/tmp", "/dev/shm", "/private/var/tmp"}

// destroyTarget: the rm target is a system root, home, a glob, `..` or an absolute path outside tmp.
func destroyTarget(m []string) bool {
	t := strings.Trim(m[len(m)-1], `"'`)
	switch {
	case t == "/", t == "/*", t == "~", t == "~/", t == "~/*", t == "*", t == ".*", t == "..", t == "../", t == "$HOME",
		t == "${HOME}", t == "$HOME/", t == "$HOME/*", t == "/.", t == ".":
		return true
	case strings.HasPrefix(t, "~/") && !strings.Contains(t, "tmp"):
		return true
	case strings.HasPrefix(t, "/"):
		for _, p := range tmpPrefixes {
			if t == p || strings.HasPrefix(t, p+"/") {
				return false
			}
		}
		return true
	}
	return false
}

var defaultIndexes = []string{"pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com",
	"proxy.golang.org", "crates.io", "static.crates.io", "index.crates.io", "direct", "off"}

// untrustedIndex: the URL/index named in the command is not one of the ecosystem defaults.
func untrustedIndex(m []string) bool {
	for _, h := range defaultIndexes {
		if strings.Contains(strings.ToLower(m[0]), h) {
			return false
		}
	}
	return true
}

// Hazards classifies text into the 7 families of SPEC 4.5, in Families order, each at most once.
func Hazards(text string) []string {
	st, _ := prepare(text)
	seen := map[string]bool{}
	for _, r := range hazardRules {
		if seen[r.family] {
			continue
		}
		if r.check == nil {
			if r.re.MatchString(st) {
				seen[r.family] = true
			}
			continue
		}
		for _, m := range r.re.FindAllStringSubmatch(st, -1) {
			if r.check(m) {
				seen[r.family] = true
				break
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	var out []string
	for _, f := range Families {
		if seen[f] {
			out = append(out, f)
		}
	}
	return out
}

// HazardsLine renders a hazard list the way headers do: "exec-remote,tls-off" or "-".
func HazardsLine(h []string) string {
	if len(h) == 0 {
		return "-"
	}
	return strings.Join(h, ",")
}
