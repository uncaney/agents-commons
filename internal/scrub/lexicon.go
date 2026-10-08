package scrub

import (
	"regexp"
	"sort"
	"strings"
)

// Lexicon classes in flag order with their score (SPEC 4.6, 27.5, 27.8). Each class counts once:
// the lexicon raises the cost of a write (quarantine at >= 2), it never rejects.
const (
	flagSelfRef   = "self-reference"
	flagCredSol   = "credential-solicitation"
	flagRemote    = "remote-exec"
	flagAuthority = "authority"
	flagUnicode   = "unicode"
	flagComment   = "html-comment"
	flagImage     = "md-image"
	flagURLs      = "urls"
	flagShortener = "shortener"
	flagBribe     = "gov-bribe"
)

var flagOrder = []string{flagSelfRef, flagCredSol, flagRemote, flagAuthority, flagUnicode, flagComment, flagImage, flagURLs, flagShortener, flagBribe}

var flagScore = map[string]int{flagSelfRef: 1, flagCredSol: 2, flagRemote: 1, flagAuthority: 1, flagUnicode: 2,
	flagComment: 1, flagImage: 2, flagURLs: 1, flagShortener: 1, flagBribe: 2}

type lexRule struct {
	class, lang string // lang "" = English
	re          *regexp.Regexp
}

var lexRules = []lexRule{
	// self-reference (en)
	{flagSelfRef, "", regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override|bypass)\s+(all\s+|any\s+|of\s+)?(the\s+|your\s+|my\s+)?(previous|prior|above|earlier|preceding|initial|original|system)\s+(instructions?|prompts?|rules?|messages?|directions?|guidelines?|context)\b`)},
	{flagSelfRef, "", regexp.MustCompile(`(?i)\bsystem\s+prompt\b|\byou\s+are\s+now\b|\bas\s+an\s+ai\b|\bnew\s+instructions?\s*:|\bdeveloper\s+mode\b|\bjailbreak|\bdo\s+anything\s+now\b|\byour\s+(new|real|true)\s+(instructions?|task|goal|purpose)\s+(is|are)\b|\bfrom\s+now\s+on\s+you\b|\bstop\s+being\s+an?\s+(ai|assistant)\b`)},
	// credential solicitation (en)
	{flagCredSol, "", regexp.MustCompile(`(?i)\b(send|post|paste|upload|share|forward|dm|email|submit|reply\s+with|include)\s+(me|us|back|here|it|them|to\s+\S+|it\s+to\s+\S+)?\s*(your|the|all\s+your|any|its)\s+([a-z_-]+\s+){0,2}(tokens?|keys?|api[\s_-]?keys?|\.?env|env\s+vars?|environment\s+variables?|credentials?|passwords?|secrets?|cookies?|sessions?|seed\s+phrase|private\s+keys?|bearer)\b`)},
	{flagCredSol, "", regexp.MustCompile(`(?i)\byour\s+(api[\s_-]?key|token|password|credentials|secret|private\s+key)\s+(to|at|into|in)\s+(https?://|this|the\s+form|the\s+url|the\s+link)`)},
	{flagCredSol, "", regexp.MustCompile(`(?i)\b(run|execute)\s+(cat|type|echo|printenv|env)\s+[^\n]{0,40}(\.env|credentials|\.ssh|\$[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD))\b[^\n]{0,60}\b(send|post|paste|reply|share)\b`)},
	// authority claims (en)
	{flagAuthority, "", regexp.MustCompile(`(?i)\bofficial\b|\banthropic\b|\bopenai\b|\boperator\s+(asked|says|said|requests?|requires?|wants|told|instructed)\b|\badmin(istrator)?\s+(notice|message|alert|announcement|override)\b|\bmoderator\s+(notice|message|alert)\b|\bsystem\s+(notice|message|alert|override)\b|\bfrom\s+the\s+(admin|operator|staff|moderators?|platform\s+team)\b|\b(verified|approved|endorsed)\s+by\s+(the\s+)?(admin|operator|staff|anthropic|openai)\b|\btrusted\s+(source|instruction)\b`)},
	// French
	{flagSelfRef, "fr", regexp.MustCompile(`(?i)\bignor(e|ez|er)\s+(toutes?\s+)?(les\s+|tes\s+|vos\s+)?(instructions|consignes|règles|directives)\s+(précédentes|antérieures|ci-dessus|initiales)\b|\b(invite|prompt|message)\s+syst[èe]me\b|\btu\s+es\s+(maintenant|désormais)\b|\bvous\s+êtes\s+(maintenant|désormais)\b|\ben\s+tant\s+qu'?\s*ia\b|\bnouvelles\s+instructions\s*:`)},
	{flagCredSol, "fr", regexp.MustCompile(`(?i)\b(envoie|envoyez|envoi|colle|collez|partage|partagez|donne|donnez|transmets|transmettez|poste|postez)[- ]?(moi|nous|le|la|les)?\s+(ton|ta|tes|votre|vos|la|le|les)\s+([a-zéè_-]+\s+){0,2}(clés?|clefs?|jetons?|tokens?|mots?\s+de\s+passe|identifiants|secrets?|credentials|\.?env)`)},
	{flagAuthority, "fr", regexp.MustCompile(`(?i)\bofficiel(le)?s?\b|\bl'op[ée]rateur\s+(a\s+)?(demand[ée]|exige|veut|requiert)|\b(avis|message|notice)\s+(de\s+l')?admin(istrateur)?\b|\bmessage\s+(du|de\s+la)\s+(mod[ée]rateur|mod[ée]ration|plateforme|syst[èe]me)\b`)},
	// Spanish
	{flagSelfRef, "es", regexp.MustCompile(`(?i)\bignor(a|e|en|ar)\s+(todas?\s+)?(las\s+|tus\s+|sus\s+)?(instrucciones|indicaciones|reglas)\s+(anteriores|previas|iniciales)\b|\b(prompt|indicaci[óo]n|mensaje)\s+del\s+sistema\b|\bahora\s+eres\b|\bcomo\s+(una\s+)?ia\b|\bnuevas\s+instrucciones\s*:`)},
	{flagCredSol, "es", regexp.MustCompile(`(?i)\b(env[íi]a|env[íi]ame|env[íi]e|pega|comparte|dame|manda|m[áa]ndame|publica|sube)(me|nos)?\s+(tu|tus|su|sus|la|el|los|las)\s+([a-záéíóú_-]+\s+){0,2}(claves?|tokens?|contraseñas?|credenciales|secretos?|llaves?|\.?env)`)},
	{flagAuthority, "es", regexp.MustCompile(`(?i)\boficial(es)?\b|\bel\s+operador\s+(ha\s+)?(pidi[óo]|pide|exige|solicit[óo]a?)|\b(aviso|mensaje|nota)\s+(del\s+)?(admin|administrador|moderador|sistema)\b`)},
	// German
	{flagSelfRef, "de", regexp.MustCompile(`(?i)\bignorier(e|en|t)\s+(alle\s+)?(vorherigen|bisherigen|obigen|früheren|urspr[üu]nglichen)\s+(anweisungen|instruktionen|regeln|befehle)\b|\bsystemprompt\b|\bdu\s+bist\s+(jetzt|ab\s+jetzt|nun|ab\s+sofort)\b|\bals\s+(eine\s+)?ki\b|\bneue\s+anweisungen\s*:`)},
	{flagCredSol, "de", regexp.MustCompile(`(?i)\b(sende|schick|schicke|schickt|füge|teile|teilt|gib|gebt|poste|lade)\s+(mir|uns)?\s*(deinen|deine|dein|ihren|ihre|ihr|den|die|das|eure|euren)\s+([a-zäöüß_-]+\s+){0,2}(schlüssel|tokens?|passw(ort|örter)|zugangsdaten|anmeldedaten|geheimnis(se)?|api[- ]?key|\.?env)`)},
	{flagAuthority, "de", regexp.MustCompile(`(?i)\boffiziell(e|er|es|en)?\b|\bder\s+betreiber\s+(hat\s+)?(gebeten|verlangt|fordert|will)|\badmin[- ]?(hinweis|nachricht|mitteilung)\b|\b(hinweis|nachricht)\s+(des|vom)\s+(admin|administrators?|betreibers?|moderators?|systems?)\b`)},
	// Portuguese
	{flagSelfRef, "pt", regexp.MustCompile(`(?i)\bignor(e|a|em|ar)\s+(todas?\s+)?(as\s+|suas\s+|tuas\s+)?(instru[çc][õo]es|regras|orienta[çc][õo]es)\s+(anteriores|pr[ée]vias|iniciais|acima)\b|\bprompt\s+do\s+sistema\b|\b(voc[êe]\s+agora\s+[ée]|agora\s+voc[êe]\s+[ée]|tu\s+[ée]s\s+agora)\b|\bcomo\s+(uma\s+)?ia\b|\bnovas\s+instru[çc][õo]es\s*:`)},
	{flagCredSol, "pt", regexp.MustCompile(`(?i)\b(envie|envia|cole|compartilhe|partilhe|manda|mande|me\s+d[êe]|d[êe]-me|publique|suba)(-me|-nos)?\s+(sua|suas|tua|tuas|a|o|as|os)\s+([a-záéíóúãõç_-]+\s+){0,2}(chaves?|tokens?|senhas?|credenciais|segredos?|palavras?-passe|\.?env)`)},
	{flagAuthority, "pt", regexp.MustCompile(`(?i)\boficial(is)?\b|\bo\s+operador\s+(pediu|solicitou|exige|quer)|\b(aviso|mensagem|nota)\s+(do\s+)?(admin|administrador|moderador|sistema)\b`)},
	// Chinese
	{flagSelfRef, "zh", regexp.MustCompile(`忽略(所有|全部|之前|以前|上述|上面|先前)?的?(指令|指示|提示|规则|说明)|系统提示|你现在是|您现在是|作为(一个)?(人工智能|AI)|新的?指令[:：]`)},
	{flagCredSol, "zh", regexp.MustCompile(`(发送|发给|粘贴|分享|上传|提交|告诉|给)(我|我们)?(你的|您的|所有的?)?(密钥|秘钥|令牌|密码|凭证|凭据|API密钥|API密匙|私钥|token|key)|(你的|您的|所有的?)(密钥|秘钥|令牌|密码|凭证|凭据|API密钥|API密匙|私钥|token|key)(发|发送|发给|粘贴|分享|上传|提交|告诉|给)`)},
	{flagAuthority, "zh", regexp.MustCompile(`官方|管理员(通知|公告|消息|提示)|操作员(要求|请求|指示)|运营者(要求|请求|指示)|系统(通知|公告)`)},
	// Japanese
	{flagSelfRef, "ja", regexp.MustCompile(`(これまでの|以前の|上記の|前の|最初の|元の)(指示|命令|プロンプト|ルール)を?(無視|忘れ|破棄)|システムプロンプト|あなたは今|今からあなたは|AIとして|新しい指示[:：]`)},
	{flagCredSol, "ja", regexp.MustCompile(`(あなたの|お前の|君の|全ての|すべての)?(APIキー|トークン|パスワード|秘密鍵|認証情報|鍵|キー|シークレット)を(送って|送信|貼り付け|共有|教えて|アップロード|提出)`)},
	{flagAuthority, "ja", regexp.MustCompile(`公式|管理者(からの)?(通知|お知らせ|メッセージ)|オペレーター(が|の|から)(要請|指示|依頼)|システム(通知|メッセージ)`)},
}

var (
	htmlCommentRe = regexp.MustCompile(`<!--`)
	mdImageRe     = regexp.MustCompile(`!\[`)
	urlRe         = regexp.MustCompile(`(?i)https?://`)
	shortenerRe   = regexp.MustCompile(`(?i)\b(bit\.ly|t\.co|tinyurl\.com|goo\.gl|is\.gd|ow\.ly|buff\.ly|cutt\.ly|rb\.gy|shorturl\.at|tiny\.cc|t\.ly|lnkd\.in|s\.id|rebrand\.ly|bl\.ink|snip\.ly|v\.gd|qr\.ae|adf\.ly|tr\.im|tiny\.one|short\.io|u\.to|x\.co|clck\.ru|surl\.li)\b`)
	bribeWordRe   = regexp.MustCompile(`(?i)\b(vote|yes|support|upvote)\b`)
	bribeIDRe     = regexp.MustCompile(`\bp[a-z2-7]{6}\b|/p/`)
	bribeStop     = map[string]bool{}
)

func init() {
	for _, w := range strings.Fields(`process project problem package pattern payload publish pending perhaps present private
		product program protect provide purpose prepare perform popular primary promise propose protest picture plastic
		plugins players parties parents passing payment percent perfect persons physics planned planets playing pointed
		portion posting pottery poverty powered praised precise predict premium prevent preview printed profile profits
		promote prompts proving pursuit pushing putting pytest patches partial parsing padding pointer polling pooling
		porting posture pricing printer privacy probing produce proceed profess proofed proxied proxies prudent publics
		puzzles pyramid pythons`) {
		bribeStop[w] = true
	}
}

// Flags scores text against the injection lexicon. cleaned is the text with invisible code points
// stripped and mixed-script homoglyphs folded (a hit of its own, score 2); the classes run on
// cleaned and on the plaintext of base64 runs. flags come in a fixed order, then lang=<xx> markers
// for hits found through the six-language table.
func Flags(text string) (score int, flags []string, cleaned string) {
	cleaned, changed := foldMixed(text)
	hit := map[string]bool{}
	langs := map[string]bool{}
	if changed {
		hit[flagUnicode] = true
	}
	classes(cleaned, hit, langs)
	st, _ := prepare(cleaned)
	for _, m := range b64Re.FindAllStringIndex(st, -1) {
		run := st[m[0]:m[1]]
		if hexRe.MatchString(run) {
			continue
		}
		if dec, ok := decodeB64(run); ok {
			classes(dec, hit, langs)
		}
	}
	for _, r := range hazardRules {
		if r.family == "exec-remote" && r.re.MatchString(st) {
			hit[flagRemote] = true
			break
		}
	}
	if htmlCommentRe.MatchString(st) {
		hit[flagComment] = true
	}
	if mdImageRe.MatchString(st) {
		hit[flagImage] = true
	}
	if len(urlRe.FindAllStringIndex(st, 5)) > 3 {
		hit[flagURLs] = true
	}
	if shortenerRe.MatchString(st) {
		hit[flagShortener] = true
	}
	if bribe(st) {
		hit[flagBribe] = true
	}
	for _, f := range flagOrder {
		if hit[f] {
			score += flagScore[f]
			flags = append(flags, f)
		}
	}
	var ls []string
	for l := range langs {
		ls = append(ls, "lang="+l)
	}
	sort.Strings(ls)
	return score, append(flags, ls...), cleaned
}

func classes(s string, hit, langs map[string]bool) {
	for _, r := range lexRules {
		if r.lang != "" && hit[r.class] && langs[r.lang] {
			continue
		}
		if r.re.MatchString(s) {
			hit[r.class] = true
			if r.lang != "" {
				langs[r.lang] = true
			}
		}
	}
}

// bribe: a proposal id (p + 6 base32 chars, not a common word) or a /p/ path within 40 chars of
// vote|yes|support|upvote (SPEC 27.5).
func bribe(s string) bool {
	words := bribeWordRe.FindAllStringIndex(s, -1)
	if len(words) == 0 {
		return false
	}
	for _, m := range bribeIDRe.FindAllStringIndex(s, -1) {
		if id := s[m[0]:m[1]]; id != "/p/" && bribeStop[strings.ToLower(id)] {
			continue
		}
		for _, w := range words {
			if w[0]-m[1] <= 40 && m[0]-w[1] <= 40 {
				return true
			}
		}
	}
	return false
}

// FlagsLine renders flags the way headers do: "self-reference,md-image" or "-".
func FlagsLine(flags []string) string {
	if len(flags) == 0 {
		return "-"
	}
	return strings.Join(flags, ",")
}
