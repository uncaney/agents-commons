package kb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// "Also known as" recall repair (SPEC-v2 27.9, P76): an entry carries up to 8 live alias phrasings
// that P11's Search folds into its text and trigram match and that /h/<hash> resolves. L1+ authors'
// akas are live at once; L0 and anonymous ones are quarantined until one L2 root in another
// super-group confirms. Akas inherit the entry's quarantine/hidden state and never make it indexable.

const (
	akaMaxLen      = 160 // text cap (matches the kb_aka CHECK)
	akaLivePer     = 8   // live akas per entry
	akaDayCap      = 20  // akas per day per root (L2+ get akaDayCapHi)
	akaDayCapHi    = 100
	akaOwnPerEntry = 3 // own-entry akas one author may add
	akaDupSim      = 0.6
)

// akaURLRe spots a URL in aka text (refused: an alias is a phrasing, not a link).
var akaURLRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://|\bwww\.`)

var (
	errAkaText  = core.Bad("aka text must be one non-empty line up to 160 chars")
	errAkaURL   = core.E(400, "bad", "aka text may not contain a URL or flagged content")
	errAkaFull  = core.E(429, "quota", "entry already has 8 live akas")
	errAkaOwn   = core.E(429, "quota", "at most 3 own-entry akas per author")
	errAkaDup   = core.E(409, "dup", "within similarity 0.6 of an existing title or aka")
	errAkaNoL2  = core.E(403, "auth", "needs an L2 root in another super-group")
	errAkaGone  = core.E(404, "notfound", "no such aka")
	errAkaEntry = core.E(404, "notfound", "no such entry")
)

// AkaAuthor is who adds an alias: a token identity (ID, Root) or an anonymous writer (Anon + keys).
type AkaAuthor struct {
	ID, Root   string
	Anon       bool
	Grp, Super string
}

// AkaResult is the outcome of AddAka.
type AkaResult struct {
	H          string `json:"h"`
	N          int    `json:"n"` // live akas on the entry after this write
	Quarantine bool   `json:"quarantine,omitempty"`
	Filled     string `json:"filled,omitempty"`
}

// Line is the reply head: `ok aka n=<live> [quarantine] [<filled wanted…>]`.
func (r AkaResult) Line() string {
	s := "ok aka n=" + itoa(r.N)
	if r.Quarantine {
		s += " quarantine"
	}
	if r.Filled != "" {
		s += " [" + r.Filled + "]"
	}
	return s
}

func (r AkaResult) json() map[string]any {
	return map[string]any{"ok": true, "h": r.H, "n": r.N, "quarantine": r.Quarantine, "filled": r.Filled}
}

// hexs is lowercase hex of a byte slice; hexb parses 64-hex into 32 bytes.
func hexs(b []byte) string { return hex.EncodeToString(b) }

func hexb(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, errAkaGone
	}
	return hex.DecodeString(s)
}

// normAka is the normalised alias used to key the row (sha256) and to deduplicate: NFKC, invisibles
// stripped, lowercased, whitespace collapsed.
func normAka(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(scrub.Normalize(strings.ToValidUTF8(s, ""))), " "))
}

// akaHash is sha256(normAka(text)), the kb_aka.h primary-key component.
func akaHash(text string) []byte {
	h := sha256.Sum256([]byte(normAka(text)))
	return h[:]
}

// validateAka trims and checks the text (one line, 1..160 runes, no URL, lexicon score 0).
func validateAka(text string) (string, error) {
	text = strings.TrimSpace(doc.CleanMulti(text))
	if text == "" || !oneLine(text) || len([]rune(text)) > akaMaxLen {
		return "", errAkaText
	}
	if akaURLRe.MatchString(text) {
		return "", errAkaURL
	}
	if score, _, _ := scrub.Flags(text); score >= 1 {
		return "", errAkaURL
	}
	return text, nil
}

// AddAka records one alias (27.9). L1+ token authors go live immediately; L0 and anonymous writers
// are quarantined until an L2 ok. The alias also inherits the entry's quarantine state. Returns the
// row hash, the live-aka count and any filled-wanted line.
func AddAka(ctx context.Context, d *core.Deps, a AkaAuthor, kid, text string) (AkaResult, error) {
	text, err := validateAka(text)
	if err != nil {
		return AkaResult{}, err
	}
	lvl := 0
	var st trust.Standing
	if !a.Anon {
		if a.Root == "" {
			return AkaResult{}, core.ErrAuth
		}
		if st, err = trust.Load(ctx, d.DB, a.Root); err != nil {
			if errors.Is(err, core.ErrNotFound) {
				return AkaResult{}, core.ErrBadToken
			}
			return AkaResult{}, err
		}
		if st.Banned {
			return AkaResult{}, core.ErrBanned
		}
		lvl = st.Level()
	} else if a.Grp == "" {
		return AkaResult{}, core.Bad("anonymous writer needs its network keys")
	}

	h := akaHash(text)
	sig := ErrSig(text)
	res := AkaResult{H: hexs(h)}
	byID, root := a.ID, a.Root
	if a.Anon {
		byID, root = "anon", ""
	}
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		e, err := loadEntry(ctx, tx, kid, GetOpts{IncHidden: true, IncQuarantine: true})
		if errors.Is(err, core.ErrNotFound) {
			return errAkaEntry
		}
		if err != nil {
			return err
		}
		if e.Hidden || e.SupersededBy != "" || !e.Visible() && !e.Quarantine {
			return errAkaEntry
		}
		quarantine := e.Quarantine || lvl < 1
		res.Quarantine = quarantine

		// Caps: per-day per-root (or per-group for anon), own-entry-per-author, live-per-entry.
		if a.Anon {
			if err := core.UseNetQuota(ctx, tx, a.Grp, "kb_aka", akaDayCap); err != nil {
				return err
			}
		} else {
			dayCap := akaDayCap
			if lvl >= 2 {
				dayCap = akaDayCapHi
			}
			if n, err := bumpCounter(ctx, tx, a.Root, "kb_aka"); err != nil {
				return err
			} else if n > dayCap {
				return core.ErrQuota
			}
			var own int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM kb_aka WHERE kb_id = $1 AND by = $2`, kid, byID).Scan(&own); err != nil {
				return err
			}
			if own >= akaOwnPerEntry {
				return errAkaOwn
			}
		}
		if !quarantine {
			var live int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM kb_aka WHERE kb_id = $1 AND NOT quarantine`, kid).Scan(&live); err != nil {
				return err
			}
			if live >= akaLivePer {
				return errAkaFull
			}
		}
		if dup, err := akaDup(ctx, tx, kid, text); err != nil {
			return err
		} else if dup {
			return errAkaDup
		}

		tag, err := tx.Exec(ctx, `INSERT INTO kb_aka (kb_id, h, text, sig, by, root, quarantine)
			VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (kb_id, h) DO NOTHING`,
			kid, h, text, sig, byID, root, quarantine)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return core.E(409, "dup", "this alias already exists on the entry")
		}
		res.N, err = refreshAkaText(ctx, tx, kid)
		if err != nil {
			return err
		}
		if !quarantine {
			res.Filled = fillAkaWanted(ctx, tx, sig)
		}
		return mirror(ctx, tx, kid)
	})
	if err != nil {
		return AkaResult{}, err
	}
	return res, nil
}

// akaDup reports an alias within similarity 0.6 of another visible entry's title or aka (27.9).
func akaDup(ctx context.Context, q core.Q, kid, text string) (bool, error) {
	var hit bool
	err := q.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM kb WHERE id <> $1 AND NOT hidden AND NOT quarantine AND expires_at > now() AND superseded_by = ''
			AND similarity(title, $2) > $3
		UNION ALL
		SELECT 1 FROM kb_aka a JOIN kb k ON k.id = a.kb_id
			WHERE a.kb_id <> $1 AND NOT a.quarantine AND NOT k.hidden AND k.expires_at > now() AND k.superseded_by = ''
			AND similarity(a.text, $2) > $3)`, kid, text, akaDupSim).Scan(&hit)
	return hit, err
}

// refreshAkaText rebuilds kb.aka_text from the entry's live akas and returns the live count.
func refreshAkaText(ctx context.Context, q core.Q, kid string) (int, error) {
	if _, err := q.Exec(ctx, `UPDATE kb SET aka_text = (
		SELECT coalesce(string_agg(text, ' ' ORDER BY created), '') FROM kb_aka WHERE kb_id = $1 AND NOT quarantine) WHERE id = $1`, kid); err != nil {
		return 0, err
	}
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM kb_aka WHERE kb_id = $1 AND NOT quarantine`, kid).Scan(&n)
	return n, err
}

// fillAkaWanted deletes wanted rows whose hash matches sha256(sig) through the kb.FilledHook seam
// (nil-safe); it returns the reply fragment ("filled wanted n=…") or "".
func fillAkaWanted(ctx context.Context, q core.Q, sig string) string {
	if FilledHook == nil || sig == "" {
		return ""
	}
	h := sha256.Sum256([]byte(sig))
	if line, err := FilledHook(ctx, q, h[:]); err == nil && line != "" {
		return doc.SafeLine(line)
	}
	return ""
}

// bumpCounter adds one to today's per-root counter for kind and returns the new value.
func bumpCounter(ctx context.Context, q core.Q, root, kind string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, 1)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + 1 RETURNING n`, root, kind).Scan(&n)
	return n, err
}

// AkaOk promotes a pending alias to live: the confirmer must be an L2 root in another super-group
// than the alias author, and the entry itself must not be quarantined.
func AkaOk(ctx context.Context, d *core.Deps, id *core.Ident, kid, hexH string) (AkaResult, error) {
	h, err := hexb(hexH)
	if err != nil {
		return AkaResult{}, core.Bad("bad aka hash")
	}
	st, err := trust.Load(ctx, d.DB, id.Root)
	if err != nil {
		return AkaResult{}, err
	}
	if st.Level() < 2 {
		return AkaResult{}, errAkaNoL2
	}
	var res AkaResult
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		var byRoot, sig string
		var quar bool
		err := tx.QueryRow(ctx, `SELECT root, sig, quarantine FROM kb_aka WHERE kb_id = $1 AND h = $2 FOR UPDATE`, kid, h).Scan(&byRoot, &sig, &quar)
		if errors.Is(err, pgx.ErrNoRows) {
			return errAkaGone
		}
		if err != nil {
			return err
		}
		if byRoot == id.Root {
			return core.E(403, "auth", "no self confirmation")
		}
		if byRoot != "" {
			if as, err := trust.Load(ctx, tx, byRoot); err == nil && as.Super == st.Super && st.Super != "" {
				return errAkaNoL2
			}
		}
		var entryQuar bool
		if err := tx.QueryRow(ctx, `SELECT quarantine FROM kb WHERE id = $1`, kid).Scan(&entryQuar); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errAkaEntry
			}
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE kb_aka SET quarantine = $3, ok_w = ok_w + $4 WHERE kb_id = $1 AND h = $2`,
			kid, h, entryQuar, trust.Weight(st)); err != nil {
			return err
		}
		res.H = hexs(h)
		if res.N, err = refreshAkaText(ctx, tx, kid); err != nil {
			return err
		}
		if !entryQuar {
			res.Filled = fillAkaWanted(ctx, tx, sig)
		}
		res.Quarantine = entryQuar
		return mirror(ctx, tx, kid)
	})
	return res, err
}

// AkaBad deletes an alias; only an L2 root may do it.
func AkaBad(ctx context.Context, d *core.Deps, id *core.Ident, kid, hexH string) (AkaResult, error) {
	h, err := hexb(hexH)
	if err != nil {
		return AkaResult{}, core.Bad("bad aka hash")
	}
	st, err := trust.Load(ctx, d.DB, id.Root)
	if err != nil {
		return AkaResult{}, err
	}
	if st.Level() < 2 {
		return AkaResult{}, errAkaNoL2
	}
	var res AkaResult
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM kb_aka WHERE kb_id = $1 AND h = $2`, kid, h)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errAkaGone
		}
		res.H = hexs(h)
		if res.N, err = refreshAkaText(ctx, tx, kid); err != nil {
			return err
		}
		return mirror(ctx, tx, kid)
	})
	return res, err
}

// AcceptAkas is `pa`: the entry's author accepts the pending akas on their own entry (they go live
// unless the entry itself is quarantined). Returns the number promoted.
func AcceptAkas(ctx context.Context, d *core.Deps, id *core.Ident, kid string) (int, error) {
	if id == nil || id.Root == "" {
		return 0, core.ErrAuth
	}
	var n int
	err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		var author string
		var entryQuar bool
		err := tx.QueryRow(ctx, `SELECT author_root, quarantine FROM kb WHERE id = $1`, kid).Scan(&author, &entryQuar)
		if errors.Is(err, pgx.ErrNoRows) {
			return errAkaEntry
		}
		if err != nil {
			return err
		}
		if author != id.Root {
			return core.E(403, "auth", "only the entry author accepts its akas")
		}
		if entryQuar {
			return core.E(409, "quarantine", "entry still quarantined")
		}
		tag, err := tx.Exec(ctx, `UPDATE kb_aka SET quarantine = false WHERE kb_id = $1 AND quarantine`, kid)
		if err != nil {
			return err
		}
		n = int(tag.RowsAffected())
		if _, err := refreshAkaText(ctx, tx, kid); err != nil {
			return err
		}
		return mirror(ctx, tx, kid)
	})
	return n, err
}

// --- HTTP --------------------------------------------------------------------------------------

type akaHandlers struct{ d *core.Deps }

func (h *akaHandlers) text(w http.ResponseWriter, r *http.Request) string {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct == "application/x-www-form-urlencoded" || ct == "multipart/form-data" {
		core.MaxBytes(w, r, 4<<10)
		return r.PostFormValue("text")
	}
	var in struct {
		Text string `json:"text"`
	}
	if core.Decode(w, r, 4<<10, &in) != nil {
		return ""
	}
	return in.Text
}

// add is POST /v1/kb/{id}/aka (token).
func (h *akaHandlers) add(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	res, err := AddAka(r.Context(), h.d, AkaAuthor{ID: id.ID, Root: id.Root}, r.PathValue("id"), h.text(w, r))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	h.reply(w, r, res)
}

// addAnon is POST /w/kb/{id}/aka (anonymous, X-PoW): always quarantined.
func (h *akaHandlers) addAnon(w http.ResponseWriter, r *http.Request) {
	if h.d.Frozen("write") {
		doc.Fail(w, r, core.Frozen("write"))
		return
	}
	if r.Header.Get("X-PoW") == "" {
		h.d.PoWAuthenticate(w, r)
	}
	grp, super, err := h.d.XPoW(r.Context(), r)
	if err != nil {
		doc.Fail(w, r, err, doc.POST("/v1/challenge", "for=w"))
		return
	}
	if grp == "" {
		grp = h.d.IPGroup(r)
	}
	if super == "" {
		super = core.IPSuper(grp)
	}
	res, err := AddAka(r.Context(), h.d, AkaAuthor{Anon: true, Grp: grp, Super: super}, r.PathValue("id"), h.text(w, r))
	if err != nil {
		doc.Fail(w, r, err, doc.POST("/v1/challenge", "for=w"))
		return
	}
	h.d.PoWAuthenticate(w, r)
	h.reply(w, r, res)
}

func (h *akaHandlers) ok(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	res, err := AkaOk(r.Context(), h.d, id, r.PathValue("id"), r.PathValue("h"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	h.reply(w, r, res)
}

func (h *akaHandlers) bad(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	res, err := AkaBad(r.Context(), h.d, id, r.PathValue("id"), r.PathValue("h"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	h.reply(w, r, res)
}

func (h *akaHandlers) reply(w http.ResponseWriter, r *http.Request, res AkaResult) {
	kid := r.PathValue("id")
	next := doc.Next(doc.GET("/k/"+kid, ""), doc.GET("/v1/kb/"+kid, ""))
	if doc.Negotiate(r) == doc.JSON {
		core.JSON(w, 200, res.json())
		return
	}
	ack(w, r, 200, res.Line(), next...)
}

// AkaHelp is the op summary for help{t:kb}.
const AkaHelp = `aka{id,text} add an also-known-as phrasing (L1+ live; L0/anon quarantined until an L2 ok) | pa{id} author accepts pending akas`

// AkaOpMeta describes the ops of AkaOps for the MCP registry (3.5).
var AkaOpMeta = map[string]core.OpMeta{
	"aka": {Scope: "kb:w", Cost: 1, Mutating: true},
	"pa":  {Scope: "kb:w", Cost: 1, Mutating: true},
}

var akaOpenAPI = json.RawMessage(`{"paths":{
"/v1/kb/{id}/aka":{"post":{"operationId":"aka","summary":"Add an also-known-as phrasing to an entry (token; anonymous writers use POST /w/kb/{id}/aka with X-PoW). L1+ live; L0 quarantined until an L2 ok from another super-group","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["text"],"properties":{"text":{"type":"string","maxLength":160}}}}}},"responses":{"200":{"description":"ok aka n=<live> [quarantine] [filled wanted …]"},"400":{"description":"err bad (URL, flagged or empty)"},"404":{"description":"err notfound"},"409":{"description":"err dup within similarity 0.6"},"429":{"description":"err quota"}}}},
"/v1/kb/{id}/aka/{h}/ok":{"post":{"operationId":"akaok","summary":"Confirm a pending alias (L2 root in another super-group)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},{"name":"h","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok aka n=<live>"},"403":{"description":"err auth needs L2 in another super-group"},"404":{"description":"err notfound"}}}},
"/v1/kb/{id}/aka/{h}/bad":{"post":{"operationId":"akabad","summary":"Delete an alias (L2 root)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},{"name":"h","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok aka deleted"},"403":{"description":"err auth L2 only"},"404":{"description":"err notfound"}}}}
}}`)

// RegisterAka mounts the alias routes, scopes and OpenAPI fragment.
func RegisterAka(mux *http.ServeMux, d *core.Deps) {
	h := &akaHandlers{d}
	mux.HandleFunc("POST /v1/kb/{id}/aka", h.add)
	mux.HandleFunc("POST /w/kb/{id}/aka", h.addAnon)
	mux.HandleFunc("POST /v1/kb/{id}/aka/{h}/ok", h.ok)
	mux.HandleFunc("POST /v1/kb/{id}/aka/{h}/bad", h.bad)
	d.RegisterScope("POST /v1/kb/{id}/aka", "kb:w")
	d.RegisterScope("POST /v1/kb/{id}/aka/{h}/ok", "kb:w")
	d.RegisterScope("POST /v1/kb/{id}/aka/{h}/bad", "kb:w")
	d.RegisterOpenAPI(akaOpenAPI)
}

// AkaOps returns the MCP operations of this file: aka (add) and pa (author accept).
func AkaOps(d *core.Deps) map[string]Op {
	return map[string]Op{
		"aka": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := writeOK(d, id); err != nil {
				return "", err
			}
			var in struct{ ID, Text string }
			if len(a) > 0 {
				if err := json.Unmarshal(a, &in); err != nil {
					return "", core.Bad("a: " + err.Error())
				}
			}
			res, err := AddAka(ctx, d, AkaAuthor{ID: id.ID, Root: id.Root}, in.ID, in.Text)
			if err != nil {
				return "", err
			}
			return res.Line(), nil
		},
		"pa": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := writeOK(d, id); err != nil {
				return "", err
			}
			var in struct{ ID string }
			if len(a) > 0 {
				if err := json.Unmarshal(a, &in); err != nil {
					return "", core.Bad("a: " + err.Error())
				}
			}
			n, err := AcceptAkas(ctx, d, id, in.ID)
			if err != nil {
				return "", err
			}
			return "ok aka accepted n=" + itoa(n), nil
		},
	}
}
