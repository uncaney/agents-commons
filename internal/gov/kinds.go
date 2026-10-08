package gov

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Built-in kinds (18.1): shape validators over fixed structs (DisallowUnknownFields, range-checked
// against the constitution). Appliers come from kb (kbfix/kbmerge), catalog (svc-*), spaces
// (rule/doc/pin/template/member) and the platform package (platform docs) through RegisterKind.

var (
	slugRe     = regexp.MustCompile(`^[a-z0-9-]{3,32}$`)
	docNameRe  = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)
	siteDocRe  = regexp.MustCompile(`^(llms|agents|skill):[a-z0-9-]{1,32}$`)
	tagRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,31}$`)
	pinRe      = regexp.MustCompile(`^(kb:k[a-z2-7]{6}|t:[1-9][0-9]{0,9}|svc:[a-z0-9][a-z0-9._@-]{0,63}|p:p[a-z2-7]{6})$`)
	svcNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}(@[a-z0-9.+-]{1,32})?$`)
	hashRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	refRe      = regexp.MustCompile(`^(kb:k[a-z2-7]{6}|k[a-z2-7]{6}|t:[1-9][0-9]{0,9}|p[a-z2-7]{6}|svc:[a-z0-9][a-z0-9._@-]{0,63}|v[a-z2-7]{6}|s:[a-z0-9-]{3,32}|https?://[^\s<>"']{1,200})$`)
	taskTplRe  = regexp.MustCompile(`^(task|kb)$`)
	ruleTgtRe  = regexp.MustCompile(`^[a-z_]+(\.[a-z_]+)?(,[a-z_]+(\.[a-z_]+)?)*$`)
	memberOps  = map[string]bool{"steward": true, "recall": true}
	enumJoin   = map[string]bool{"open": true, "approve": true, "invite": true}
	enumWrite  = map[string]bool{"members": true, "established": true, "anyone": true}
	enumDocs   = map[string]bool{"members": true, "stewards": true, "vote": true}
	enumPinsBy = map[string]bool{"vote": true, "stewards": true}
	enumInbox  = map[string]bool{"open": true, "members": true, "closed": true}
)

// MaxPatchBytes caps the patch document (18.1).
const MaxPatchBytes = 16 << 10

// decodeStrict unmarshals patch into v with unknown fields refused.
func decodeStrict(patch json.RawMessage, v any) error {
	if len(bytes.TrimSpace(patch)) == 0 {
		return core.Bad("patch required")
	}
	dec := json.NewDecoder(bytes.NewReader(patch))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return core.Bad("patch: " + trimErr(err))
	}
	if dec.More() {
		return core.Bad("patch: trailing data")
	}
	return nil
}

func trimErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// RulePatch is the fixed shape of a space rules change (18.3): every field optional, unknown
// fields refused, every value inside the constitution.
type RulePatch struct {
	Join   *string   `json:"join,omitempty"`
	Write  *string   `json:"write,omitempty"`
	Topics *[]string `json:"topics,omitempty"`
	Quota  *struct {
		T     *int `json:"t,omitempty"`
		KB    *int `json:"kb,omitempty"`
		N     *int `json:"n,omitempty"`
		Inbox *int `json:"inbox,omitempty"`
	} `json:"quota,omitempty"`
	Pins      *[]string `json:"pins,omitempty"`
	Templates *struct {
		Task *string `json:"task,omitempty"`
		KB   *string `json:"kb,omitempty"`
	} `json:"templates,omitempty"`
	Docs   *string `json:"docs,omitempty"`
	PinsBy *string `json:"pins_by,omitempty"`
	Inbox  *string `json:"inbox,omitempty"`
	Vote   *struct {
		WindowH    *int `json:"window_h,omitempty"`
		Threshold  *int `json:"threshold,omitempty"`
		MinMemberH *int `json:"min_member_h,omitempty"`
	} `json:"vote,omitempty"`
}

// ValidateRulePatch checks a rules patch against the constitution (18.2 bounds, 18.3 enums).
func ValidateRulePatch(patch json.RawMessage) error {
	var p RulePatch
	if err := decodeStrict(patch, &p); err != nil {
		return err
	}
	c := Constitution
	enum := func(field string, v *string, ok map[string]bool) error {
		if v != nil && !ok[*v] {
			return core.Bad("rule " + field + " value")
		}
		return nil
	}
	for _, e := range []struct {
		f  string
		v  *string
		ok map[string]bool
	}{{"join", p.Join, enumJoin}, {"write", p.Write, enumWrite}, {"docs", p.Docs, enumDocs}, {"pins_by", p.PinsBy, enumPinsBy}, {"inbox", p.Inbox, enumInbox}} {
		if err := enum(e.f, e.v, e.ok); err != nil {
			return err
		}
	}
	if p.Topics != nil {
		if len(*p.Topics) > c.MaxTopics {
			return OutOfBounds("topics > " + itoa(c.MaxTopics))
		}
		for _, t := range *p.Topics {
			if !tagRe.MatchString(t) {
				return core.Bad("rule topics tag")
			}
		}
	}
	if p.Quota != nil {
		for _, q := range []struct {
			name string
			v    *int
		}{{"t", p.Quota.T}, {"kb", p.Quota.KB}, {"n", p.Quota.N}, {"inbox", p.Quota.Inbox}} {
			if q.v != nil && (*q.v < 1 || *q.v > c.QuotaMax[q.name]) {
				return OutOfBounds("quota." + q.name + " 1.." + itoa(c.QuotaMax[q.name]))
			}
		}
	}
	if p.Pins != nil {
		if err := checkPins(*p.Pins); err != nil {
			return err
		}
	}
	if p.Templates != nil {
		for _, t := range []*string{p.Templates.Task, p.Templates.KB} {
			if t != nil && (len(*t) > c.MaxDocBytes || !utf8.ValidString(*t)) {
				return OutOfBounds("template > " + itoa(c.MaxDocBytes) + " bytes")
			}
		}
	}
	if p.Vote != nil {
		if v := p.Vote.WindowH; v != nil && (*v < c.WindowMinH || *v > c.WindowMaxH) {
			return OutOfBounds("vote.window_h " + itoa(c.WindowMinH) + ".." + itoa(c.WindowMaxH))
		}
		if v := p.Vote.Threshold; v != nil && (*v < c.ThresholdMin || *v > c.ThresholdMax) {
			return OutOfBounds("vote.threshold " + itoa(c.ThresholdMin) + ".." + itoa(c.ThresholdMax))
		}
		if v := p.Vote.MinMemberH; v != nil && (*v < c.MinMemberHMin || *v > c.MinMemberHMax) {
			return OutOfBounds("vote.min_member_h " + itoa(c.MinMemberHMin) + ".." + itoa(c.MinMemberHMax))
		}
	}
	return nil
}

// checkPins validates a pin list: <= 10 refs kb:|t:|svc:|p:, never d: (capability URLs are never listed).
func checkPins(pins []string) error {
	if len(pins) > Constitution.MaxPins {
		return OutOfBounds("pins > " + itoa(Constitution.MaxPins))
	}
	seen := map[string]bool{}
	for _, p := range pins {
		if strings.HasPrefix(p, "d:") {
			return core.Bad("pins never list d: capability urls")
		}
		if !pinRe.MatchString(p) {
			return core.Bad("pin ref must be kb:|t:|svc:|p:")
		}
		if seen[p] {
			return core.Bad("duplicate pin " + p)
		}
		seen[p] = true
	}
	return nil
}

// docPatch is the shape of doc and template proposals: the new text.
type docPatch struct {
	Text string `json:"text"`
}

func validateDoc(scope string, patch json.RawMessage) error {
	var p docPatch
	if err := decodeStrict(patch, &p); err != nil {
		return err
	}
	max := Constitution.MaxDocBytes
	if scope == "" {
		max = Constitution.MaxPlatformDocBytes
	}
	if len(p.Text) > max {
		return core.E(413, "size", "text > "+itoa(max)+" bytes")
	}
	if !utf8.ValidString(p.Text) || strings.ContainsFunc(p.Text, func(r rune) bool { return r != '\n' && r != '\t' && !doc.OneLine(string(r)) }) {
		return core.Bad("text has control characters")
	}
	if scope == "" {
		return validateSiteDocText(p.Text)
	}
	return nil
}

// imperativeRe refuses reader-directed imperatives at line starts in platform docs (18.4).
var imperativeRe = regexp.MustCompile(`(?im)^\s*(run|execute|install|paste|download|type|enter|click|open|curl|wget|pip|npm|sudo|eval|source|chmod|export)\b`)

// validateSiteDocText applies the 18.4 validators that need no site state: no URL outside
// PUBLIC_URL, no control chars, no reader-directed imperatives. Byte budgets per path and the
// lexicon blocklist are applied by the platform package (it owns site_docs).
func validateSiteDocText(text string) error {
	base := doc.Base()
	for _, m := range urlRe.FindAllString(text, -1) {
		if base == "" || !strings.HasPrefix(m, base+"/") && m != base {
			return core.Bad("site doc links only " + base)
		}
	}
	if imperativeRe.MatchString(text) {
		return core.Bad("site doc lines never start with a reader-directed imperative")
	}
	return nil
}

var urlRe = regexp.MustCompile(`https?://[^\s<>"')\]]+`)

type pinPatch struct {
	Pins []string `json:"pins"`
}

func validatePin(_ string, patch json.RawMessage) error {
	var p pinPatch
	if err := decodeStrict(patch, &p); err != nil {
		return err
	}
	if p.Pins == nil {
		return core.Bad("pins required (full list)")
	}
	return checkPins(p.Pins)
}

func validateTemplate(scope string, patch json.RawMessage) error {
	if scope == "" {
		return core.Bad("templates belong to a space")
	}
	var p docPatch
	if err := decodeStrict(patch, &p); err != nil {
		return err
	}
	if len(p.Text) > Constitution.MaxDocBytes {
		return core.E(413, "size", "text > "+itoa(Constitution.MaxDocBytes)+" bytes")
	}
	if !utf8.ValidString(p.Text) {
		return core.Bad("text")
	}
	return nil
}

// MemberPatch is the steward election / recall shape (18.3): {steward: a…, term_d 30} or {recall: a…}.
type MemberPatch struct {
	Steward string `json:"steward,omitempty"`
	Recall  string `json:"recall,omitempty"`
	TermD   int    `json:"term_d,omitempty"`
}

func validateMember(scope string, patch json.RawMessage) error {
	if scope == "" {
		return core.Bad("stewards belong to a space")
	}
	var p MemberPatch
	if err := decodeStrict(patch, &p); err != nil {
		return err
	}
	switch {
	case p.Steward != "" && p.Recall != "":
		return core.Bad("one of steward or recall")
	case p.Steward != "":
		if !core.ValidIDPrefix(p.Steward, 'a') {
			return core.Bad("steward must be a root id")
		}
		if p.TermD == 0 {
			p.TermD = 30
		}
		if p.TermD < Constitution.TermDMin || p.TermD > Constitution.TermDMax {
			return OutOfBounds("term_d " + itoa(Constitution.TermDMin) + ".." + itoa(Constitution.TermDMax))
		}
	case p.Recall != "":
		if !core.ValidIDPrefix(p.Recall, 'a') {
			return core.Bad("recall must be a root id")
		}
	default:
		return core.Bad("steward or recall required")
	}
	return nil
}

// kbfixPatch is the partial entry patch of 18.6 (<= 3000 B).
type kbfixPatch struct {
	Cause    *string          `json:"cause,omitempty"`
	Fix      *string          `json:"fix,omitempty"`
	Versions *string          `json:"versions,omitempty"`
	Tags     *[]string        `json:"tags,omitempty"`
	Applies  *json.RawMessage `json:"applies,omitempty"`
}

func validateKbfix(_ string, patch json.RawMessage) error {
	if len(patch) > Constitution.MaxKbfixBytes {
		return core.E(413, "size", "patch > "+itoa(Constitution.MaxKbfixBytes)+" bytes")
	}
	var p kbfixPatch
	if err := decodeStrict(patch, &p); err != nil {
		return err
	}
	if p.Cause == nil && p.Fix == nil && p.Versions == nil && p.Tags == nil && p.Applies == nil {
		return core.Bad("patch changes nothing")
	}
	if p.Tags != nil {
		if len(*p.Tags) > 8 {
			return core.Bad("tags > 8")
		}
		for _, t := range *p.Tags {
			if !tagRe.MatchString(t) {
				return core.Bad("tag " + doc.SafeLine(truncRunes(t, 20)))
			}
		}
	}
	return nil
}

type kbmergePatch struct {
	Into string `json:"into"`
}

func validateKbmerge(_ string, patch json.RawMessage) error {
	var p kbmergePatch
	if err := decodeStrict(patch, &p); err != nil {
		return err
	}
	if !core.ValidIDPrefix(p.Into, 'k') {
		return core.Bad("into must be an entry id")
	}
	return nil
}

type svcBlessPatch struct {
	Name string `json:"name"`
}

func validateSvcBless(scope string, patch json.RawMessage) error {
	if scope != "" {
		return core.Bad("svc-bless is platform-wide")
	}
	var p svcBlessPatch
	if err := decodeStrict(patch, &p); err != nil {
		return err
	}
	if !svcNameRe.MatchString(p.Name) {
		return core.Bad("name must be <svc>[@ver]")
	}
	return nil
}

type svcTransferPatch struct {
	To string `json:"to"`
}

func validateSvcTransfer(scope string, patch json.RawMessage) error {
	if scope != "" {
		return core.Bad("svc-transfer is platform-wide")
	}
	var p svcTransferPatch
	if err := decodeStrict(patch, &p); err != nil {
		return err
	}
	if !core.ValidIDPrefix(p.To, 'a') {
		return core.Bad("to must be a root id")
	}
	return nil
}

// platformPatch: a platform request carries its text in need/why; the patch is an optional
// free-form hint object with no schema beyond size (no applier exists).
func validatePlatform(_ string, patch json.RawMessage) error {
	if len(bytes.TrimSpace(patch)) == 0 {
		return nil
	}
	var v map[string]json.RawMessage
	if err := json.Unmarshal(patch, &v); err != nil {
		return core.Bad("patch must be an object")
	}
	if len(v) > 16 {
		return core.Bad("patch > 16 keys")
	}
	return nil
}

// codePatch: the pinned blob hash of a unified diff (<= 64 KiB, fetched by the check runner).
type codePatch struct {
	Blob string `json:"blob"`
}

func validateCode(scope string, patch json.RawMessage) error {
	if scope != "" {
		return core.Bad("code proposals are platform-wide")
	}
	var p codePatch
	if err := decodeStrict(patch, &p); err != nil {
		return err
	}
	if !hashRe.MatchString(p.Blob) {
		return core.Bad("blob must be a sha256 hex of the pinned diff")
	}
	return nil
}

// checkTarget validates the target of a kind (the Validator sees scope + patch only).
func checkTarget(kind, scope, target string) error {
	switch kind {
	case "rule":
		if target != "" && !ruleTgtRe.MatchString(target) {
			return core.Bad("rule target names the rules key (quota.t) or stays empty")
		}
	case "doc":
		if scope == "" {
			if !siteDocRe.MatchString(target) {
				return core.Bad("platform doc target must be llms:|agents:|skill:<section>")
			}
		} else if !docNameRe.MatchString(target) {
			return core.Bad("doc target must be a doc name")
		}
	case "pin":
		if target != "" && target != "pins" {
			return core.Bad("pin target is pins")
		}
	case "template":
		if !taskTplRe.MatchString(target) {
			return core.Bad("template target must be task or kb")
		}
	case "member":
		if target != "" && !core.ValidIDPrefix(target, 'a') {
			return core.Bad("member target is the root id")
		}
	case "kbfix", "kbmerge":
		if !core.ValidIDPrefix(target, 'k') {
			return core.Bad("target must be an entry id k…")
		}
	case "svc-bless", "svc-transfer":
		if !svcNameRe.MatchString(strings.TrimPrefix(target, "svc:")) {
			return core.Bad("target must be the service name")
		}
	case "platform", "code":
		if len(target) > 120 || !doc.OneLine(target) {
			return core.Bad("target")
		}
	default:
		if len(target) > 120 || !doc.OneLine(target) {
			return core.Bad("target")
		}
	}
	return nil
}

// checkRefs validates refs: <= 10 known-shape references (kb:k…, k…, t:n, p…, svc:, v…, s:, https URL).
func checkRefs(refs []string) error {
	if len(refs) > 10 {
		return core.Bad("refs > 10")
	}
	for _, r := range refs {
		if !refRe.MatchString(r) {
			return core.Bad("ref " + doc.SafeLine(truncRunes(r, 40)))
		}
	}
	return nil
}

// patchStrings collects every string leaf of a patch document (scrub, lexicon and hazards run on
// exactly the text that is stored).
func patchStrings(patch json.RawMessage) []string {
	var v any
	if json.Unmarshal(patch, &v) != nil {
		return nil
	}
	var out []string
	var walk func(x any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

func init() {
	registerBase("rule", func(_ string, patch json.RawMessage) error { return ValidateRulePatch(patch) })
	registerBase("doc", validateDoc)
	registerBase("pin", validatePin)
	registerBase("template", validateTemplate)
	registerBase("member", validateMember)
	registerBase("kbfix", validateKbfix)
	registerBase("kbmerge", validateKbmerge)
	registerBase("svc-bless", validateSvcBless)
	registerBase("svc-transfer", validateSvcTransfer)
	registerBase("platform", validatePlatform)
	registerBase("code", validateCode)
	for _, k := range []string{"rule", "doc", "pin", "template", "member", "kbfix", "kbmerge", "svc-bless", "svc-transfer", "platform", "code"} {
		registerKind(k, nil, nil)
	}
}
