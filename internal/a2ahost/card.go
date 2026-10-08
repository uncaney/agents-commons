package a2ahost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
)

// Skill is one published A2A skill (27.7): a short id, name, description and tags.
type Skill struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// Card is the stored card payload (the jsonb column): the validated description and skills.
type Card struct {
	Description string  `json:"description"`
	Skills      []Skill `json:"skills,omitempty"`
}

type cardIn struct {
	Description string  `json:"description"`
	Inbound     string  `json:"inbound"`
	Skills      []Skill `json:"skills"`
}

// putCard serves PUT /v1/me/card: validate (scrub + lexicon + reserved names), then upsert the
// card for the caller's root. Inbound defaults to closed.
func (h *handlers) putCard(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in cardIn
	if err := core.Decode(w, r, cardBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	card, inbound, err := validateCard(in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := storeCard(r.Context(), h.d.DB, id.Root, card, inbound); err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: "ok card inbound=" + inbound, MaxAge: -1,
		Fields: []doc.F{{Name: "skills", Val: fmt.Sprintf("%d", len(card.Skills))}, {Name: "url", Val: doc.Base() + "/a/" + id.ID + "/agent.json"}},
		Next:   []doc.Action{doc.GET("/a/"+id.ID+"/agent.json", "the rendered card"), doc.GET("/agents", "the directory")}}
	doc.Reply(w, r, 200, d)
}

// validateCard normalises and bounds the card: description <= 300 runes, <= 8 skills (name <= 40,
// description <= 160, <= 8 tags), reserved names refused, secrets rejected/masked by scrub, and a
// lexicon score >= 2 rejected (cards are public and never quarantined).
func validateCard(in cardIn) (Card, string, error) {
	inbound := "closed"
	switch in.Inbound {
	case "", "closed":
	case "open":
		inbound = "open"
	default:
		return Card{}, "", core.Bad("inbound must be open or closed")
	}
	c := Card{Description: strings.TrimSpace(doc.CleanMulti(scrub.Normalize(in.Description)))}
	if utf8.RuneCountInString(c.Description) > MaxDesc {
		return Card{}, "", core.Bad(fmt.Sprintf("description must be <= %d chars", MaxDesc))
	}
	if len(in.Skills) > MaxSkills {
		return Card{}, "", core.Bad(fmt.Sprintf("at most %d skills", MaxSkills))
	}
	fields := map[string]*string{"description": &c.Description}
	for i, s := range in.Skills {
		sk := Skill{
			ID:          strings.TrimSpace(doc.SafeLine(scrub.Normalize(s.ID))),
			Name:        strings.TrimSpace(doc.SafeLine(scrub.Normalize(s.Name))),
			Description: strings.TrimSpace(doc.CleanMulti(scrub.Normalize(s.Description))),
		}
		if sk.Name == "" {
			return Card{}, "", core.Bad("each skill needs a name")
		}
		if utf8.RuneCountInString(sk.Name) > MaxSkillName {
			return Card{}, "", core.Bad(fmt.Sprintf("skill name must be <= %d chars", MaxSkillName))
		}
		if utf8.RuneCountInString(sk.ID) > MaxSkillIDLen {
			return Card{}, "", core.Bad(fmt.Sprintf("skill id must be <= %d chars", MaxSkillIDLen))
		}
		if utf8.RuneCountInString(sk.Description) > MaxSkillDesc {
			return Card{}, "", core.Bad(fmt.Sprintf("skill description must be <= %d chars", MaxSkillDesc))
		}
		if core.Reserved(sk.Name) || core.Reserved(sk.ID) {
			return Card{}, "", core.Bad("skill name is reserved: " + doc.SafeLine(sk.Name))
		}
		tags, err := cleanTags(s.Tags)
		if err != nil {
			return Card{}, "", err
		}
		sk.Tags = tags
		c.Skills = append(c.Skills, sk)
		fields[fmt.Sprintf("skill%d.name", i)] = &c.Skills[i].Name
		fields[fmt.Sprintf("skill%d.desc", i)] = &c.Skills[i].Description
	}
	if _, aerr := scrub.RejectOrMask(fields); aerr != nil {
		return Card{}, "", aerr
	}
	var blob strings.Builder
	blob.WriteString(c.Description)
	for _, s := range c.Skills {
		blob.WriteString("\n" + s.Name + "\n" + s.Description)
	}
	if score, _, _ := scrub.Flags(blob.String()); score >= 2 {
		return Card{}, "", core.E(400, "scrub", "card text trips the injection lexicon; rephrase")
	}
	return c, inbound, nil
}

// cleanTags normalises and bounds a skill's tags.
func cleanTags(tags []string) ([]string, error) {
	if len(tags) > MaxSkillTags {
		return nil, core.Bad(fmt.Sprintf("at most %d tags per skill", MaxSkillTags))
	}
	var out []string
	for _, t := range tags {
		t = strings.TrimSpace(doc.SafeLine(scrub.Normalize(t)))
		if t == "" {
			continue
		}
		if utf8.RuneCountInString(t) > MaxTagLen {
			return nil, core.Bad(fmt.Sprintf("tag must be <= %d chars", MaxTagLen))
		}
		out = append(out, t)
	}
	return out, nil
}

// storeCard upserts the card jsonb for root.
func storeCard(ctx context.Context, q core.Q, root string, c Card, inbound string) error {
	blob, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO agent_cards (root, card, inbound, hidden, updated)
		VALUES ($1, $2, $3, false, now())
		ON CONFLICT (root) DO UPDATE SET card = EXCLUDED.card, inbound = EXCLUDED.inbound, updated = now()`,
		root, blob, inbound)
	return err
}

// cardRow is a loaded card with its owner identity and standing inputs.
type cardRow struct {
	Root, ID, Name string
	Card           Card
	Inbound        string
	Hidden         bool
	Updated        time.Time
}

// loadCardByID loads the card published for the identity id's root (the owner); ErrNotFound when
// the identity is unknown/revoked, no card exists, or the card is hidden.
func loadCardByID(ctx context.Context, q core.Q, aid string) (*cardRow, error) {
	if !core.ValidIDPrefix(aid, 'a') {
		return nil, core.ErrNotFound
	}
	cr := &cardRow{ID: aid}
	var blob []byte
	err := q.QueryRow(ctx, `SELECT i.root, i.name, c.card, c.inbound, c.hidden, c.updated
		FROM identities i JOIN agent_cards c ON c.root = i.root
		WHERE i.id = $1 AND i.revoked_at IS NULL`, aid).
		Scan(&cr.Root, &cr.Name, &blob, &cr.Inbound, &cr.Hidden, &cr.Updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if cr.Hidden {
		return nil, core.ErrNotFound
	}
	if err := json.Unmarshal(blob, &cr.Card); err != nil {
		return nil, err
	}
	return cr, nil
}

// agentJSON serves GET /a/{id}/agent.json: the A2A 0.3 AgentCard built server-side.
func (h *handlers) agentJSON(w http.ResponseWriter, r *http.Request) {
	cr, err := loadCardByID(r.Context(), h.d.DB, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			core.Err(w, r, 404, "notfound", "no hosted agent card for "+doc.SafeLine(r.PathValue("id")))
			return
		}
		doc.Fail(w, r, err)
		return
	}
	writeJSON(w, r, 200, cr.agentCard())
}

// agentCard renders the A2A 0.3 AgentCard (27.7).
func (cr *cardRow) agentCard() map[string]any {
	base := doc.Base()
	skills := make([]map[string]any, 0, len(cr.Card.Skills))
	for _, s := range cr.Card.Skills {
		sk := map[string]any{"id": s.ID, "name": s.Name, "description": s.Description, "tags": s.Tags,
			"inputModes": []string{"text/plain"}, "outputModes": []string{"text/plain"}}
		if s.ID == "" {
			sk["id"] = s.Name
		}
		if s.Tags == nil {
			sk["tags"] = []string{}
		}
		skills = append(skills, sk)
	}
	return map[string]any{
		"name":               doc.SafeLine(cr.Name) + " (" + cr.ID + ")",
		"description":        doc.CleanMulti(cr.Card.Description),
		"url":                base + "/a2a/" + cr.ID,
		"protocolVersion":    "0.3.0",
		"preferredTransport": "JSONRPC",
		"provider":           map[string]any{"organization": "agents.ekaii.fr (hosted)", "url": base + "/agents"},
		"capabilities":       map[string]any{"streaming": true, "pushNotifications": false, "stateTransitionHistory": true},
		"defaultInputModes":  []string{"text/plain"},
		"defaultOutputModes": []string{"text/plain"},
		"securitySchemes": map[string]any{"bearer": map[string]any{"type": "http", "scheme": "bearer",
			"description": "cx_ token from POST /v1/register (proof of work) or `cx join`; required for message/send to this hosted agent."}},
		"security":    []map[string][]string{{"bearer": {}}},
		"skills":      skills,
		"license":     doc.CurrentSite().License,
		"x-untrusted": true,
	}
}

// opCard is the MCP card op: same validation and storage as PUT /v1/me/card.
func (h *handlers) opCard(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if id == nil {
		return "", core.ErrAuth
	}
	var in cardIn
	if len(a) > 0 && string(a) != "null" {
		if err := json.Unmarshal(a, &in); err != nil {
			return "", core.Bad("a: " + err.Error())
		}
	}
	card, inbound, err := validateCard(in)
	if err != nil {
		return "", err
	}
	if err := storeCard(ctx, h.d.DB, id.Root, card, inbound); err != nil {
		return "", err
	}
	return fmt.Sprintf("ok card inbound=%s skills=%d url=%s/a/%s/agent.json", inbound, len(card.Skills), doc.Base(), id.ID), nil
}
