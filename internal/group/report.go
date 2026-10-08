package group

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/scrub"
)

// report is POST /v1/g/{gid}/report: the group variant of the recipient-reveal report path (26.3,
// E2EE 8.3). A current OR former member (reports by former members are why the tomb is kept 12
// months) reveals the franking key kf and the plaintext of one app row; the server recomputes the
// franking commitment C over the bytes it is shown, and only on a match opens that one message in
// memory, runs scrub over it, and stores kinds, score and sha256 (90 d) in grp_evidence — never the
// text. A tier-1 secret or a scrub finding makes the report upheld. The operator never holds a key.
func (s *svc) report(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	gid := r.PathValue("gid")
	if !core.ValidIDPrefix(gid, 'g') {
		core.Fail(w, r, core.Bad("gid must be a group id"))
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		core.Fail(w, r, core.Bad("read"))
		return
	}
	var in struct {
		Seq     int64  `json:"seq"`
		KF      string `json:"kf"`
		CType   int    `json:"ctype"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		core.Fail(w, r, core.Bad("body: "+err.Error()))
		return
	}
	kf, err := decodeB64(in.KF)
	if err != nil || len(kf) != 32 {
		core.Fail(w, r, core.Bad("kf must be the 32-byte franking key (base64url)"))
		return
	}
	payload, err := decodeB64(in.Payload)
	if err != nil {
		core.Fail(w, r, core.Bad("payload must be base64url"))
		return
	}
	if in.CType < 1 || in.CType > 255 {
		core.Fail(w, r, core.Bad("ctype must be 1..255"))
		return
	}
	// The reporter must be, or have been, a member of this group.
	member, err := reporterStanding(r.Context(), s.d.DB, gid, id.ID)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if !member {
		core.Fail(w, r, core.E(403, "roster", "reports come from current or former members"))
		return
	}
	// Load the row's cleartext header: the franking commitment C and the (epoch, idx, gen) it binds.
	var hdr []byte
	var kind int16
	err = s.d.DB.QueryRow(r.Context(), `SELECT hdr, kind FROM grp_rows WHERE gid = $1 AND seq = $2`, gid, in.Seq).Scan(&hdr, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		core.Fail(w, r, core.E(404, "notfound", "no row at this seq"))
		return
	}
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if kind != e2e.GKindApp {
		core.Fail(w, r, core.Bad("only an app message carries a franking commitment"))
		return
	}
	h, err := e2e.ParseGHdr(hdr)
	if err != nil {
		core.Fail(w, r, errBadRow)
		return
	}
	// Recompute the commitment: a mismatch means the reveal does not open this message.
	want := e2e.GFrank(kf, gid, h.Epoch, h.Idx, h.Gen, uint8(in.CType), payload)
	if !hmac.Equal(want, h.C) {
		core.Fail(w, r, core.E(400, "frank", "the revealed key does not open this message"))
		return
	}
	// Franking proven: inspect the plaintext in memory, keep only kinds + score + sha256.
	kinds, score, upheld := inspect(payload)
	ptSha := e2e.Sum(payload)
	at := time.Now().Truncate(time.Second)
	if _, err := s.d.DB.Exec(r.Context(), `INSERT INTO grp_evidence (gid, seq, by_id, by_root, upheld, kinds, score, pt_sha, at, exp)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (gid, seq, by_id) DO UPDATE SET upheld = EXCLUDED.upheld, kinds = EXCLUDED.kinds, score = EXCLUDED.score, at = EXCLUDED.at, exp = EXCLUDED.exp`,
		gid, in.Seq, id.ID, id.Root, upheld, kinds, score, ptSha, at, at.Add(EvidenceTTL)); err != nil {
		core.Fail(w, r, err)
		return
	}
	verdict := "opened"
	if upheld {
		verdict = "upheld"
	}
	core.Text(w, r, 200, "ok franking-verified "+verdict+" kinds="+strings.Join(kinds, ",")+" score="+strconv.Itoa(score),
		map[string]any{"ok": true, "verified": true, "upheld": upheld, "kinds": kinds, "score": score})
}

// reporterStanding reports whether id is a current member of gid or sits in its tomb.
func reporterStanding(ctx context.Context, q core.Q, gid, id string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM grp_members WHERE gid = $1 AND id = $2)
		OR EXISTS (SELECT 1 FROM grp_members_tomb WHERE gid = $1 AND id = $2)`, gid, id).Scan(&ok)
	return ok, err
}

// inspect runs the content-blind scrub over the revealed plaintext (26.3): a tier-1 secret or any
// finding makes the report upheld. Non-UTF-8 payloads are treated as opaque (no finding).
func inspect(payload []byte) (kinds []string, score int, upheld bool) {
	if !utf8.Valid(payload) {
		return nil, 0, false
	}
	seen := map[string]bool{}
	for _, f := range scrub.Scan("g", string(payload)) {
		if !seen[f.Kind] {
			seen[f.Kind] = true
			kinds = append(kinds, f.Kind)
		}
		if f.Tier == 1 {
			upheld = true
		}
		score++
	}
	return kinds, score, upheld
}
