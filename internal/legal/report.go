// Package legal implements the content-blind moderation guarantees of SECURITY-E2EE-v2 8.3-8.6 and
// SPEC-v2 26.3: recipient-reveal reports with three-signature evidence, the diversity-gated penalty
// queue applied at fixed batch ticks, the operator review queue and the /admin/x/* surface, and the
// /legal/e2ee and /legal/transparency pages. The operator never holds a key: a report discloses the
// franking key and the already-decrypted payload, the server verifies the commitment, runs the
// scanners in memory and stores only the verdict (kinds, score, sha256) and the self-contained
// signatures that prove the sender committed to that payload.
package legal

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/keys"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/xmail"
)

// svc is the package service.
type svc struct{ d *core.Deps }

// cur is the service installed by Register (nil = not ready).
var cur atomic.Pointer[svc]

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

const (
	// evidenceTTL is the retention of x_evidence (8.5): 90 d, extended only while a notice is open.
	evidenceTTL = 90 * 24 * time.Hour
	// freezeDur is the automatic freeze window set at the batch tick (8.3 D12).
	freezeDur = 7 * 24 * time.Hour
	// reportWindow is the diversity window for the auto-freeze threshold (8.3).
	reportWindow = 7 * 24 * time.Hour
	// freezeRepDelta is the reputation hit applied with the freeze at the tick (8.3).
	freezeRepDelta = -5
	// distinctNeeded is the number of distinct established reporters and distinct IP groups a
	// sender root must draw within reportWindow before any automatic sanction (8.3 D12).
	distinctNeeded = 3
	// reviewWeight is the weight a bad-frank or sub-threshold report carries in the queue (4.7).
	reviewWeight = 0.34
	// badFrankPerDay zeroes a reporter's report quota for a day after this many bad-frank failures.
	badFrankPerDay = 3
	// whyMax caps the reporter's free-text judgement.
	whyMax = 200
	// flagCredSol is the lexicon flag that upholds a report on its own (26.3).
	flagCredSol = "credential-solicitation"
)

// reportIn is the POST /v1/x/report body (8.3). kind 'frank' discloses the franking key and the
// decrypted (type, payload) of exactly one message; kind 'bad-frank' asserts an unverifiable
// franking commitment and carries no plaintext.
type reportIn struct {
	Kind    string `json:"kind"`
	Seq     int64  `json:"seq"`
	G       string `json:"g"` // group id (group/object report); "" = pairwise
	KF      string `json:"kf"`
	Type    int    `json:"type"`
	Payload string `json:"payload"`
	Why     string `json:"why"`
}

// row is the reported envelope's ledger twin: metadata and signatures that outlive the ciphertext.
type row struct {
	hdr, rcpt, sendSig []byte
	fromID, fromRoot   string
	at                 time.Time
}

// verdict is the in-memory scanner result; only kinds, score and sha256 are stored (26.3).
type verdict struct {
	kinds  []string
	score  int
	sha    []byte
	upheld bool
	token  string // first tier-1 secret found (opens the leak path), never stored
}

func (s *svc) report(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		core.Fail(w, r, core.Bad("read"))
		return
	}
	var in reportIn
	if err := json.Unmarshal(body, &in); err != nil {
		core.Fail(w, r, core.Bad("body: "+err.Error()))
		return
	}
	sig, _ := keys.SigFrom(r.Context())
	text, err := s.handle(r.Context(), id, &in, sig, s.d.IPGroup(r))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, text+"\n", map[string]any{"ok": true, "status": text})
}

// handle runs one report end to end inside a transaction and returns the reply line.
func (s *svc) handle(ctx context.Context, caller *core.Ident, in *reportIn, sig *e2e.ReqSig, ipg string) (string, error) {
	if sig == nil {
		return "", core.E(401, "sig", "X-Cx-Sig required")
	}
	if in.Seq <= 0 {
		return "", core.Bad("seq must be the reported envelope sequence")
	}
	in.Why = strings.TrimSpace(in.Why)
	if len(in.Why) > whyMax {
		return "", core.Bad("why must be <= 200 bytes")
	}
	if blocked, err := s.reportBlocked(ctx, caller.Root); err != nil {
		return "", err
	} else if blocked {
		return "", core.E(429, "quota", "report quota 0 for today: too many bad-frank reports")
	}
	ref, rw, err := s.load(ctx, caller, in)
	if err != nil {
		return "", err
	}
	switch in.Kind {
	case "", "frank":
		return s.reportFrank(ctx, caller, in, ref, rw, sig, ipg)
	case "bad-frank":
		return s.reportBadFrank(ctx, caller, in, ref, rw, sig, ipg)
	default:
		return "", core.Bad("kind must be frank or bad-frank")
	}
}

// load reads the reported row's ledger twin (hdr, rcpt, send_sig) and checks the caller is the
// recipient (pairwise) or a current/former member (group). The ciphertext may be long gone.
func (s *svc) load(ctx context.Context, caller *core.Ident, in *reportIn) (string, *row, error) {
	if in.G != "" {
		return "", nil, core.E(501, "unsupported", "group reports arrive once the group lane ships; pairwise reports only")
	}
	rw := &row{}
	err := s.d.DB.QueryRow(ctx, `SELECT hdr, rcpt, send_sig, from_id, from_root, at FROM x_ledger WHERE to_id = $1 AND seq = $2`,
		caller.ID, in.Seq).Scan(&rw.hdr, &rw.rcpt, &rw.sendSig, &rw.fromID, &rw.fromRoot, &rw.at)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, core.E(404, "notfound", "no message "+caller.ID+"/"+strconv.FormatInt(in.Seq, 10)+" in your inbox (expired beyond 30 d, or never yours)")
	}
	if err != nil {
		return "", nil, err
	}
	return "m:" + caller.ID + "/" + strconv.FormatInt(in.Seq, 10), rw, nil
}

// reportFrank verifies the franking commitment against the disclosed (kf, type, payload), runs the
// scanners in memory, records the verdict and applies the diversity gate. A wrong disclosure halves
// the reporter's report_trust and records nothing (8.3).
func (s *svc) reportFrank(ctx context.Context, caller *core.Ident, in *reportIn, ref string, rw *row, sig *e2e.ReqSig, ipg string) (string, error) {
	hdr, err := e2e.ParseHdr(rw.hdr)
	if err != nil {
		return "", err
	}
	if hdr.To != caller.ID {
		return "", core.E(403, "auth", "only the recipient may report a sealed message")
	}
	kf, err := decodeB64(in.KF)
	if err != nil || len(kf) != 32 {
		return "", core.Bad("kf must be the 32-byte franking key, base64url")
	}
	payload, err := decodeB64(in.Payload)
	if err != nil {
		return "", core.Bad("payload must be the decrypted plaintext, base64url")
	}
	if in.Type < 0 || in.Type > 255 {
		return "", core.Bad("type must be the inner message type")
	}
	if !e2e.VerifyFrank(hdr, kf, uint8(in.Type), payload) {
		// Bad disclosure: nothing recorded, the reporter's standing takes the cost (8.3).
		if err := s.badFrank(ctx, caller.Root); err != nil {
			return "", err
		}
		return "", core.E(400, "bad", "frank: the disclosed key, type and payload do not match this message's commitment")
	}
	v := scan(payload)
	var upheld bool
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if v.token != "" {
			if _, err := core.LeakedToken(ctx, tx, v.token); err != nil {
				return err
			}
		}
		est, err := established(ctx, tx, caller)
		if err != nil {
			return err
		}
		evID, err := insertEvidence(ctx, tx, "frank", ref, rw, hdr, &v, in.Why, caller.Root, ipg, est, sig)
		if err != nil {
			return err
		}
		upheld = v.upheld
		froze, err := s.gate(ctx, tx, rw.fromRoot)
		if err != nil {
			return err
		}
		if froze {
			return nil
		}
		return s.enqueue(ctx, tx, evID, rw.fromRoot, ref, queueReason(&v, est), reviewWeight)
	})
	if err != nil {
		return "", err
	}
	if upheld {
		return "ok verified upheld", nil
	}
	return "ok verified", nil
}

// reportBadFrank records an unverifiable franking claim (4.4): the recipient could decrypt but the
// commitment does not bind the plaintext, so the sender sent an unfrankable envelope and is flagged.
func (s *svc) reportBadFrank(ctx context.Context, caller *core.Ident, in *reportIn, ref string, rw *row, sig *e2e.ReqSig, ipg string) (string, error) {
	hdr, err := e2e.ParseHdr(rw.hdr)
	if err != nil {
		return "", err
	}
	if hdr.To != caller.ID {
		return "", core.E(403, "auth", "only the recipient may report a sealed message")
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		est, err := established(ctx, tx, caller)
		if err != nil {
			return err
		}
		evID, err := insertEvidence(ctx, tx, "bad-frank", ref, rw, hdr, &verdict{}, in.Why, caller.Root, ipg, est, sig)
		if err != nil {
			return err
		}
		return s.enqueue(ctx, tx, evID, rw.fromRoot, ref, "unfrankable-envelope sender-flagged", reviewWeight)
	})
	if err != nil {
		return "", err
	}
	return "ok flagged unfrankable", nil
}

// scan runs normalise -> scrub -> lexicon -> hazard on the disclosed plaintext (26.3). Only the
// resulting kinds, lexicon score and sha256 leave this function; the plaintext never does.
func scan(payload []byte) verdict {
	sha := sha256.Sum256(payload)
	v := verdict{sha: sha[:]}
	norm := scrub.Normalize(string(payload))
	seen := map[string]bool{}
	var secrets []string
	for _, f := range scrub.Scan("x", norm) {
		if !seen["s:"+f.Kind] {
			seen["s:"+f.Kind] = true
			secrets = append(secrets, f.Kind)
		}
		if v.token == "" && f.Tier == 1 && f.Off+f.Len <= len(norm) {
			v.token = norm[f.Off : f.Off+f.Len]
		}
	}
	sort.Strings(secrets)
	score, flags, _ := scrub.Flags(norm)
	hazards := scrub.Hazards(norm)
	v.score = score
	v.kinds = append(append(append([]string{}, secrets...), flags...), hazards...)
	v.upheld = score >= 2 || contains(flags, flagCredSol) || len(hazards) > 0
	return v
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// established reports whether the reporter root was established at report time (rep >= 5, age >= 72 h,
// or seed): the D12 gate counts only established reporters.
func established(ctx context.Context, q core.Q, caller *core.Ident) (bool, error) {
	if caller.Established() {
		return true, nil
	}
	var rep int
	var created time.Time
	var seed bool
	err := q.QueryRow(ctx, `SELECT rep, created, seed FROM identities WHERE id = $1`, caller.Root).Scan(&rep, &created, &seed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return seed || (rep >= 5 && time.Since(created) >= core.EstablishedAge), nil
}

// insertEvidence writes one x_evidence row; kinds/score/sha256 are the verdict, never the plaintext.
func insertEvidence(ctx context.Context, q core.Q, kind, ref string, rw *row, hdr *e2e.Hdr, v *verdict, why, reporterRoot, ipg string, est bool, sig *e2e.ReqSig) (int64, error) {
	var sha []byte
	if len(v.sha) == 32 {
		sha = v.sha
	}
	var id int64
	err := q.QueryRow(ctx, `INSERT INTO x_evidence
		(kind, ref, from_id, from_root, at, hdr, rcpt, send_sig, kinds, score, sha256, pol, upheld, why,
		 reporter_root, reporter_ipg, reporter_est, report_ts, report_nonce, report_sig, exp)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) RETURNING id`,
		kind, ref, rw.fromID, rw.fromRoot, rw.at, rw.hdr, rw.rcpt, rw.sendSig,
		strings.Join(v.kinds, ","), v.score, sha, int(hdr.Pol), v.upheld, why,
		reporterRoot, ipg, est, int64(sig.TS), sig.Nonce, sig.Sig, time.Now().Add(evidenceTTL)).Scan(&id)
	return id, err
}

// gate applies the D12 diversity threshold: >= 3 distinct established reporter roots in >= 3 distinct
// IP groups within 7 d (one per reporter per sender). On the threshold it queues a pending penalty
// (frozen_until + rep hit) for the next batch tick and returns true; otherwise it returns false and
// the caller files the report for operator review.
func (s *svc) gate(ctx context.Context, q core.Q, fromRoot string) (bool, error) {
	var roots, groups int
	if err := q.QueryRow(ctx, `SELECT count(DISTINCT reporter_root), count(DISTINCT reporter_ipg)
		FROM x_evidence WHERE from_root = $1 AND kind = 'frank' AND reporter_est AND reporter_ipg <> ''
		AND created > now() - $2::interval`, fromRoot, reportWindow.String()).Scan(&roots, &groups); err != nil {
		return false, err
	}
	if roots < distinctNeeded || groups < distinctNeeded {
		return false, nil
	}
	tag, err := q.Exec(ctx, `INSERT INTO x_penalties (from_root, basis, until, rep_delta)
		VALUES ($1, 'reports', now() + $2::interval, $3) ON CONFLICT (from_root) WHERE applied_at IS NULL DO NOTHING`,
		fromRoot, freezeDur.String(), freezeRepDelta)
	if err != nil {
		return false, err
	}
	// Whether this report created the pending penalty or one was already pending, the sanction is
	// gated and queued for the tick; the report itself does not land in the operator review queue.
	_ = tag
	return true, nil
}

// queue files a report for operator review (sub-threshold, bad-frank or cold-root) and raises the
// ops inbox event under the per-kind cap.
func (s *svc) enqueue(ctx context.Context, q core.Q, evID int64, fromRoot, ref, reason string, weight float64) error {
	if _, err := q.Exec(ctx, `INSERT INTO x_review_queue (evidence, from_root, ref, reason, weight) VALUES ($1,$2,$3,$4,$5)`,
		evID, fromRoot, ref, reason, weight); err != nil {
		return err
	}
	return core.Event(ctx, q, "ops", "x-review", "", "verified report pending "+ref)
}

// queueReason labels a sub-threshold report for the operator.
func queueReason(v *verdict, est bool) string {
	switch {
	case v.upheld:
		return "upheld below-threshold"
	case !est:
		return "cold-root"
	default:
		return "below-threshold"
	}
}

// badFrank halves the reporter's report_trust and records the bad-frank failure; past
// badFrankPerDay failures in a day the reporter's report quota is held at zero (checked in handle).
func (s *svc) badFrank(ctx context.Context, reporterRoot string) error {
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO report_trust (reporter, score) VALUES ($1, 0.5)
			ON CONFLICT (reporter) DO UPDATE SET score = report_trust.score * 0.5, updated = now()`, reporterRoot); err != nil {
			return err
		}
		_, err := bump(ctx, tx, reporterRoot, "x-bad-frank", 1)
		return err
	})
}

// reportBlocked reports whether the reporter has spent its day's bad-frank allowance (report quota 0).
func (s *svc) reportBlocked(ctx context.Context, reporterRoot string) (bool, error) {
	var n int
	err := s.d.DB.QueryRow(ctx, `SELECT coalesce(n, 0) FROM counters WHERE scope = $1 AND kind = 'x-bad-frank' AND day = current_date`, reporterRoot).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return n >= badFrankPerDay, err
}

// Freeze is xmail's lever: write a sender freeze so xmail refuses sends (8.1/8.3).
func freeze(ctx context.Context, q core.Q, root string, until time.Time) error {
	return xmail.Freeze(ctx, q, root, until, "reports")
}
