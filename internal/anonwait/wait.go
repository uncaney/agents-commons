package anonwait

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/pow"
)

const (
	challengeTTL = 10 * time.Minute // matches core: issuance = exp - challengeTTL
	baseWaitS    = 20               // the floor wait in seconds (bits byte = wait_s/10)
	maxWaitS     = 300              // adaptive cap
	outPerGroup  = 10               // outstanding wait challenges per IP group per hour
	outPerSuper  = 40               // ... and per super-group per hour
)

type handlers struct{ d *core.Deps }

// Register mounts GET|POST /v1/challenge/wait, its cost and OpenAPI, and the janitor sweep of the
// 0044 counters and the expired 0252 tickets. It installs nothing on core.XPoWFn: P60a wires
// core.XPoWFn = anonwait.Wrap(core.XPoWFn) and a.PendingFn/PendingGetFn = anonwait.Pending/Get.
func Register(mux *http.ServeMux, d *core.Deps) {
	deps.Store(d)
	h := &handlers{d}
	mux.HandleFunc("GET /v1/challenge/wait", h.challenge)
	mux.HandleFunc("POST /v1/challenge/wait", h.challenge)
	d.RegisterCost("GET /v1/challenge/wait", 1)
	d.RegisterCost("POST /v1/challenge/wait", 1)
	d.RegisterOpenAPI(json.RawMessage(openAPI))
	if d.Janitor != nil {
		d.Janitor.Add("anonwait_sweep", func(ctx context.Context) error { return sweep(ctx, d) })
	}
}

// challenge serves GET|POST /v1/challenge/wait?for=w: a stateless w_wait challenge that is spendable
// only wait_s seconds after issuance. wait_s adapts to the super-group's recent wait writes and the
// issuance is rate-capped per hour (outstanding caps) at cost 1.
func (h *handlers) challenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if p := r.URL.Query().Get("for"); p != "" && p != "w" {
		core.Fail(w, r, core.Bad("for must be w"))
		return
	}
	if !h.d.CheckFrozen(w, r, "write") {
		return
	}
	ctx := r.Context()
	grp, super := h.d.IPGroup(r), h.d.IPSuper(r)
	waitS, err := adaptiveWait(ctx, h.d.DB, super)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if err := chargeOutstanding(ctx, h.d.DB, grp, super); err != nil {
		core.Fail(w, r, err)
		return
	}
	t := now()
	exp := t.Add(challengeTTL).Truncate(time.Second)
	ready := exp.Add(-challengeTTL).Add(time.Duration(waitS) * time.Second)
	c := pow.New(h.d.Cfg.ServerSecret, exp, waitS/10, pow.PurposeWait)
	text := fmt.Sprintf("c=%s ready=%d exp=%d for=w mode=wait wait_s=%d", c, ready.Unix(), exp.Unix(), waitS)
	core.OK(w, r, text, map[string]any{"c": c, "ready": ready.Unix(), "exp": exp.Unix(), "for": "w", "mode": "wait", "wait_s": waitS})
}

// adaptiveWait is 20 * 2^floor(writes_24h/10) capped at 300, where writes_24h is the super-group's
// wait writes over the last day (wait_writes, 0044).
func adaptiveWait(ctx context.Context, q core.Q, super string) (int, error) {
	var writes int
	err := q.QueryRow(ctx, `SELECT COALESCE(sum(n), 0)::int FROM wait_writes WHERE super_h = $1 AND day >= current_date - 1`, grpHash(super)).Scan(&writes)
	if err != nil {
		return 0, err
	}
	waitS := baseWaitS
	for i := 0; i < writes/10 && waitS < maxWaitS; i++ {
		waitS *= 2
	}
	if waitS > maxWaitS {
		waitS = maxWaitS
	}
	return waitS, nil
}

// chargeOutstanding bumps the per-hour issuance counters for the group and its super-group and
// enforces <= 10/h per group and <= 40/h per super-group (pow_wait, 0044).
func chargeOutstanding(ctx context.Context, q core.Q, grp, super string) error {
	hour := now().Truncate(time.Hour)
	g, err := bumpPowWait(ctx, q, grpHash(grp), hour)
	if err != nil {
		return err
	}
	s, err := bumpPowWait(ctx, q, grpHash("s:"+super), hour)
	if err != nil {
		return err
	}
	if g > outPerGroup || s > outPerSuper {
		return core.E(429, "quota", "too many outstanding wait challenges, retry next hour")
	}
	return nil
}

func bumpPowWait(ctx context.Context, q core.Q, h []byte, hour time.Time) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO pow_wait (grp_h, hour, n) VALUES ($1, $2, 1)
		ON CONFLICT (grp_h, hour) DO UPDATE SET n = pow_wait.n + 1 RETURNING n`, h, hour).Scan(&n)
	return n, err
}

// Wrap decorates the anonymous-write PoW checker: a `<c>:wait` header is verified as a w_wait
// challenge and accepted once inside its window (now >= exp-600+wait_s AND now < exp), marking the
// request wait-mode; any other header runs inner unchanged (27.2).
func Wrap(inner core.XPoWFnType) core.XPoWFnType {
	return func(ctx context.Context, q core.Q, r *http.Request) (grp, super string, err error) {
		h := strings.TrimSpace(r.Header.Get("X-PoW"))
		c, rest, ok := strings.Cut(h, ":")
		if !ok || rest != "wait" {
			if inner == nil {
				return "", "", core.E(400, "pow", "X-PoW required")
			}
			return inner(ctx, q, r)
		}
		return consumeWait(ctx, q, r, c)
	}
}

// consumeWait verifies and single-use-consumes a wait challenge, bumps the super-group's wait-write
// counter and marks the request wait-mode.
func consumeWait(ctx context.Context, q core.Q, r *http.Request, c string) (grp, super string, err error) {
	if len(c) > 64 {
		return "", "", core.E(400, "pow", "X-PoW must be <challenge>:wait")
	}
	info, err := pow.VerifyV2(serverSecret(), c, now())
	if err != nil {
		return "", "", core.E(400, "pow", err.Error())
	}
	if info.Purpose != pow.PurposeWait {
		return "", "", core.E(400, "pow", "challenge purpose "+info.Purpose.String()+", need w_wait")
	}
	ready := info.Exp.Add(-challengeTTL).Add(time.Duration(info.Bits) * 10 * time.Second)
	if now().Before(ready) {
		return "", "", core.E(400, "pow", "too early")
	}
	if _, err := q.Exec(ctx, `INSERT INTO used_challenges (c, exp) VALUES ($1, $2)`, c, info.Exp); err != nil {
		if core.IsUniqueViolation(err) {
			return "", "", core.E(400, "pow", "challenge already used")
		}
		return "", "", err
	}
	if _, grp, super = core.ClientFrom(ctx); grp == "" {
		if d := depsOrNil(); d != nil {
			grp, super = d.IPGroup(r), d.IPSuper(r)
		}
	}
	if _, err := q.Exec(ctx, `INSERT INTO wait_writes (super_h, day, n) VALUES ($1, current_date, 1)
		ON CONFLICT (super_h, day) DO UPDATE SET n = wait_writes.n + 1`, grpHash(super)); err != nil {
		return "", "", err
	}
	markWait(ctx)
	return grp, super, nil
}

// sweep drops stale 0044 counters and expired 0252 tickets (janitor).
func sweep(ctx context.Context, d *core.Deps) error {
	if _, err := d.DB.Exec(ctx, `DELETE FROM pow_wait WHERE hour < now() - interval '2 hours';
		DELETE FROM wait_writes WHERE day < current_date - 2`); err != nil {
		return err
	}
	_, err := d.DB.Exec(ctx, `DELETE FROM a2a_pending WHERE n IS NULL AND created < now() - interval '10 minutes'`)
	return err
}
