// Package webhook adds webhooks by pull and inbound webhook sinks (SPEC-v2 27.7, P109).
//
// Outbound carries no egress: an agent registers a hook (a target url, a signing secret, and a
// 19.1 watch filter over the event log); the events janitor renders a complete, signed envelope
// per matching event into hook_out, and the agent pulls those rows (GET /v1/hook/{id}/out, as JSON
// or ready-to-run curl lines) and delivers them with its OWN egress. The gateway never fetches the
// url, and the url is rendered masked everywhere but the owner's own out rows. Standard Webhooks
// envelopes carry webhook-id / webhook-timestamp / webhook-signature (v1 HMAC-SHA256); slack,
// discord, ntfy and a2a shapes are also available. A private per-root feed GET /f/h/{url-token}
// serves the same envelopes.
//
// Inbound sinks receive real provider webhooks: POST /v1/inhook registers a sink; POST /in/{id}
// verifies a GitHub / GitLab / generic HMAC signature in constant time (an invalid signature is
// answered with the same 404 as an unknown id), extracts one short, scrubbed line, and drops it
// into a topic, a mailbox or a work queue. Bodies are never stored, payload URLs never fetched, a
// replay guard dedupes by delivery id, and a hook disables itself after 100 consecutive bad
// signatures.
package webhook

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"ekaii.fr/commons/internal/core"
)

// Production knobs (vars so tests can tighten the windows); SPEC-v2 27.7 fixes the defaults.
var (
	MaxHooks   = 10  // outbound hooks per root (L0: 0)
	MaxInHooks = 5   // inbound sinks per root (L1+)
	MaxOutLive = 500 // live hook_out rows per hook
	OutKeep    = 7 * 24 * time.Hour
	InKeep     = 24 * time.Hour  // in_deliveries retention
	MaxWait    = 85              // longest out long-poll (seconds)
	MaxOutK    = 20              // rows per out poll
	InMaxBytes = int64(64 << 10) // inbound body cap
	InLineMax  = 1 << 10         // extracted line cap
	InPerHour  = 60              // inbound events per hour per hook
	InPerDay   = 600             // inbound events per day per root
	BadDisable = 100             // consecutive bad signatures that disable a hook
	LexDrop    = 2               // scrub lexicon score that drops an inbound line

	// Storage-class caps for the governor (21.2).
	OutBytes = int64(256 << 20)
	InBytes  = int64(64 << 20)
)

const (
	maxURL     = 512
	maxQ       = 120
	secretLen  = 24
	maxEnv     = 16 << 10
	createBody = 4 << 10
	ackBody    = 1 << 10
)

// outTopic is the long-poll notifier topic a hook's out poll waits on.
func outTopic(hook string) string { return "hk:" + hook }

type handlers struct{ d *core.Deps }

// Register mounts the outbound and inbound routes, the scopes, costs, the url-token feed, the
// OpenAPI fragment, the storage classes, the retention janitors, the event-consuming janitor and
// the purge hook.
func Register(mux *http.ServeMux, d *core.Deps) {
	h := &handlers{d}
	// Outbound.
	mux.HandleFunc("POST /v1/hook", h.hookCreate)
	mux.HandleFunc("GET /v1/hook", h.hookList)
	mux.HandleFunc("GET /v1/hook/{id}/out", h.out)
	mux.HandleFunc("POST /v1/hook/{id}/ack", h.ack)
	mux.HandleFunc("DELETE /v1/hook/{id}", h.hookDelete)
	// Inbound.
	mux.HandleFunc("POST /v1/inhook", h.inCreate)
	mux.HandleFunc("GET /v1/inhook", h.inList)
	mux.HandleFunc("DELETE /v1/inhook/{id}", h.inDelete)
	mux.HandleFunc("POST /in/{id}", h.inbound)

	d.RegisterScope("POST /v1/hook", "hook")
	d.RegisterScope("GET /v1/hook", "hook")
	d.RegisterScope("GET /v1/hook/{id}/out", "hook")
	d.RegisterScope("POST /v1/hook/{id}/ack", "hook")
	d.RegisterScope("DELETE /v1/hook/{id}", "hook")
	d.RegisterScope("POST /v1/inhook", "hook")
	d.RegisterScope("GET /v1/inhook", "hook")
	d.RegisterScope("DELETE /v1/inhook/{id}", "hook")
	d.RegisterScope("POST /in/{id}", "*") // anonymous: the signature authenticates
	d.RegisterCost("GET /v1/hook/{id}/out", 0.2)
	d.RegisterCost("POST /in/{id}", 0.2)

	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("webhooks", func(context.Context) string { return llmsText })
	d.RegisterFeed("h", h.feed)
	d.RegisterTarget("h", core.Target{Exists: h.tgtHookExists, Hide: noop, Restore: noop})
	d.RegisterTarget("i", core.Target{Exists: h.tgtInExists, Hide: h.tgtInHide, Restore: h.tgtInRestore})

	d.StorageClass("webhook_out", OutBytes, `SELECT pg_total_relation_size('hook_out')`)
	d.StorageClass("webhook_in", InBytes, `SELECT pg_total_relation_size('in_deliveries')`)

	d.Janitor.Add("webhook_deliver", h.deliverPass)
	d.Janitor.Add("webhook_out_retain", func(ctx context.Context) error {
		_, err := d.DB.Exec(ctx, `DELETE FROM hook_out WHERE created < now() - $1::interval`,
			dur(OutKeep))
		return err
	})
	d.Janitor.Add("webhook_in_retain", func(ctx context.Context) error {
		_, err := d.DB.Exec(ctx, `DELETE FROM in_deliveries WHERE at < now() - $1::interval`, dur(InKeep))
		return err
	})
	d.OnPurge(h.purge)
}

// purge removes a root's hooks and inbound sinks when the root is deleted (hook_out cascades).
func (h *handlers) purge(ctx context.Context, root string) error {
	if _, err := h.d.DB.Exec(ctx, `DELETE FROM hooks WHERE root = $1`, root); err != nil {
		return err
	}
	_, err := h.d.DB.Exec(ctx, `DELETE FROM in_hooks WHERE root = $1`, root)
	return err
}

// dur renders a duration as a Postgres interval literal ("604800 seconds").
func dur(d time.Duration) string { return fmt.Sprintf("%d seconds", int64(d.Seconds())) }
