// Command courier is the only component of the stack with Internet egress (SPEC-v2 20). It polls
// the gateway's outbox on INTERNAL_LISTEN (http://gateway:8081), performs each job against a
// compiled-in host allowlist and acks the result or reports the failure. No inbound port, no
// database access, secrets as files, stdlib only.
//
// Config (env): INTERNAL_URL (http://gateway:8081), GATEWAY_URL (http://gateway:8080, export
// files), COURIER_TOKEN_FILE (/run/secrets/courier_token), EGRESS_KINDS (comma list, required),
// SECRETS_DIR (/run/secrets), PUBLIC_URL (fallback until /internal/config answers), POLL_WAIT
// (55), S3_ENDPOINT (adds its host to the allowlist), HEARTBEAT_FILE (/tmp/courier.alive),
// COURIER_TEST_BASE (tests/e2e only: every egress request goes to this base URL).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	jobTimeout    = 5 * time.Minute
	maxBackoff    = time.Minute
	heartbeatMaxA = 5 * time.Minute
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

type config struct {
	InternalURL string
	GatewayURL  string
	PublicURL   string
	Token       string
	Kinds       []string
	SecretsDir  string
	Wait        int
	S3Endpoint  string
	TestBase    string
	Heartbeat   string
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

// secret reads NAME_FILE (trimmed) if set, else NAME, else the default file.
func secret(name, defFile string) (string, error) {
	p := os.Getenv(name + "_FILE")
	if p == "" {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v, nil
		}
		p = defFile
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func loadConfig() (config, error) {
	c := config{
		InternalURL: strings.TrimRight(env("INTERNAL_URL", "http://gateway:8081"), "/"),
		GatewayURL:  strings.TrimRight(env("GATEWAY_URL", "http://gateway:8080"), "/"),
		PublicURL:   strings.TrimRight(env("PUBLIC_URL", "https://agents.ekaii.fr"), "/"),
		SecretsDir:  env("SECRETS_DIR", "/run/secrets"),
		S3Endpoint:  env("S3_ENDPOINT", ""),
		TestBase:    env("COURIER_TEST_BASE", ""),
		Heartbeat:   env("HEARTBEAT_FILE", "/tmp/courier.alive"),
	}
	for _, u := range []struct{ name, val string }{{"INTERNAL_URL", c.InternalURL}, {"GATEWAY_URL", c.GatewayURL}, {"PUBLIC_URL", c.PublicURL}} {
		p, err := url.Parse(u.val)
		if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Hostname() == "" {
			return c, fmt.Errorf("%s must be an http(s) URL with a host", u.name)
		}
	}
	tok, err := secret("COURIER_TOKEN", c.SecretsDir+"/courier_token")
	if err != nil {
		return c, err
	}
	if len(tok) < 16 {
		return c, errors.New("COURIER_TOKEN too short (need >= 16 chars)")
	}
	c.Token = tok
	for _, k := range strings.Split(os.Getenv("EGRESS_KINDS"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			c.Kinds = append(c.Kinds, k)
		}
	}
	if len(c.Kinds) == 0 {
		return c, errors.New("EGRESS_KINDS required (comma-separated kinds, e.g. indexnow,libmeta,cf_purge,hf)")
	}
	if c.Wait, err = strconv.Atoi(env("POLL_WAIT", "55")); err != nil || c.Wait < 0 || c.Wait > 55 {
		return c, errors.New("POLL_WAIT must be 0..55")
	}
	return c, nil
}

// s3Host extracts the host of S3_ENDPOINT (URL or bare host).
func s3Host(ep string) string {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return ""
	}
	if !strings.Contains(ep, "://") {
		ep = "https://" + ep
	}
	u, err := url.Parse(ep)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	kinds, err := enabledKinds(cfg.Kinds)
	if err != nil {
		return err
	}
	allow := buildAllowlist(kinds, s3Host(cfg.S3Endpoint))
	var client *http.Client
	if cfg.TestBase != "" {
		base, err := url.Parse(cfg.TestBase)
		if err != nil || base.Host == "" {
			return errors.New("COURIER_TEST_BASE must be a URL")
		}
		log.Warn("COURIER_TEST_BASE set: ALL egress goes to this base and the allowlist is bypassed (tests only)", "base", cfg.TestBase)
		client = newClient(rewriteTransport{base: base, next: &http.Transport{Proxy: nil}})
	} else {
		client = newClient(newTransport(allow))
	}
	e := newEnv(cfg, client, log)
	hosts := make([]string, 0, len(allow))
	for h := range allow {
		hosts = append(hosts, h)
	}
	names := make([]string, 0, len(kinds))
	for _, k := range kinds {
		names = append(names, k.Name)
	}
	log.Info("courier starting", "kinds", names, "allowlist", len(hosts), "internal", cfg.InternalURL)

	c := &courier{e: e, kinds: kinds, wait: cfg.Wait, last: map[string]time.Time{}, sleep: sleepCtx,
		beat: func() { os.WriteFile(cfg.Heartbeat, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600) }}
	c.waitConfig(ctx)
	for _, k := range kinds {
		if k.Scan != nil {
			go c.runScanner(ctx, k)
		}
	}
	c.run(ctx)
	log.Info("courier stopped")
	return nil
}

// courier is the poll/ack loop over the enabled outbox kinds.
type courier struct {
	e     *Env
	kinds []*Kind
	wait  int
	last  map[string]time.Time // last partial drain per throttled kind
	sleep func(ctx context.Context, d time.Duration) bool
	beat  func()
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// waitConfig fetches /internal/config until the gateway answers (the courier may boot first).
func (c *courier) waitConfig(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		if err := c.e.loadInternalConfig(ctx); err == nil {
			c.e.Log.Info("gateway config loaded", "public_url", c.e.PublicURL, "indexnow_key", c.e.IndexNowKey != "")
			return
		} else {
			c.e.Log.Warn("gateway config", "err", err)
		}
		if !c.sleep(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// run polls until ctx is done: errors back off exponentially (1 s .. 60 s), a quiet cycle relies on
// the server's long-poll.
func (c *courier) run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		if c.beat != nil {
			c.beat()
		}
		n, err := c.cycle(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			c.e.Log.Warn("poll", "err", oneLine(err.Error(), 200), "retry_in", backoff.String())
			c.sleep(ctx, backoff)
			backoff = min(backoff*2, maxBackoff)
		default:
			backoff = time.Second
			if n == 0 && c.wait == 0 {
				c.sleep(ctx, time.Second)
			}
		}
	}
}

// due returns the outbox kinds to poll now and how long until the next throttled one is due.
func (c *courier) due(now time.Time) ([]*Kind, time.Duration) {
	var out []*Kind
	next := time.Duration(-1)
	for _, k := range c.kinds {
		if k.Scan != nil {
			continue
		}
		if k.Every > 0 {
			if rem := k.Every - now.Sub(c.last[k.Name]); rem > 0 {
				if next < 0 || rem < next {
					next = rem
				}
				continue
			}
		}
		out = append(out, k)
	}
	return out, next
}

// cycle polls once and handles what it gets: 0 jobs on 204 (after the server waited) or when
// nothing is due yet; errors are transport/protocol failures against the gateway.
func (c *courier) cycle(ctx context.Context) (int, error) {
	now := c.e.Now()
	due, next := c.due(now)
	if len(due) == 0 {
		if next < 0 {
			next = time.Minute
		}
		c.sleep(ctx, min(next, time.Duration(max(c.wait, 1))*time.Second))
		return 0, nil
	}
	names := make([]string, len(due))
	for i, k := range due {
		names[i] = k.Name
	}
	job, err := c.fetch(ctx, names, c.wait)
	if err != nil || job == nil {
		return 0, err
	}
	k, ok := Lookup(job.Kind)
	if !ok || !c.enabled(k) {
		c.fail(ctx, job, fmt.Errorf("kind %s not enabled on this courier", job.Kind))
		return 1, nil
	}
	jctx, cancel := context.WithTimeout(ctx, jobTimeout)
	defer cancel()
	if k.RunBatch != nil {
		jobs := []*Job{job}
		for len(jobs) < k.Batch {
			j, err := c.fetch(ctx, []string{k.Name}, 0)
			if err != nil || j == nil {
				break
			}
			jobs = append(jobs, j)
		}
		if len(jobs) < k.Batch {
			c.last[k.Name] = now // a partial drain starts the Every throttle; a full one drains again at once
		}
		err := k.RunBatch(jctx, c.e, jobs)
		for _, j := range jobs {
			if err != nil {
				c.fail(ctx, j, err)
			} else {
				c.ack(ctx, j, nil)
			}
		}
		return len(jobs), nil
	}
	c.last[k.Name] = now
	res, err := k.Run(jctx, c.e, job)
	if err != nil {
		c.fail(ctx, job, err)
	} else {
		c.ack(ctx, job, res)
	}
	return 1, nil
}

func (c *courier) enabled(k *Kind) bool {
	for _, e := range c.kinds {
		if e == k {
			return true
		}
	}
	return false
}

// fetch claims the next due job of the given kinds; nil on 204.
func (c *courier) fetch(ctx context.Context, kinds []string, wait int) (*Job, error) {
	q := url.Values{"kinds": {strings.Join(kinds, ",")}, "wait": {strconv.Itoa(wait)}}
	code, body, err := c.e.Internal(ctx, http.MethodGet, "/internal/egress?"+q.Encode(), nil, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("poll: %w", err)
	}
	switch code {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var j Job
		if err := json.Unmarshal(body, &j); err != nil || j.ID <= 0 || !kindRe.MatchString(j.Kind) {
			return nil, errors.New("poll: malformed job")
		}
		return &j, nil
	}
	return nil, statusErr("poll", code, body)
}

func (c *courier) ack(ctx context.Context, j *Job, result json.RawMessage) {
	var body *bytes.Reader
	if len(result) > 0 {
		b, _ := json.Marshal(map[string]json.RawMessage{"result": result})
		body = bytes.NewReader(b)
	} else {
		body = bytes.NewReader([]byte(`{}`))
	}
	code, b, err := c.e.Internal(ctx, http.MethodPost, fmt.Sprintf("/internal/egress/%d/ack", j.ID), body, 64<<10)
	if err != nil || code != 200 {
		c.e.Log.Warn("ack failed", "id", j.ID, "kind", j.Kind, "status", code, "err", err, "body", oneLine(string(b), 160))
		return
	}
	c.e.Log.Info("job done", "id", j.ID, "kind", j.Kind, "attempt", j.Attempts, "result_bytes", len(result))
}

func (c *courier) fail(ctx context.Context, j *Job, jerr error) {
	msg := oneLine(jerr.Error(), 500)
	b, _ := json.Marshal(map[string]string{"err": msg})
	code, rb, err := c.e.Internal(ctx, http.MethodPost, fmt.Sprintf("/internal/egress/%d/fail", j.ID), bytes.NewReader(b), 64<<10)
	if err != nil || code != 200 {
		c.e.Log.Warn("fail report failed", "id", j.ID, "kind", j.Kind, "status", code, "err", err, "body", oneLine(string(rb), 160))
	}
	c.e.Log.Warn("job failed", "id", j.ID, "kind", j.Kind, "attempt", j.Attempts, "err", msg)
}

// runScanner ticks a Scan kind every Every (first run at once); errors are logged.
func (c *courier) runScanner(ctx context.Context, k *Kind) {
	t := time.NewTicker(k.Every)
	defer t.Stop()
	for {
		sctx, cancel := context.WithTimeout(ctx, jobTimeout)
		if err := k.Scan(sctx, c.e); err != nil && ctx.Err() == nil {
			c.e.Log.Warn("scanner", "kind", k.Name, "err", oneLine(err.Error(), 300))
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// healthcheck (distroless has no shell): the loop touches HEARTBEAT_FILE every cycle; stale or
// missing for 5 min means the courier is wedged.
func healthcheck() int {
	st, err := os.Stat(env("HEARTBEAT_FILE", "/tmp/courier.alive"))
	if err != nil || time.Since(st.ModTime()) > heartbeatMaxA {
		return 1
	}
	return 0
}
