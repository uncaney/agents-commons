// Package egress is the gateway side of the courier (SPEC-v2 20, 9.6). The outbox routes live on
// their own http.Server bound to INTERNAL_LISTEN (Serve / InternalHandler), never on the public
// mux, and require `Authorization: Bearer <COURIER_TOKEN>` compared in constant time; ack results
// are handed to ResultFn[kind]. Register mounts the ONLY public route, GET /<indexnow-key>.txt.
// RegisterInternal lets other packages add bearer-protected /internal/* routes (never public).
package egress

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

const (
	MaxWait     = 55               // seconds a poll may block (wait<=55, 20)
	MaxAttempts = 10               // dead-letter threshold (20)
	Lease       = 10 * time.Minute // a claimed row is invisible to further polls for this long
	MaxResult   = 256 << 10        // ack body cap (payloads are <= 64 KiB; results may be larger)
	MaxFailBody = 4 << 10
	maxErrLen   = 500
	pollEvery   = time.Second
	baseBackoff = 60.0    // seconds, doubled per failed attempt
	maxBackoff  = 21600.0 // 6 h
)

// ResultFunc handles the result a courier posted with an ack, inside the ack's transaction: payload
// is the row's payload, result the courier's JSON (nil when the ack carried none). Both are
// courier-produced, so handlers validate shape and sizes. An error rolls the ack back (500 to the
// courier); the row is re-leased after Lease and the kind runs again (at-least-once).
type ResultFunc func(ctx context.Context, d *core.Deps, q core.Q, payload, result json.RawMessage) error

// ResultFn maps a kind to its result handler. Set at boot, before Serve (the integration package).
var ResultFn = map[string]ResultFunc{}

// Row is one outbox job as the courier receives it.
type Row struct {
	ID       int64           `json:"id"`
	Kind     string          `json:"kind"`
	Payload  json.RawMessage `json:"payload"`
	Attempts int             `json:"attempts"`
	Created  time.Time       `json:"created"`
}

var kindRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

type route struct {
	pattern string
	h       http.HandlerFunc
}

var (
	imu            sync.Mutex
	internalRoutes []route
)

// RegisterInternal adds a route to the INTERNAL_LISTEN mux, behind the same courier bearer as the
// egress routes (demand's GET /internal/render?url=). The pattern's path must start with
// /internal/. Call before Serve / InternalHandler.
func RegisterInternal(pattern string, h http.HandlerFunc) {
	p := pattern
	if i := strings.IndexByte(p, ' '); i >= 0 {
		p = strings.TrimSpace(p[i+1:])
	}
	if !strings.HasPrefix(p, "/internal/") || h == nil {
		panic("egress.RegisterInternal: pattern must be [METHOD ]/internal/... with a handler")
	}
	imu.Lock()
	defer imu.Unlock()
	for _, r := range internalRoutes {
		if r.pattern == pattern {
			panic("egress.RegisterInternal: duplicate pattern " + pattern)
		}
	}
	internalRoutes = append(internalRoutes, route{pattern, h})
}

// IndexNowKey derives the IndexNow key (9.6): hex(HMAC(server_secret, "indexnow"))[:32].
func IndexNowKey(secret []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("indexnow"))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// Register mounts the only public route of this package, GET /<indexnow-key>.txt, and the outbox
// sweep janitor task. No /internal/* route is ever mounted on the public mux.
func Register(mux *http.ServeMux, d *core.Deps) {
	key := IndexNowKey(d.Cfg.ServerSecret)
	mux.HandleFunc("GET /"+key+".txt", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Cache-Control", "public, max-age=86400")
		io.WriteString(w, key)
	})
	if d.Janitor != nil {
		d.Janitor.Add("egress_sweep", func(ctx context.Context) error { return Sweep(ctx, d.DB) })
	}
}

// Serve runs the internal server on addr (INTERNAL_LISTEN) until ctx is done.
func Serve(ctx context.Context, d *core.Deps, addr string) error {
	if d.Cfg.CourierToken == "" {
		d.Log.Warn("egress: COURIER_TOKEN unset, every /internal/* request answers 401")
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           InternalHandler(d),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      (MaxWait + 15) * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		d.Log.Info("egress listening", "addr", addr)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type server struct{ d *core.Deps }

// InternalHandler builds the INTERNAL_LISTEN handler: recovery and bearer auth around the egress
// routes and every RegisterInternal route. Each call builds a fresh mux.
func InternalHandler(d *core.Deps) http.Handler {
	s := &server{d: d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/egress", s.next)
	mux.HandleFunc("POST /internal/egress/{id}/ack", s.ack)
	mux.HandleFunc("POST /internal/egress/{id}/fail", s.fail)
	mux.HandleFunc("GET /internal/config", s.config)
	imu.Lock()
	for _, r := range internalRoutes {
		mux.HandleFunc(r.pattern, r.h)
	}
	imu.Unlock()
	return s.wrap(mux)
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(c int) {
	if !w.wrote {
		w.status, w.wrote = c, true
		w.ResponseWriter.WriteHeader(c)
	}
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}

func (s *server) wrap(next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(s.d.Cfg.CourierToken))
	configured := s.d.Cfg.CourierToken != ""
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				s.d.Log.Error("egress panic", "path", r.URL.Path, "err", rec)
				if !sw.wrote {
					core.Err(sw, r, 500, "internal", "internal error")
				}
			}
			if sw.status != 204 {
				s.d.Log.Info("egress", "m", r.Method, "p", r.URL.Path, "s", sw.status, "ms", time.Since(start).Milliseconds())
			}
		}()
		w.Header().Set("Cache-Control", "no-store")
		if !configured || !bearerOK(r, want) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="courier"`)
			core.Err(sw, r, 401, "auth", "courier token required")
			return
		}
		next.ServeHTTP(sw, r)
	})
}

// bearerOK compares the presented bearer with the configured token over fixed-length digests.
func bearerOK(r *http.Request, want [32]byte) bool {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "Bearer ") {
		return false
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(h[7:])))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// ParseKinds validates the comma-separated kinds filter of a poll (1..32 kind names).
func ParseKinds(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, k := range strings.Split(s, ",") {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if !kindRe.MatchString(k) {
			return nil, core.Bad("kinds: bad kind name")
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
		if len(out) > 32 {
			return nil, core.Bad("kinds: too many")
		}
	}
	if len(out) == 0 {
		return nil, core.Bad("kinds required (comma-separated kind names)")
	}
	return out, nil
}

// next serves GET /internal/egress?kinds=&wait=: the next due row (JSON) or 204 after waiting up to
// wait seconds; 204 at once while freeze:egress is on.
func (s *server) next(w http.ResponseWriter, r *http.Request) {
	kinds, err := ParseKinds(r.URL.Query().Get("kinds"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	wait := 0
	if v := r.URL.Query().Get("wait"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			core.Fail(w, r, core.Bad("wait must be 0.."+strconv.Itoa(MaxWait)))
			return
		}
		wait = min(n, MaxWait)
	}
	ctx := r.Context()
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		if s.d.Frozen("egress") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		row, err := Claim(ctx, s.d.DB, kinds)
		if err != nil {
			if ctx.Err() == nil {
				core.Fail(w, r, err)
			}
			return
		}
		if row != nil {
			core.JSON(w, 200, row)
			return
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t := time.NewTimer(min(rem, pollEvery))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *server) ack(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		core.Fail(w, r, core.ErrNotFound)
		return
	}
	var in struct {
		Result json.RawMessage `json:"result"`
	}
	if err := core.Decode(w, r, MaxResult, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	res := bytes.TrimSpace(in.Result)
	if bytes.Equal(res, []byte("null")) {
		res = nil
	}
	if err := Ack(r.Context(), s.d, id, res); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.JSON(w, 200, map[string]any{"ok": true, "id": id})
}

func (s *server) fail(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		core.Fail(w, r, core.ErrNotFound)
		return
	}
	var in struct {
		Err string `json:"err"`
	}
	if err := core.Decode(w, r, MaxFailBody, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	if err := Fail(r.Context(), s.d.DB, id, in.Err); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.JSON(w, 200, map[string]any{"ok": true, "id": id})
}

// config serves GET /internal/config: what the courier cannot derive itself (the IndexNow key is an
// HMAC of the server secret) plus the public URL its kinds build URLs against.
func (s *server) config(w http.ResponseWriter, r *http.Request) {
	core.JSON(w, 200, map[string]any{
		"public_url":   s.d.Cfg.PublicURL,
		"indexnow_key": IndexNowKey(s.d.Cfg.ServerSecret),
		"frozen":       s.d.Frozen("egress"),
	})
}

// Claim leases the next due row of the given kinds (attempts+1, invisible for Lease); nil when none.
func Claim(ctx context.Context, q core.Q, kinds []string) (*Row, error) {
	var row Row
	err := q.QueryRow(ctx, `UPDATE egress_outbox o SET attempts = o.attempts + 1, next_at = now() + make_interval(secs => $2)
		WHERE o.id = (SELECT id FROM egress_outbox WHERE done_at IS NULL AND next_at <= now()
			AND kind = ANY($1) AND attempts < $3 ORDER BY next_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING o.id, o.kind, o.payload, o.attempts, o.created`,
		kinds, Lease.Seconds(), MaxAttempts).Scan(&row.ID, &row.Kind, &row.Payload, &row.Attempts, &row.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// Ack marks a live row done and dispatches its result to ResultFn[kind] in the same transaction.
// ErrNotFound when the row does not exist or is already done.
func Ack(ctx context.Context, d *core.Deps, id int64, result json.RawMessage) error {
	if len(result) > MaxResult {
		return core.ErrSize
	}
	if len(result) > 0 && !json.Valid(result) {
		return core.Bad("result: invalid json")
	}
	return core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		var kind string
		var payload json.RawMessage
		err := tx.QueryRow(ctx, `UPDATE egress_outbox SET done_at = now(), last_err = ''
			WHERE id = $1 AND done_at IS NULL RETURNING kind, payload`, id).Scan(&kind, &payload)
		if errors.Is(err, pgx.ErrNoRows) {
			return core.ErrNotFound
		}
		if err != nil {
			return err
		}
		if fn := ResultFn[kind]; fn != nil {
			if err := fn(ctx, d, tx, payload, result); err != nil {
				return fmt.Errorf("egress result %s #%d: %w", kind, id, err)
			}
		}
		return nil
	})
}

// Fail records a failure on a live row with exponential backoff (60 s doubling, <= 6 h); at
// MaxAttempts the row is dead-lettered (done with last_err "dead-letter: ..."). ErrNotFound when the
// row does not exist or is already done.
func Fail(ctx context.Context, q core.Q, id int64, msg string) error {
	msg = oneLine(msg, maxErrLen)
	if msg == "" {
		msg = "failed"
	}
	tag, err := q.Exec(ctx, `UPDATE egress_outbox SET
		last_err = CASE WHEN attempts >= $3 THEN 'dead-letter: ' || $2 ELSE $2 END,
		done_at = CASE WHEN attempts >= $3 THEN now() ELSE NULL END,
		next_at = now() + make_interval(secs => least($4 * power(2, greatest(attempts - 1, 0)), $5))
		WHERE id = $1 AND done_at IS NULL`, id, msg, MaxAttempts, baseBackoff, maxBackoff)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return nil
}

// Sweep (janitor) dead-letters rows that reached MaxAttempts without a report and deletes done
// rows older than 7 days (daily caps count rows of the last day only, 20).
func Sweep(ctx context.Context, q core.Q) error {
	if _, err := q.Exec(ctx, `UPDATE egress_outbox SET done_at = now(), last_err = 'dead-letter: no report'
		WHERE done_at IS NULL AND attempts >= $1 AND next_at < now()`, MaxAttempts); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `DELETE FROM egress_outbox WHERE done_at IS NOT NULL AND done_at < now() - interval '7 days'`)
	return err
}

// oneLine makes s a single safe line of at most max runes (control chars -> space, invalid UTF-8
// dropped): last_err is rendered on admin pages and must never start a line of its own.
func oneLine(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if max > 0 && utf8.RuneCountInString(s) > max {
		s = strings.TrimSpace(string([]rune(s)[:max]))
	}
	return s
}
