// Command edge is the internal blue/green reverse proxy (SPEC-v2 21.3): cloudflared -> edge ->
// gateway or gateway-next. The upstream URL lives in a file (EDGE_UPSTREAM_FILE) re-read on
// SIGHUP, so a deploy flips traffic with one signal and no restart. The Rewrite preserves the
// inbound Host (the gateway keys everything on it), copies X-Forwarded-*, caps request bodies at
// 5 MB and passes Retry-After through untouched; when the upstream is unreachable it answers
// 503 + Retry-After: 1 so long-pollers come straight back after a flip.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const maxBody = 5 << 20

type edge struct {
	file  string
	up    atomic.Pointer[url.URL]
	proxy *httputil.ReverseProxy
	log   *slog.Logger
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	e, err := newEdge(env("EDGE_UPSTREAM_FILE", "/etc/edge/upstream"), log)
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go e.watchHUP(ctx)
	srv := &http.Server{Addr: env("EDGE_LISTEN", ":8090"), Handler: e, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 60 * time.Second, WriteTimeout: 130 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10}
	errc := make(chan error, 1)
	go func() {
		log.Info("edge listening", "addr", srv.Addr, "upstream", e.up.Load().String())
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		log.Error("fatal", "err", err)
		os.Exit(1)
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("shutdown", "err", err)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// newEdge loads the upstream file once and builds the proxy.
func newEdge(file string, log *slog.Logger) (*edge, error) {
	if log == nil {
		log = slog.Default()
	}
	e := &edge{file: file, log: log}
	if err := e.reload(); err != nil {
		return nil, err
	}
	e.proxy = &httputil.ReverseProxy{
		Rewrite: e.rewrite,
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          128,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 125 * time.Second, // long-polls run up to 120 s upstream
			ForceAttemptHTTP2:     false,
		},
		FlushInterval: -1, // streams (SSE, chunked exports) flush as they arrive
		ErrorHandler:  e.onError,
		ErrorLog:      slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return e, nil
}

// reload re-reads the upstream file (one URL, http or https, host required) and swaps it in; on
// any error the previous upstream stays.
func (e *edge) reload() error {
	b, err := os.ReadFile(e.file)
	if err != nil {
		return err
	}
	s := strings.TrimSpace(string(b))
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("upstream %q: %w", s, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("upstream %q: want http(s)://host[:port][/prefix]", s)
	}
	e.up.Store(u)
	return nil
}

// watchHUP reloads the upstream on SIGHUP until ctx is done.
func (e *edge) watchHUP(ctx context.Context) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	defer signal.Stop(c)
	for {
		select {
		case <-ctx.Done():
			return
		case <-c:
			if err := e.reload(); err != nil {
				e.log.Error("edge reload failed, keeping upstream", "upstream", e.up.Load().String(), "err", err)
				continue
			}
			e.log.Info("edge upstream reloaded", "upstream", e.up.Load().String())
		}
	}
}

// rewrite targets the current upstream, keeps the inbound Host (never the upstream address) and
// extends X-Forwarded-*: the inbound values are copied, the edge appends its view.
func (e *edge) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(e.up.Load())
	pr.Out.Host = pr.In.Host
	if prior := pr.In.Header.Values("X-Forwarded-For"); len(prior) > 0 {
		pr.Out.Header["X-Forwarded-For"] = append([]string(nil), prior...)
	}
	if host, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
		pr.Out.Header.Set("X-Forwarded-For", strings.TrimSpace(strings.Join(append(pr.Out.Header.Values("X-Forwarded-For"), host), ", ")))
	}
	// Rewrite mode strips the inbound X-Forwarded-Host/Proto: copy them back, fill when absent.
	for _, h := range []string{"X-Forwarded-Host", "X-Forwarded-Proto"} {
		if v := pr.In.Header.Get(h); v != "" {
			pr.Out.Header.Set(h, v)
		}
	}
	if pr.Out.Header.Get("X-Forwarded-Host") == "" {
		pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
	}
	if pr.Out.Header.Get("X-Forwarded-Proto") == "" {
		proto := "http"
		if pr.In.TLS != nil {
			proto = "https"
		}
		pr.Out.Header.Set("X-Forwarded-Proto", proto)
	}
}

// ServeHTTP caps the request body at 5 MB before proxying.
func (e *edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > maxBody {
		w.Header().Set("Retry-After", "120")
		http.Error(w, "err size body too large (5 MB)", http.StatusRequestEntityTooLarge)
		return
	}
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	}
	e.proxy.ServeHTTP(w, r)
}

// onError maps proxy failures: oversized bodies 413, a dead or draining upstream 503 with
// Retry-After: 1 (the flip takes a moment), timeouts 504; a client that went away gets nothing.
func (e *edge) onError(w http.ResponseWriter, r *http.Request, err error) {
	var mbe *http.MaxBytesError
	switch {
	case errors.Is(err, context.Canceled):
		return
	case errors.As(err, &mbe):
		http.Error(w, "err size body too large (5 MB)", http.StatusRequestEntityTooLarge)
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		w.Header().Set("Retry-After", "1")
		http.Error(w, "err upstream timeout", http.StatusGatewayTimeout)
	default:
		e.log.Warn("edge upstream error", "upstream", e.up.Load().String(), "err", err)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "err busy upstream unavailable retry=1", http.StatusServiceUnavailable)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
