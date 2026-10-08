package gitmirror

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"ekaii.fr/commons/internal/doc"
)

// Tarball cache (7.3): GET /git/kb.tar.gz serves EXPORT_DIR/kb-git.tar.gz, refreshed from the
// archive API when older than TarballTTL. One download runs at a time (waiters share it); when
// the upstream fails the stale file is served and the next attempt waits TarballRetry.
var (
	TarballTTL     = 24 * time.Hour
	TarballRetry   = 5 * time.Minute
	TarballTimeout = 10 * time.Minute
	TarballMax     = int64(2 << 30) // the mirror freezes past 2 GiB (7.3)
)

const (
	tarName = "kb-git.tar.gz"
	apiRepo = "/api/v1/repos/commons/kb"
)

var (
	branchRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	errBackoff = errors.New("tarball: upstream failed recently")
)

type flight struct {
	done chan struct{}
	err  error
}

func (s *svc) tarPath() string { return filepath.Join(s.d.Cfg.ExportDir, tarName) }

func (s *svc) tarball(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawPath != "" || r.URL.RawQuery != "" {
		s.other(w, r)
		return
	}
	path := s.tarPath()
	st, err := os.Stat(path)
	if err != nil || time.Since(st.ModTime()) >= TarballTTL {
		if rerr := s.refresh(r.Context()); rerr != nil {
			if err != nil {
				s.d.Log.Warn("gitmirror tarball", "err", rerr)
				doc.Fail(w, r, errUpstream)
				return
			}
			s.d.Log.Warn("gitmirror tarball: serving stale snapshot", "err", rerr)
		}
		if st, err = os.Stat(path); err != nil {
			doc.Fail(w, r, errUpstream)
			return
		}
	}
	f, err := os.Open(path)
	if err != nil {
		doc.Fail(w, r, errUpstream)
		return
	}
	defer f.Close()
	h := w.Header()
	h.Set("Content-Type", "application/gzip")
	h.Set("Content-Disposition", `attachment; filename="kb.tar.gz"`)
	h.Set("Cache-Control", "public, max-age=3600")
	h.Set("X-Robots-Tag", "noindex")
	http.ServeContent(w, r, "", st.ModTime(), f)
}

// refresh joins or starts the single download; ctx bounds only the wait, the download itself
// runs under TarballTimeout. After a failure every caller gets errBackoff until TarballRetry passes.
func (s *svc) refresh(ctx context.Context) error {
	s.tmu.Lock()
	if s.inflight == nil {
		if time.Now().Before(s.failUntil) {
			s.tmu.Unlock()
			return fmt.Errorf("%w, retry after %s", errBackoff, s.failUntil.UTC().Format(time.RFC3339))
		}
		fl := &flight{done: make(chan struct{})}
		s.inflight = fl
		go func() {
			fl.err = s.download()
			s.tmu.Lock()
			s.inflight = nil
			if fl.err != nil {
				s.failUntil = time.Now().Add(TarballRetry)
			}
			s.tmu.Unlock()
			close(fl.done)
		}()
	}
	fl := s.inflight
	s.tmu.Unlock()
	select {
	case <-fl.done:
		return fl.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// download fetches <default branch>.tar.gz into a temp file next to the cache and renames it in
// place; the body must be gzip (magic bytes) and at most TarballMax.
func (s *svc) download() error {
	ctx, cancel := context.WithTimeout(context.Background(), TarballTimeout)
	defer cancel()
	branch := s.defaultBranch(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.upstream(apiRepo+"/archive/"+url.PathEscape(branch)+".tar.gz", "").String(), nil)
	if err != nil {
		return err
	}
	s.auth(req)
	res, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("archive api: status %d", res.StatusCode)
	}
	br := bufio.NewReader(io.LimitReader(res.Body, TarballMax+1))
	if magic, err := br.Peek(2); err != nil || !bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		return errors.New("archive api: not a gzip body")
	}
	dir := s.d.Cfg.ExportDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, tarName+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	n, err := io.Copy(tmp, br)
	if err != nil {
		tmp.Close()
		return err
	}
	if n > TarballMax {
		tmp.Close()
		return fmt.Errorf("archive larger than %d bytes", TarballMax)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.tarPath())
}

// defaultBranch asks the repo API; "main" (what forge creates) when unavailable or odd.
func (s *svc) defaultBranch(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.upstream(apiRepo, "").String(), nil)
	if err != nil {
		return "main"
	}
	s.auth(req)
	req.Header.Set("Accept", "application/json")
	res, err := s.hc.Do(req)
	if err != nil {
		return "main"
	}
	defer res.Body.Close()
	var v struct {
		DefaultBranch string `json:"default_branch"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&v) != nil || !branchRe.MatchString(v.DefaultBranch) {
		return "main"
	}
	return v.DefaultBranch
}
