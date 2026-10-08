package sync

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/export"
)

// params are the GET /v1/sync (and op sync) arguments.
type params struct {
	kinds    []string
	after    int64
	hasAfter bool
	k        int
}

var syncKindSet = []string{"kb", "claim", "digest", "task", "svc"}

// parseParams validates the query of GET /v1/sync.
func parseParams(q map[string][]string) (params, error) {
	var p params
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	if s := get("kinds"); s != "" {
		for _, k := range strings.Split(s, ",") {
			k = strings.ToLower(strings.TrimSpace(k))
			if k == "" {
				continue
			}
			if !slices.Contains(syncKindSet, k) {
				return p, core.Bad("kinds must be a comma list of kb|claim|digest|task|svc")
			}
			if !slices.Contains(p.kinds, k) {
				p.kinds = append(p.kinds, k)
			}
		}
	}
	if s := get("after"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 {
			return p, core.Bad("after must be a sequence number")
		}
		p.after, p.hasAfter = n, true
	}
	if s := get("k"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > MaxK {
			return p, core.Bad("k must be 1.." + strconv.Itoa(MaxK))
		}
		p.k = n
	}
	return p, nil
}

func (p params) limit() int {
	if p.k <= 0 {
		return DefK
	}
	return min(p.k, MaxK)
}

// fetchLog reads up to limit sync_log rows past the cursor, filtered by kinds.
func (s *Service) fetchLog(ctx context.Context, p params, limit int) ([]logRow, error) {
	var b strings.Builder
	b.WriteString(`SELECT seq, op, kind, id, at FROM sync_log WHERE seq > $1`)
	args := []any{p.after}
	if len(p.kinds) > 0 {
		args = append(args, p.kinds)
		fmt.Fprintf(&b, ` AND kind = ANY($%d)`, len(args))
	}
	args = append(args, limit)
	fmt.Fprintf(&b, ` ORDER BY seq LIMIT $%d`, len(args))
	rows, err := s.q().Query(ctx, b.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []logRow
	for rows.Next() {
		var lr logRow
		if err := rows.Scan(&lr.Seq, &lr.Op, &lr.Kind, &lr.ID, &lr.At); err != nil {
			return nil, err
		}
		out = append(out, lr)
	}
	return out, rows.Err()
}

// head is the greatest sync_log seq (0 when empty).
func (s *Service) head(ctx context.Context) (int64, error) {
	var h int64
	err := s.q().QueryRow(ctx, `SELECT coalesce(max(seq), 0) FROM sync_log`).Scan(&h)
	return h, err
}

// page renders one NDJSON page past p.after: whole lines up to MaxBytes, and the seq to continue
// from. An upsert whose object is no longer indexable is downgraded to delete inside line().
func (s *Service) page(ctx context.Context, p params) (body []byte, next int64, err error) {
	limit := p.limit()
	rows, err := s.fetchLog(ctx, p, limit)
	if err != nil {
		return nil, 0, err
	}
	next = p.after
	var buf bytes.Buffer
	for _, lr := range rows {
		wl, err := s.line(ctx, lr)
		if err != nil {
			return nil, 0, err
		}
		b, err := encodeLine(wl)
		if err != nil {
			return nil, 0, err
		}
		if buf.Len() > 0 && buf.Len()+len(b) > MaxBytes {
			break
		}
		buf.Write(b)
		next = lr.Seq
	}
	return buf.Bytes(), next, nil
}

// hSync serves GET /v1/sync: anonymous, cost 3, <= 1 MiB application/x-ndjson, refused under
// shed:feeds. The continuation travels in X-Next and Link rel=next; the body carries an ETag.
func (s *Service) hSync(w http.ResponseWriter, r *http.Request) {
	if s.d.Shed(r, "feeds") {
		doc.Fail(w, r, core.ErrBusy("feeds"))
		return
	}
	if _, err := s.d.AuthOpt(r); err != nil {
		doc.Fail(w, r, err)
		return
	}
	p, err := parseParams(r.URL.Query())
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	ctx := r.Context()
	head, err := s.head(ctx)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if p.after > head {
		p.after = head
	}
	body, next, err := s.page(ctx, p)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	nextPath := "/v1/sync?after=" + strconv.FormatInt(next, 10)
	if len(p.kinds) > 0 {
		nextPath += "&kinds=" + strings.Join(p.kinds, ",")
	}
	h := w.Header()
	h.Set("Content-Type", "application/x-ndjson")
	h.Set("Cache-Control", "public, max-age=10")
	sum := sha256.Sum256(body)
	h.Set("ETag", fmt.Sprintf(`"%d-%s"`, next, hex.EncodeToString(sum[:8])))
	h.Set("X-Next", "GET "+nextPath)
	h.Add("Link", "<"+nextPath+`>; rel="next"`)
	if inm := r.Header.Get("If-None-Match"); inm != "" && inm == h.Get("ETag") {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

// --- delta shards --------------------------------------------------------------------------------

const dateFmt = "2006-01-02"

// deltaName is the materialised shard for a UTC date.
func deltaName(date string) string { return "delta-" + date + ".jsonl.gz" }

// delta is the janitor task: once per UTC day, materialise the previous closed day's sync_log
// rows into EXPORT_DIR as delta-<date>.jsonl.gz (gzip NDJSON), recorded in the flag sync:<date>.
func (s *Service) delta(ctx context.Context) error {
	now := time.Now().UTC()
	today := now.Format(dateFmt)
	// Materialise yesterday (a now-closed day, written once) and today (rewritten each tick so a
	// fresh day appears promptly). Only the closed day gets a done flag.
	for _, date := range []string{now.AddDate(0, 0, -1).Format(dateFmt), today} {
		if date != today && s.d.Flag("sync:"+date) {
			continue
		}
		if err := s.writeDelta(ctx, date); err != nil {
			return err
		}
		if date != today {
			if err := s.d.SetFlag(ctx, "sync:"+date, true, ""); err != nil {
				return err
			}
		}
	}
	// Drop day flags older than retention.
	_, err := s.d.DB.Exec(ctx, `DELETE FROM flags WHERE k LIKE 'sync:____-__-__' AND k < $1`,
		"sync:"+now.Add(-Retention).Format(dateFmt))
	return err
}

// writeDelta streams one UTC day's rows into EXPORT_DIR/delta-<date>.jsonl.gz (tmp + rename).
func (s *Service) writeDelta(ctx context.Context, date string) error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	name := deltaName(date)
	f, err := os.CreateTemp(s.dir, "."+name+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	gz := gzip.NewWriter(f)
	rows, err := s.q().Query(ctx, `SELECT seq, op, kind, id, at FROM sync_log
		WHERE at >= $1::date AND at < ($1::date + interval '1 day') ORDER BY seq`, date)
	if err != nil {
		f.Close()
		return err
	}
	for rows.Next() {
		var lr logRow
		if err := rows.Scan(&lr.Seq, &lr.Op, &lr.Kind, &lr.ID, &lr.At); err != nil {
			rows.Close()
			f.Close()
			return err
		}
		wl, err := s.line(ctx, lr)
		if err != nil {
			rows.Close()
			f.Close()
			return err
		}
		b, err := encodeLine(wl)
		if err != nil {
			rows.Close()
			f.Close()
			return err
		}
		if _, err := gz.Write(b); err != nil {
			rows.Close()
			f.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		f.Close()
		return err
	}
	rows.Close()
	if err := gz.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, name))
}

// extraFiles lists the delta shards on disk for the export manifest (export.ExtraFileFn): the
// export package measures each file's size/sha on disk; we supply the row count hint.
func (s *Service) extraFiles(ctx context.Context) ([]export.ManifestFile, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []export.ManifestFile
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "delta-") || !strings.HasSuffix(name, ".jsonl.gz") {
			continue
		}
		rows, _ := countGzipLines(filepath.Join(s.dir, name))
		out = append(out, export.ManifestFile{Name: name, Rows: rows})
	}
	return out, nil
}

// countGzipLines counts the lines of a gzip file.
func countGzipLines(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, err
	}
	defer gz.Close()
	var n int64
	buf := make([]byte, 32<<10)
	for {
		k, err := gz.Read(buf)
		for _, b := range buf[:k] {
			if b == '\n' {
				n++
			}
		}
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

var openAPI = json.RawMessage(`{"paths":{
"/v1/sync":{"get":{"operationId":"sync","summary":"Row-level replication log as NDJSON (anonymous, cost 3, <= 1 MiB): one object per line {seq, op (upsert|delete), kind (kb|claim|digest|task|svc), id, at, row, sig}. Hidden/quarantined/purged rows appear only as delete, never with content. row carries a server signature (type row1; verify against /.well-known/cx-key). Continue from X-Next (?after=<seq>).","parameters":[{"name":"kinds","in":"query","schema":{"type":"string"},"description":"comma list of kb|claim|digest|task|svc"},{"name":"after","in":"query","schema":{"type":"integer"},"description":"cursor: rows with seq > after"},{"name":"k","in":"query","schema":{"type":"integer","maximum":200}}],"responses":{"200":{"description":"application/x-ndjson; X-Next + Link rel=next + ETag"},"503":{"description":"err busy shed:feeds"}}}}
}}`)
