package export

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Remove propagates a removal to the dumps (9.5; core.ExportRemoveFn): every retained shard of
// the kind (and every delta shard) is streamed, lines carrying id are dropped and the file is
// rewritten under its own name; a tombstone is appended; manifest, SHA256SUMS and SIGNATURES
// are regenerated; the courier gets cf_purge (the /export/ URLs), mirror_rewrite and hf for the
// rewritten shards. No-op until Register ran. The work never depends on the caller's context: it
// runs to completion under its own 2 min cap so a cancelled request cannot leave a half-rewrite.
func Remove(ctx context.Context, kind, id string) {
	s := cur.Load()
	if s == nil {
		return
	}
	if err := s.remove(ctx, kind, id); err != nil {
		s.d.Log.Warn("export remove", "kind", kind, "id", id, "err", err)
	}
}

// shardPrefix maps a removal kind to its shard file prefix after validating the id.
func shardPrefix(kind, id string) (string, bool) {
	if !validTombstoneID(kind, id) {
		return "", false
	}
	switch kind {
	case "kb":
		return "kb-", true
	case "task":
		return "tasks-", true
	case "claim":
		return "claims-", true
	case "digest":
		return "digests-", true
	}
	return "", false
}

func (s *Service) remove(ctx context.Context, kind, id string) error {
	prefix, ok := shardPrefix(kind, id)
	if !ok {
		return core.Bad("export remove: kind/id")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	fresh := map[string]ManifestFile{}
	rewritten := []string{}
	for _, e := range entries {
		name := e.Name()
		if !FileRe.MatchString(name) || !(strings.HasPrefix(name, prefix) || strings.HasPrefix(name, "delta-")) {
			continue
		}
		mf, changed, err := s.filterFile(name, id)
		if err != nil {
			return err
		}
		if changed {
			fresh[name] = mf
			rewritten = append(rewritten, name)
		}
	}
	now := s.now().UTC()
	if err := s.writeTombstoneFile([]tombstone{{ID: id, Kind: kind, RemovedAt: now, Reason: "removed"}}, now.Add(-tombstoneTTL)); err != nil {
		return err
	}
	date := now.Format(dateFmt)
	if prev := s.manifest(); prev != nil && prev.Date != "" {
		date = prev.Date
	}
	if err := s.finish(ctx, date, fresh); err != nil {
		return err
	}
	base := doc.Base()
	urls := []string{base + "/export/", base + "/export/manifest.json", base + "/export/SHA256SUMS", base + "/export/SIGNATURES",
		base + "/export/tombstones.jsonl", base + "/export/croissant.json", base + "/export/latest.jsonl.gz"}
	for _, n := range rewritten {
		urls = append(urls, base+"/export/"+n)
	}
	s.egress(ctx, "cf_purge", map[string]any{"urls": urls})
	s.egress(ctx, "mirror_rewrite", map[string]any{"kind": kind, "id": id, "files": rewritten})
	for _, n := range rewritten {
		if !strings.HasPrefix(n, "delta-") {
			s.egress(ctx, "hf", map[string]any{"file": n})
		}
	}
	s.recordUsage(ctx)
	return nil
}

// filterFile rewrites one shard without the lines whose id matches; false when nothing matched
// (the file is left untouched).
func (s *Service) filterFile(name, id string) (ManifestFile, bool, error) {
	src, err := os.Open(filepath.Join(s.dir, name))
	if err != nil {
		return ManifestFile{}, false, err
	}
	defer src.Close()
	gz, err := gzip.NewReader(src)
	if err != nil {
		return ManifestFile{}, false, err
	}
	defer gz.Close()
	var kept, dropped int64
	size, sum, err := s.writeAtomic(name, func(w io.Writer) error {
		out := gzip.NewWriter(w)
		sc := bufio.NewScanner(gz)
		sc.Buffer(make([]byte, 64<<10), maxLine)
		for sc.Scan() {
			line := sc.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			if lineID(line) == id {
				dropped++
				continue
			}
			kept++
			if _, err := out.Write(line); err != nil {
				return err
			}
			if _, err := out.Write([]byte{'\n'}); err != nil {
				return err
			}
		}
		if err := sc.Err(); err != nil {
			return err
		}
		if dropped == 0 {
			return errUnchanged
		}
		return out.Close()
	})
	if errors.Is(err, errUnchanged) {
		return ManifestFile{}, false, nil
	}
	if err != nil {
		return ManifestFile{}, false, err
	}
	return ManifestFile{Name: name, Size: size, SHA256: sum, Rows: kept}, true, nil
}

// lineID extracts the top-level id of a JSONL row as a string (numbers rendered plainly).
func lineID(line []byte) string {
	var v struct {
		ID any `json:"id"`
	}
	if json.Unmarshal(line, &v) != nil {
		return ""
	}
	switch x := v.ID.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}
