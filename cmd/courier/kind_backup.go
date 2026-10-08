package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// backup_ship (SPEC-v2 20): streams ./backups/*.tar.age to an S3-compatible bucket with SigV4,
// write-only by policy. It lists the bucket (ListObjectsV2), PUTs only the local files the bucket
// does not already hold, and reports both lists back through the ack. The S3 host is allowlisted
// through S3_ENDPOINT (never a compiled-in Kind.Hosts), so the kind contributes no host of its own.
const (
	backupMaxUploads = 100
	backupListMax    = 5000
	backupPutTimeout = 15 * time.Minute
)

var (
	backupFileRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.tar\.age$`)
	errS3NoConfig = errors.New("backup_ship: S3_ENDPOINT, S3_BUCKET and secret s3_key required")
)

func init() {
	Register(&Kind{Name: "backup_ship", Run: runBackupShip})
}

type backupResult struct {
	Uploaded []string `json:"uploaded"`
	Skipped  []string `json:"skipped"`
	Remote   []string `json:"remote"`
	Bytes    int64    `json:"bytes"`
}

func runBackupShip(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
	// The payload is advisory (an optional {} trigger); no fields are required.
	if len(job.Payload) > 0 {
		var ignore map[string]any
		if err := json.Unmarshal(job.Payload, &ignore); err != nil {
			return nil, fmt.Errorf("backup_ship: payload: %w", err)
		}
	}
	host := s3Host(e.Getenv("S3_ENDPOINT"))
	bucket := strings.Trim(strings.TrimSpace(e.Getenv("S3_BUCKET")), "/")
	key, secret, err := parseS3Key(e.Secret("s3_key"))
	if host == "" || bucket == "" || err != nil {
		return nil, errS3NoConfig
	}
	if !validHost(host) {
		return nil, fmt.Errorf("backup_ship: S3_ENDPOINT host %q invalid", host)
	}
	signer := newS3Signer(key, secret, e.Getenv("S3_REGION"))
	base := "https://" + host + "/" + bucket

	dir := e.Getenv("BACKUPS_DIR")
	if dir == "" {
		dir = "./backups"
	}
	local, err := localBackups(dir)
	if err != nil {
		return nil, err
	}
	remote, err := s3List(ctx, e, signer, base)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, k := range remote {
		have[k] = true
	}
	res := backupResult{Uploaded: []string{}, Skipped: []string{}, Remote: remote}
	for _, name := range local {
		if have[name] {
			res.Skipped = append(res.Skipped, name)
			continue
		}
		if len(res.Uploaded) >= backupMaxUploads {
			break
		}
		n, err := s3PutFile(ctx, e, signer, base, filepath.Join(dir, name), name)
		if err != nil {
			return nil, err
		}
		res.Uploaded = append(res.Uploaded, name)
		res.Bytes += n
	}
	e.Log.Info("backup_ship", "uploaded", len(res.Uploaded), "skipped", len(res.Skipped), "remote", len(remote), "bytes", res.Bytes)
	return json.Marshal(res)
}

// parseS3Key reads the s3_key secret: "<access-key>:<secret-key>" or the two on separate lines.
func parseS3Key(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", errors.New("empty s3_key")
	}
	var a, b string
	if strings.ContainsAny(s, "\n\r") {
		lines := strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' })
		if len(lines) >= 2 {
			a, b = strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1])
		}
	} else {
		a, b, _ = strings.Cut(s, ":")
		a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	}
	if a == "" || b == "" {
		return "", "", errors.New("s3_key must be access-key:secret-key")
	}
	return a, b, nil
}

// localBackups lists the *.tar.age files directly under dir, sorted, regular files only.
func localBackups(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("backup_ship: read %s: %w", dir, err)
	}
	var out []string
	for _, en := range ents {
		if en.IsDir() || !backupFileRe.MatchString(en.Name()) {
			continue
		}
		if fi, err := en.Info(); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, en.Name())
	}
	sort.Strings(out)
	return out, nil
}

type listBucketResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

// s3List returns the keys in the bucket (ListObjectsV2), following continuation tokens. Only keys
// that look like our backup files are kept.
func s3List(ctx context.Context, e *Env, signer sigV4Signer, base string) ([]string, error) {
	var keys []string
	token := ""
	for page := 0; page < 64; page++ {
		q := url.Values{"list-type": {"2"}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		req, err := http.NewRequest(http.MethodGet, base+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		signer.sign(req, emptyPayloadHash, e.Now())
		code, body, _, err := e.Do(ctx, req, readCap, dialTimeout)
		if err != nil {
			return nil, fmt.Errorf("backup_ship list: %w", err)
		}
		if code/100 != 2 {
			return nil, statusErr("backup_ship list", code, body)
		}
		var res listBucketResult
		if err := xml.Unmarshal(body, &res); err != nil {
			return nil, fmt.Errorf("backup_ship list: %w", err)
		}
		for _, c := range res.Contents {
			k := strings.TrimPrefix(c.Key, "/")
			if backupFileRe.MatchString(k) {
				keys = append(keys, k)
			}
			if len(keys) >= backupListMax {
				break
			}
		}
		if !res.IsTruncated || res.NextContinuationToken == "" || len(keys) >= backupListMax {
			break
		}
		token = res.NextContinuationToken
	}
	sort.Strings(keys)
	return keys, nil
}

// s3PutFile uploads one local file, SigV4-signed with the file's content hash; the body is read once
// to hash and once to stream so nothing large is held in memory.
func s3PutFile(ctx context.Context, e *Env, signer sigV4Signer, base, path, key string) (int64, error) {
	hash, size, err := fileSHA256(path)
	if err != nil {
		return 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	req, err := http.NewRequest(http.MethodPut, base+"/"+awsURIEncode(key, false), f)
	if err != nil {
		return 0, err
	}
	req.ContentLength = size
	signer.sign(req, hash, e.Now())
	code, body, _, err := e.Do(ctx, req, readCap, backupPutTimeout)
	if err != nil {
		return 0, fmt.Errorf("backup_ship put %s: %w", key, err)
	}
	if code/100 != 2 {
		return 0, statusErr("backup_ship put "+key, code, body)
	}
	return size, nil
}

// fileSHA256 streams the file through SHA-256 and returns the hex digest and byte count.
func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
