package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4 for S3 (SPEC-v2 20, kind backup_ship), stdlib only. The signer builds the
// canonical request, string-to-sign and signing key exactly as the AWS documentation describes and
// is covered by the published AWS test vectors (sigv4_test.go). It signs every header present on the
// request at signing time (always including host), so the caller controls the signed set by setting
// only the headers it means to sign before calling.
const (
	sigV4Algorithm   = "AWS4-HMAC-SHA256"
	sigV4Request     = "aws4_request"
	sigV4Service     = "s3"
	amzTimeFmt       = "20060102T150405Z"
	amzDateFmt       = "20060102"
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // sha256("")
	unsignedPayload  = "UNSIGNED-PAYLOAD"
)

// sigV4Signer holds the credentials and the target region/service.
type sigV4Signer struct {
	accessKey, secretKey, region, service string
}

func newS3Signer(accessKey, secretKey, region string) sigV4Signer {
	if region == "" {
		region = "us-east-1"
	}
	return sigV4Signer{accessKey: accessKey, secretKey: secretKey, region: region, service: sigV4Service}
}

// sign sets x-amz-date (unless already set), x-amz-content-sha256 and Authorization on req. The
// request's existing headers are all folded into the signature.
func (s sigV4Signer) sign(req *http.Request, payloadHash string, t time.Time) {
	if payloadHash == "" {
		payloadHash = emptyPayloadHash
	}
	if req.Header.Get("x-amz-date") == "" {
		req.Header.Set("x-amz-date", t.UTC().Format(amzTimeFmt))
	}
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("Authorization", s.authorization(req, payloadHash, t))
}

// authorization computes the full Authorization header value without mutating req; every header set
// on req (minus Authorization) plus host is signed.
func (s sigV4Signer) authorization(req *http.Request, payloadHash string, t time.Time) string {
	amzDate := req.Header.Get("x-amz-date")
	if amzDate == "" {
		amzDate = t.UTC().Format(amzTimeFmt)
	}
	dateStamp := amzDate
	if len(amzDate) >= 8 {
		dateStamp = amzDate[:8]
	}
	canonicalHeaders, signedHeaders := canonicalHeaders(req)
	canonicalReq := strings.Join([]string{
		req.Method,
		canonicalURI(req),
		canonicalQuery(req),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
	scope := dateStamp + "/" + s.region + "/" + s.service + "/" + sigV4Request
	stringToSign := strings.Join([]string{
		sigV4Algorithm,
		amzDate,
		scope,
		hexSHA256([]byte(canonicalReq)),
	}, "\n")
	signingKey := s.signingKey(dateStamp)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	return sigV4Algorithm + " Credential=" + s.accessKey + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

// signingKey derives the SigV4 signing key for the day.
func (s sigV4Signer) signingKey(dateStamp string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+s.secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, s.region)
	kService := hmacSHA256(kRegion, s.service)
	return hmacSHA256(kService, sigV4Request)
}

// canonicalHeaders returns the canonical header block and the semicolon-joined signed-header list.
// Every header present on req is signed (Authorization excepted), always including host.
func canonicalHeaders(req *http.Request) (string, string) {
	vals := map[string][]string{}
	add := func(name, v string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "authorization" || name == "" {
			return
		}
		vals[name] = append(vals[name], trimAll(v))
	}
	add("host", hostHeader(req))
	for name, vs := range req.Header {
		if strings.EqualFold(name, "host") {
			continue
		}
		for _, v := range vs {
			add(name, v)
		}
	}
	names := make([]string, 0, len(vals))
	for n := range vals {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(strings.Join(vals[n], ","))
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(names, ";")
}

// hostHeader is the host the request is addressed to (req.Host wins, then the URL host).
func hostHeader(req *http.Request) string {
	if req.Host != "" {
		return req.Host
	}
	return req.URL.Host
}

// canonicalURI is the URI-encoded path with slashes preserved (S3 encodes once).
func canonicalURI(req *http.Request) string {
	p := req.URL.Path
	if p == "" {
		return "/"
	}
	return awsURIEncode(p, true)
}

// canonicalQuery sorts the query parameters and URI-encodes keys and values (slashes encoded).
func canonicalQuery(req *http.Request) string {
	raw := req.URL.RawQuery
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, p := range strings.Split(raw, "&") {
		if p == "" {
			continue
		}
		k, v, _ := strings.Cut(p, "=")
		pairs = append(pairs, kv{awsURIEncode(decodeQueryComponent(k), false), awsURIEncode(decodeQueryComponent(v), false)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

// decodeQueryComponent decodes %XX escapes and '+' as space so re-encoding is canonical; on any
// malformed escape the component is used verbatim.
func decodeQueryComponent(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '+':
			b.WriteByte(' ')
		case s[i] == '%' && i+2 < len(s):
			h := fromHex(s[i+1])<<4 | fromHex(s[i+2])
			if h < 0 {
				return s
			}
			b.WriteByte(byte(h))
			i += 2
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func fromHex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}

// awsURIEncode encodes per RFC 3986 the AWS way: A-Za-z0-9-_.~ are literal, '/' is kept when
// keepSlash, every other byte becomes %XX (uppercase hex).
func awsURIEncode(s string, keepSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte('/')
		default:
			b.WriteByte('%')
			b.WriteByte(hexUpper[c>>4])
			b.WriteByte(hexUpper[c&0x0f])
		}
	}
	return b.String()
}

const hexUpper = "0123456789ABCDEF"

// trimAll trims the value and collapses internal runs of whitespace to single spaces (SigV4 rule
// for unquoted header values).
func trimAll(v string) string {
	return strings.Join(strings.Fields(v), " ")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
