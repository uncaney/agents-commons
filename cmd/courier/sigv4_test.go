package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The published AWS S3 SigV4 examples ("Authenticating Requests: Using the Authorization Header",
// Signature Version 4 test suite). The example credentials are AWS's own documentation values.
const (
	awsExAccessKey = "AKIAIOSFODNN7EXAMPLE"
	awsExSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

func awsExTime(t *testing.T) time.Time {
	t.Helper()
	tm, err := time.Parse(amzTimeFmt, "20130524T000000Z")
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// sigOf extracts the Signature= token from an Authorization header value.
func sigOf(t *testing.T, auth string) string {
	t.Helper()
	i := strings.Index(auth, "Signature=")
	if i < 0 {
		t.Fatalf("no Signature= in %q", auth)
	}
	return auth[i+len("Signature="):]
}

func signedHeadersOf(t *testing.T, auth string) string {
	t.Helper()
	i := strings.Index(auth, "SignedHeaders=")
	if i < 0 {
		t.Fatalf("no SignedHeaders= in %q", auth)
	}
	rest := auth[i+len("SignedHeaders="):]
	j := strings.Index(rest, ",")
	if j < 0 {
		t.Fatalf("malformed SignedHeaders in %q", auth)
	}
	return rest[:j]
}

func TestSigV4Vectors(t *testing.T) {
	s := newS3Signer(awsExAccessKey, awsExSecretKey, "us-east-1")
	tm := awsExTime(t)

	// Example 1: GET Object with a Range header, empty payload.
	t.Run("get_object", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Range", "bytes=0-9")
		req.Header.Set("x-amz-content-sha256", emptyPayloadHash)
		req.Header.Set("x-amz-date", "20130524T000000Z")
		auth := s.authorization(req, emptyPayloadHash, tm)
		const want = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
		if got := sigOf(t, auth); got != want {
			t.Fatalf("signature\n got %s\nwant %s\nauth %s", got, want, auth)
		}
		if sh := signedHeadersOf(t, auth); sh != "host;range;x-amz-content-sha256;x-amz-date" {
			t.Fatalf("signed headers %q", sh)
		}
		if !strings.Contains(auth, "Credential="+awsExAccessKey+"/20130524/us-east-1/s3/aws4_request") {
			t.Fatalf("credential scope %q", auth)
		}
	})

	// Example 2: PUT Object, a non-empty payload, a key needing percent-encoding, extra signed headers.
	t.Run("put_object", func(t *testing.T) {
		body := "Welcome to Amazon S3."
		payloadHash := hexSHA256([]byte(body))
		const wantHash = "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
		if payloadHash != wantHash {
			t.Fatalf("payload hash %s != %s", payloadHash, wantHash)
		}
		req, err := http.NewRequest(http.MethodPut, "https://examplebucket.s3.amazonaws.com/test$file.text", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Date", "Fri, 24 May 2013 00:00:00 GMT")
		req.Header.Set("x-amz-storage-class", "REDUCED_REDUNDANCY")
		req.Header.Set("x-amz-content-sha256", payloadHash)
		req.Header.Set("x-amz-date", "20130524T000000Z")
		auth := s.authorization(req, payloadHash, tm)
		const want = "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
		if got := sigOf(t, auth); got != want {
			t.Fatalf("signature\n got %s\nwant %s\nauth %s", got, want, auth)
		}
		if sh := signedHeadersOf(t, auth); sh != "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class" {
			t.Fatalf("signed headers %q", sh)
		}
	})

	// Example 4: GET Bucket (List Objects) with a query string.
	t.Run("list_objects", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("x-amz-content-sha256", emptyPayloadHash)
		req.Header.Set("x-amz-date", "20130524T000000Z")
		auth := s.authorization(req, emptyPayloadHash, tm)
		const want = "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
		if got := sigOf(t, auth); got != want {
			t.Fatalf("signature\n got %s\nwant %s\nauth %s", got, want, auth)
		}
	})
}

// TestSigV4SignMutatesRequest checks sign() sets the three headers and matches authorization().
func TestSigV4SignMutatesRequest(t *testing.T) {
	s := newS3Signer(awsExAccessKey, awsExSecretKey, "eu-central-1")
	tm := time.Date(2026, 10, 7, 9, 30, 0, 0, time.UTC)
	req, err := http.NewRequest(http.MethodPut, "https://bucket.s3.example.net/backups/commons-2026-10-07.tar.age", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	ph := hexSHA256([]byte("x"))
	s.sign(req, ph, tm)
	if req.Header.Get("x-amz-date") != "20261007T093000Z" {
		t.Fatalf("x-amz-date %q", req.Header.Get("x-amz-date"))
	}
	if req.Header.Get("x-amz-content-sha256") != ph {
		t.Fatalf("content-sha256 %q", req.Header.Get("x-amz-content-sha256"))
	}
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, sigV4Algorithm+" Credential="+awsExAccessKey+"/20261007/eu-central-1/s3/aws4_request") {
		t.Fatalf("authorization %q", auth)
	}
	// Default (empty) payload hash falls back to the empty-string digest.
	req2, _ := http.NewRequest(http.MethodGet, "https://bucket.s3.example.net/", nil)
	s.sign(req2, "", tm)
	if req2.Header.Get("x-amz-content-sha256") != emptyPayloadHash {
		t.Fatalf("empty payload hash %q", req2.Header.Get("x-amz-content-sha256"))
	}
}

func TestAWSURIEncode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/test.txt", "/test.txt"},
		{"/test$file.text", "/test%24file.text"},
		{"/a b/c", "/a%20b/c"},
		{"/x~y_z-1.2", "/x~y_z-1.2"},
	}
	for _, c := range cases {
		if got := awsURIEncode(c.in, true); got != c.want {
			t.Fatalf("encode %q = %q, want %q", c.in, got, c.want)
		}
	}
	if got := awsURIEncode("a/b", false); got != "a%2Fb" {
		t.Fatalf("query encode slash: %q", got)
	}
}
