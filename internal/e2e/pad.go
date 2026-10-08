package e2e

import "errors"

// Plaintext padding (E2EE 2.5, SPEC-v2 26.4): ISO/IEC 7816-4 (one 0x80 then zeros) to the bucket sizes
// of the lane. The server rejects ciphertexts whose length minus the tag is not a bucket, which keeps the
// anonymity set honest and byte quotas meaningful. Plaintext is never compressed.

var (
	MailBuckets   = []int{1024, 2048, 4096}
	GroupBuckets  = []int{1024, 4096}
	ObjectBuckets = []int{4096, 16384, 65536}

	ErrTooLarge = errors.New("e2e: plaintext exceeds the largest bucket")
	ErrPadding  = errors.New("e2e: bad padding")
)

// Bucket returns the smallest bucket that holds n plaintext bytes plus the 0x80 marker.
func Bucket(n int, buckets []int) (int, bool) {
	for _, b := range buckets {
		if n < b {
			return b, true
		}
	}
	return 0, false
}

// IsBucket reports whether n is one of the lane's buckets.
func IsBucket(n int, buckets []int) bool {
	for _, b := range buckets {
		if n == b {
			return true
		}
	}
	return false
}

// Pad appends 0x80 and zeros up to the smallest fitting bucket.
func Pad(pt []byte, buckets []int) ([]byte, error) {
	b, ok := Bucket(len(pt), buckets)
	if !ok {
		return nil, ErrTooLarge
	}
	out := make([]byte, b)
	copy(out, pt)
	out[len(pt)] = 0x80
	return out, nil
}

// Unpad strips ISO 7816-4 padding; it runs on authenticated plaintext only, so timing is not secret.
func Unpad(p []byte) ([]byte, error) {
	i := len(p) - 1
	for i >= 0 && p[i] == 0 {
		i--
	}
	if i < 0 || p[i] != 0x80 {
		return nil, ErrPadding
	}
	return p[:i], nil
}

// BucketName renders a bucket for `bucket=2k` style output.
func BucketName(n int) string {
	switch n {
	case 1024:
		return "1k"
	case 2048:
		return "2k"
	case 4096:
		return "4k"
	case 16384:
		return "16k"
	case 65536:
		return "64k"
	}
	return ""
}
