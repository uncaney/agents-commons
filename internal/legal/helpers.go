package legal

import (
	"context"
	"encoding/base64"
	"strings"

	"ekaii.fr/commons/internal/core"
)

// decodeB64 decodes a base64url value, tolerating padding and the standard alphabet.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// bump adds delta to today's counter and returns the new value (metadata only).
func bump(ctx context.Context, q core.Q, scope, kind string, delta int) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, scope, kind, delta).Scan(&n)
	return n, err
}
