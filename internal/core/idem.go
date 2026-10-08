package core

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Idempotency caps per level (4.3): keys per root and stored body bytes.
const (
	idemKeysL0, idemBodyL0 = 100, 1 << 10
	idemKeysL1, idemBodyL1 = 1000, 8 << 10
	MaxIdemKey             = 64
)

var (
	ErrIdem     = E(409, "idem", "key reused with different body")
	ErrIdemBusy = E(409, "busy", "retry")
)

// Idem runs fn at most once per (root, key) for 24 h (12.7). A replay returns the stored status and
// body plus the line "idem=replay"; the same key with another request hash is refused; a key whose
// first run is still in flight answers 409 err busy retry. An empty key runs fn directly.
func Idem(ctx context.Context, d *Deps, id *Ident, key, route string, reqHash []byte, fn func() (status int, body string, err error)) (int, string, error) {
	if key == "" {
		return fn()
	}
	if len(key) > MaxIdemKey || strings.ContainsFunc(key, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return 0, "", Bad("idempotency key: <= 64 printable ASCII chars")
	}
	keys, bodyCap := idemKeysL0, idemBodyL0
	if Level(ctx, d.DB, id.Root) >= 1 {
		keys, bodyCap = idemKeysL1, idemBodyL1
	}
	tag, err := d.DB.Exec(ctx, `INSERT INTO idem (root, key, route, req_hash)
		SELECT $1, $2, $3, $4 WHERE (SELECT count(*) FROM idem WHERE root = $1) < $5
		ON CONFLICT (root, key) DO NOTHING`, id.Root, key, route, reqHash, keys)
	if err != nil {
		return 0, "", err
	}
	if tag.RowsAffected() == 0 {
		var gotRoute string
		var gotHash []byte
		var status *int
		var body *string
		err := d.DB.QueryRow(ctx, `SELECT route, req_hash, status, body FROM idem WHERE root = $1 AND key = $2`, id.Root, key).
			Scan(&gotRoute, &gotHash, &status, &body)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, "", E(429, "quota", "idempotency keys")
		}
		if err != nil {
			return 0, "", err
		}
		if gotRoute != route || !bytes.Equal(gotHash, reqHash) {
			return 0, "", ErrIdem
		}
		if status == nil || body == nil {
			return 0, "", ErrIdemBusy
		}
		return *status, strings.TrimRight(*body, "\n") + "\nidem=replay", nil
	}
	status, body, ferr := fn()
	if ferr != nil || len(body) > bodyCap {
		// No replayable result: free the key so the client can retry.
		d.DB.Exec(ctx, `DELETE FROM idem WHERE root = $1 AND key = $2`, id.Root, key)
		return status, body, ferr
	}
	_, err = d.DB.Exec(ctx, `UPDATE idem SET status = $3, body = $4 WHERE root = $1 AND key = $2`, id.Root, key, status, body)
	return status, body, err
}

// IdemKey extracts the Idempotency-Key header of a request (empty when absent).
func IdemKey(h interface{ Get(string) string }) string {
	return strings.TrimSpace(h.Get("Idempotency-Key"))
}
