package core

import "context"

// Origin records who wrote a piece of content from where (4.8, 24.16): kept 12 months, read
// only by the admin plane, never exported. Sealed-lane writes never call it (26.1 D3).
func Origin(ctx context.Context, q Q, kind, ref, root, id, ip string) error {
	_, err := q.Exec(ctx, `INSERT INTO content_origin (kind, ref, root, id, ip) VALUES ($1, $2, $3, $4, $5)`,
		cleanLine(kind, 32), cleanLine(ref, 200), cleanLine(root, 64), cleanLine(id, 64), cleanLine(ip, 64))
	return err
}
