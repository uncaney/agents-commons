package mem

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"ekaii.fr/commons/internal/core"
)

// export writes the root's continuity rows as JSONL (3.4 export-me): checkpoints, the KV rows it
// owns or wrote, later messages. Sealed values are never exported (26.7): their rows carry
// sealed=true and no content.
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	rows, err := q.Query(ctx, `SELECT `+cpCols+` FROM checkpoints WHERE root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	for rows.Next() {
		c, err := scanCP(rows)
		if err != nil {
			rows.Close()
			return err
		}
		rec := map[string]any{"kind": "cp", "id": c.ID, "name": c.Name, "seq": c.Seq, "summary": c.Summary, "pub": c.PubScope,
			"hazard": c.Hazard, "created": c.Created.UTC(), "expires": c.Expires.UTC(), "sealed": c.Sealed}
		if !c.Sealed {
			rec["body"] = c.Body
			if c.Blob != "" {
				rec["blob"] = c.Blob
			}
		}
		if err := enc.Encode(rec); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = q.Query(ctx, `SELECT `+kvCols+` FROM kv WHERE (ns = 'a:' || $1 OR root = $1) AND expires_at > now() ORDER BY ns, k`, root)
	if err != nil {
		return err
	}
	for rows.Next() {
		x, err := scanKV(rows)
		if err != nil {
			rows.Close()
			return err
		}
		rec := map[string]any{"kind": "kv", "ns": x.NS, "k": x.K, "ver": x.Ver, "fence": x.Fence, "expires": x.Exp.UTC(), "updated": x.Updated.UTC(), "sealed": x.Sealed}
		if !x.Sealed {
			rec["v"] = string(x.V)
		}
		if err := enc.Encode(rec); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = q.Query(ctx, `SELECT id, text, subject, deliver_at, cond_kind, cond_ref, delivered, delivered_at, created FROM mem_later WHERE root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, text, subject, kind, ref string
		var deliverAt, deliveredAt *time.Time
		var delivered bool
		var created time.Time
		if err := rows.Scan(&id, &text, &subject, &deliverAt, &kind, &ref, &delivered, &deliveredAt, &created); err != nil {
			return err
		}
		rec := map[string]any{"kind": "later", "id": id, "text": text, "subject": subject, "delivered": delivered, "created": created.UTC()}
		if deliverAt != nil {
			rec["deliver_at"] = deliverAt.UTC()
		}
		if deliveredAt != nil {
			rec["delivered_at"] = deliveredAt.UTC()
		}
		if kind != "" {
			rec["on"] = kind + ":" + ref
		}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}
