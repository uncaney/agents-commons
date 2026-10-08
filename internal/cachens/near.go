package cachens

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"ekaii.fr/commons/internal/core"
)

// nearLine is one near-miss candidate.
type nearLine struct {
	key, by, prev string
	sim           float64
	tok, lvl      int
}

// Line is `near <key> sim=0.71 tok=N by a… lvl=L2 <preview 80>` (27.3): never a body, only the
// scrubbed, clipped input preview.
func (n nearLine) Line() string {
	by := n.by
	if by == "" {
		by = "system"
	}
	p := n.prev
	if utf8.RuneCountInString(p) > NearPreview {
		p = string([]rune(p)[:NearPreview])
	}
	return fmt.Sprintf("near %s sim=%.2f tok=%d by %s lvl=L%d %s", n.key, n.sim, n.tok, by, n.lvl, strings.TrimSpace(p))
}

// near returns up to NearMax candidates in ns whose scrubbed preview is similar (> NearMin) to the
// canonicalised input, under the same visibility rules as GET /c/: an anonymous caller (reader nil)
// only sees public rows (an L2+ producer's inline row), a token caller sees every live, non-hidden
// row in the namespace. Bodies are never read or returned.
func (s *svc) near(ctx context.Context, reader *core.Ident, ns, in string) ([]nearLine, int, error) {
	if !nsRe.MatchString(ns) {
		return nil, 0, errNS
	}
	if len(in) > MaxIn {
		return nil, 0, core.ErrSize
	}
	canonical, v := Canon(ns, in)
	q := preview(canonical)
	if q == "" {
		return nil, v, nil
	}
	sql := `SELECT key, in_preview, cost_tokens, producer_root, producer_lvl, similarity(in_preview, $2) AS sim
		FROM cache
		WHERE ns = $1 AND NOT hidden AND expires_at > now() AND in_preview <> '' AND similarity(in_preview, $2) > $3`
	if reader == nil {
		sql += ` AND producer_lvl >= 2 AND blob IS NULL`
	}
	sql += ` ORDER BY sim DESC, key LIMIT $4`
	rows, err := s.d.DB.Query(ctx, sql, ns, q, NearMin, NearMax)
	if err != nil {
		return nil, v, err
	}
	defer rows.Close()
	var out []nearLine
	for rows.Next() {
		var n nearLine
		if err := rows.Scan(&n.key, &n.prev, &n.tok, &n.by, &n.lvl, &n.sim); err != nil {
			return nil, v, err
		}
		out = append(out, n)
	}
	return out, v, rows.Err()
}
