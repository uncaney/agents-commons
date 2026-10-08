package graph

import "sort"

// cliques finds union-find components of 2..8 roots whose inbound confirmations are at least 80 %
// from inside the component (27.4). The graph is built from reciprocal edges (both directions
// present), which is the backbone of a vote ring; the inbound test then confirms the ring votes
// mostly for itself. Each returned clique is a sorted slice of roots.
func cliques(edges []edge) [][]string {
	// Reciprocal adjacency: keep an edge only when the reverse edge also exists.
	present := map[[2]string]bool{}
	for _, e := range edges {
		present[[2]string{e.a, e.b}] = true
	}
	uf := newUF()
	for _, e := range edges {
		if present[[2]string{e.b, e.a}] {
			uf.union(e.a, e.b)
		}
	}
	// Group members by component root.
	comp := map[string][]string{}
	for node := range uf.parent {
		r := uf.find(node)
		comp[r] = append(comp[r], node)
	}
	// Inbound totals and inside-inbound per node.
	inboundTot := map[string]int{}
	for _, e := range edges {
		inboundTot[e.b] += e.n
	}
	var out [][]string
	for _, members := range comp {
		// A 2-root component is just a reciprocal pair (handled by the reciprocal rule); cliques
		// are the multi-party rings of 3..8 roots.
		if len(members) < 3 || len(members) > 8 {
			continue
		}
		inside := map[string]bool{}
		for _, m := range members {
			inside[m] = true
		}
		var insideIn, totalIn int
		for _, e := range edges {
			if inside[e.b] {
				totalIn += e.n
				if inside[e.a] {
					insideIn += e.n
				}
			}
		}
		if totalIn == 0 || float64(insideIn)/float64(totalIn) < 0.8 {
			continue
		}
		sort.Strings(members)
		out = append(out, members)
	}
	// Deterministic order by first member.
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// uf is a tiny union-find over string nodes.
type uf struct{ parent map[string]string }

func newUF() *uf { return &uf{parent: map[string]string{}} }

func (u *uf) find(x string) string {
	if _, ok := u.parent[x]; !ok {
		u.parent[x] = x
		return x
	}
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]]
		x = u.parent[x]
	}
	return x
}

func (u *uf) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u.parent[ra] = rb
	}
}
