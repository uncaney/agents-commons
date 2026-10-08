package integration

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/mcp"
)

// metalessOps is the exact set of MCP ops that intentionally carry no core.OpMeta (SPEC-v2 19.6):
// the local registry ops (help is anonymous, me is enforced inside opMe) and the scrub/sign
// anonymous read helpers (scrub, hazard, verify, key), whose packages pass nil/empty meta tables so
// their ops take the read-only default (cost 1, non-mutating). Pinning the set means any NEW metaless
// op — the usual shape of a package that forgot its OpMeta on a write op — fails this test loudly.
var metalessOps = map[string]bool{
	"help": true, "me": true, // internal/mcp local ops
	"scrub": true, "hazard": true, // internal/scrub anonymous helpers
	"verify": true, "key": true, // internal/sign anonymous reads
}

// TestNoDuplicateOps asserts the MCP registry merges every package's ops with no duplicate name
// (SPEC-v2 19.6): mergeOps panics on a collision, so a successful Ops(d) is itself the proof. It also
// checks Meta() and Ops(d) are consistent — every op the gateway exposes resolves a meta or is a
// documented metaless op, and no meta names an op that Ops does not expose (beyond the known dropped
// collisions, which stay reachable over HTTP but are withheld from the cx alias).
func TestNoDuplicateOps(t *testing.T) {
	ops := mcp.Ops(testDeps) // panics here on any duplicate op name
	if len(ops) == 0 {
		t.Fatal("Ops(d) is empty")
	}
	meta := mcp.Meta()
	var noMeta []string
	for name := range ops {
		if _, ok := meta[name]; !ok && !metalessOps[name] {
			noMeta = append(noMeta, name)
		}
	}
	if len(noMeta) > 0 {
		sort.Strings(noMeta)
		t.Fatalf("%d op(s) with neither OpMeta nor a metaless exemption:\n  %s", len(noMeta), strings.Join(noMeta, " "))
	}
}

// TestOpsInHelpAndScopes asserts the op/help/scope parity of SPEC-v2 19.6: every op either carries an
// OpMeta or is a documented metaless anonymous op; every OpMeta scope is well-formed (a scoped token
// can be issued to reach the op, or it is "*"/a privileged capability); and the help surface covers
// every namespace the index advertises, each page non-empty. (Per-op substring presence in a page is
// NOT asserted: the pages are budget-clipped summaries, 19.6, not exhaustive op listings.)
func TestOpsInHelpAndScopes(t *testing.T) {
	ops := mcp.Ops(testDeps)
	meta := mcp.Meta()

	// 1. Every op has an OpMeta or is a known metaless anonymous op.
	var missing []string
	for name := range ops {
		if _, ok := meta[name]; !ok && !metalessOps[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("op(s) absent from both OpMeta and the metaless set: %s", strings.Join(missing, " "))
	}

	// 2. Every OpMeta scope is well-formed (empty = anonymous/no scope required).
	var badScope []string
	for name, m := range meta {
		if m.Scope != "" && !scopeOK(m.Scope) {
			badScope = append(badScope, name+" -> "+strconv.Quote(m.Scope))
		}
	}
	if len(badScope) > 0 {
		sort.Strings(badScope)
		t.Fatalf("%d op(s) with an unrecognised OpMeta scope:\n  %s", len(badScope), strings.Join(badScope, "\n  "))
	}

	// 3. The help index lists every namespace, and each namespace resolves to a non-empty page.
	idx := mcp.HelpIndex()
	help := ops["help"]
	if help == nil {
		t.Fatal("no help op registered")
	}
	for _, ns := range mcp.Namespaces() {
		if !strings.Contains(idx, ns) {
			t.Errorf("help index does not advertise namespace %q", ns)
		}
		a, _ := json.Marshal(map[string]string{"t": ns})
		page, err := help(context.Background(), nil, a)
		if err != nil {
			t.Errorf("help{t:%q}: %v", ns, err)
			continue
		}
		if strings.TrimSpace(page) == "" {
			t.Errorf("namespace %q has an empty help page", ns)
		}
	}
}

// TestHelpBudgets asserts the help index and every namespace page stay within the SPEC-v2 19.6 byte
// budgets, served through the live registry (not just the package's own consts).
func TestHelpBudgets(t *testing.T) {
	const indexBudget, nsBudget = 480, 800
	if n := len(mcp.HelpIndex()); n > indexBudget {
		t.Fatalf("help index %d bytes > %d", n, indexBudget)
	}
	help := mcp.Ops(testDeps)["help"]
	for _, ns := range mcp.Namespaces() {
		a, _ := json.Marshal(map[string]string{"t": ns})
		page, err := help(context.Background(), nil, a)
		if err != nil {
			t.Fatalf("help{t:%q}: %v", ns, err)
		}
		if n := len(page); n > nsBudget {
			t.Fatalf("namespace %q page %d bytes > %d", ns, n, nsBudget)
		}
	}
}
