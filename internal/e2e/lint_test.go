package e2e_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/e2e"
)

// parsePackage parses the non-test files of internal/e2e.
func parsePackage(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := pkgs["e2e"]
	if !ok || len(pkg.Files) < 10 {
		t.Fatalf("package not found or too small: %v", pkgs)
	}
	return fset, pkg.Files
}

// TestLabelsLint: every label literal lives in labels.go (E2EE 2.3), labels are unique, and the Labels
// list is complete.
func TestLabelsLint(t *testing.T) {
	fset, files := parsePackage(t)
	isLabel := func(v string) bool {
		return strings.HasPrefix(v, "cx1/") || strings.HasPrefix(v, "cxs1") || strings.HasPrefix(v, "cx-") || v == "mac"
	}
	for path, f := range files {
		if filepath.Base(path) == "labels.go" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			if err == nil && isLabel(v) {
				t.Errorf("%s: label literal %q outside labels.go", fset.Position(lit.Pos()), v)
			}
			return true
		})
	}
	seen := map[string]bool{}
	for _, l := range e2e.Labels {
		if seen[l] {
			t.Errorf("duplicate label %q", l)
		}
		seen[l] = true
	}
	// every string constant declared in labels.go that looks like a label is in the list
	for path, f := range files {
		if filepath.Base(path) != "labels.go" {
			continue
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok {
						continue
					}
					v, _ := strconv.Unquote(lit.Value)
					if strings.HasPrefix(name.Name, "Label") && !seen[v] {
						t.Errorf("label %s = %q missing from Labels", name.Name, v)
					}
				}
			}
		}
	}
	// no label is a prefix of another label's bytes followed by 0x00 ambiguity: the separator makes
	// "cx1/ek/" distinct from "cx1/ek/1/", so only exact duplicates matter (checked above); labels never
	// contain the separator byte
	for _, l := range e2e.Labels {
		if strings.ContainsRune(l, 0) {
			t.Errorf("label %q contains the separator", l)
		}
	}
}

// TestStdlibOnly: the package imports nothing outside the standard library.
func TestStdlibOnly(t *testing.T) {
	_, files := parsePackage(t)
	for path, f := range files {
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if first := strings.SplitN(p, "/", 2)[0]; strings.Contains(first, ".") {
				t.Errorf("%s imports %s", filepath.Base(path), p)
			}
		}
	}
}

// TestConstantTimeLint type-checks the package and fails on any comparison of byte material that is
// not constant time: bytes.Equal/Compare, slices.Equal, reflect.DeepEqual anywhere; == or != between
// byte slices or byte arrays; == or != against a string([]byte) conversion unless the other operand is
// a constant (a public magic such as "cxkb2"). Tags, commitments, MACs and signatures are compared
// with hmac.Equal (subtle.ConstantTimeCompare) only.
func TestConstantTimeLint(t *testing.T) {
	fset, fileMap := parsePackage(t)
	var names []string
	for p := range fileMap {
		names = append(names, p)
	}
	sort.Strings(names)
	var files []*ast.File
	for _, p := range names {
		files = append(files, fileMap[p])
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	if _, err := conf.Check("ekaii.fr/commons/internal/e2e", fset, files, info); err != nil {
		t.Fatal(err)
	}
	isBytes := func(tp types.Type) bool {
		switch u := tp.Underlying().(type) {
		case *types.Slice:
			b, ok := u.Elem().Underlying().(*types.Basic)
			return ok && b.Kind() == types.Uint8
		case *types.Array:
			b, ok := u.Elem().Underlying().(*types.Basic)
			return ok && b.Kind() == types.Uint8
		}
		return false
	}
	isStringOfBytes := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return false
		}
		tv, ok := info.Types[call.Fun]
		if !ok || !tv.IsType() {
			return false
		}
		b, ok := tv.Type.Underlying().(*types.Basic)
		return ok && b.Kind() == types.String && isBytes(info.Types[call.Args[0]].Type)
	}
	banned := map[string]bool{"bytes.Equal": true, "bytes.Compare": true, "slices.Equal": true, "slices.Compare": true, "reflect.DeepEqual": true}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && banned[id.Name+"."+sel.Sel.Name] {
						t.Errorf("%s: %s.%s is not constant time", fset.Position(x.Pos()), id.Name, sel.Sel.Name)
					}
				}
			case *ast.BinaryExpr:
				if x.Op != token.EQL && x.Op != token.NEQ {
					return true
				}
				lt, rt := info.Types[x.X], info.Types[x.Y]
				if lt.IsNil() || rt.IsNil() {
					return true // presence checks, not content comparisons
				}
				if isBytes(lt.Type) || isBytes(rt.Type) {
					t.Errorf("%s: == on byte material", fset.Position(x.Pos()))
				}
				if (isStringOfBytes(x.X) && rt.Value == nil) || (isStringOfBytes(x.Y) && lt.Value == nil) {
					t.Errorf("%s: string([]byte) compared with a non-constant", fset.Position(x.Pos()))
				}
			case *ast.SwitchStmt:
				if x.Tag != nil && isStringOfBytes(x.Tag) {
					t.Errorf("%s: switch on string([]byte)", fset.Position(x.Pos()))
				}
			}
			return true
		})
	}
	// and the comparisons that must exist: hmac.Equal is what the open/verify paths use
	uses := 0
	for id, obj := range info.Uses {
		if obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "crypto/hmac" && id.Name == "Equal" {
			uses++
		}
	}
	if uses < 10 {
		t.Errorf("only %d hmac.Equal uses; the open/verify paths must compare tags with it", uses)
	}
}
