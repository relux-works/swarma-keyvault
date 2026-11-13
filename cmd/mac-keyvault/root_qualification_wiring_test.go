package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func wiringFunc(t *testing.T, file, name string) *ast.FuncDecl {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range parsed.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("%s: function %s not found", file, name)
	return nil
}

// wiringCalls returns the argument list of every call to callee inside fn.
func wiringCalls(fn *ast.FuncDecl, callee string) [][]ast.Expr {
	var calls [][]ast.Expr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == callee {
				calls = append(calls, call.Args)
			}
		}
		return true
	})
	return calls
}

// wiringUses counts the uses of the identifier name inside fn's body.
func wiringUses(fn *ast.FuncDecl, name string) int {
	uses := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			uses++
		}
		return true
	})
	return uses
}

func wiringIsSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == pkg && sel.Sel.Name == name
}

func wiringIsIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// Claim: the product wiring sends the diagnostic line to stderr and the result to
// stdout. The only product entry, main, passes os.Stdout then os.Stderr to the owning
// process; that process writes the result through its stdout parameter exactly once and
// hands its stderr parameter, and nothing else, down to the post-native step, which
// receives it as its diagnostic writer. Every other test supplies its own buffer, so
// they cannot see a wrong product sink; this reads the wiring itself. A change that
// sends the diagnostic to stdout, in main or anywhere along the chain, fails here.
// Limit: it checks the shape of the calls in these three functions, not a live run.
func TestProductWiringSendsTheDiagnosticToStderrAndTheResultToStdout(t *testing.T) {
	entry := wiringCalls(wiringFunc(t, "main.go", "main"), "rootQualificationParentProcess")
	if len(entry) != 1 || len(entry[0]) != 4 || !wiringIsSelector(entry[0][2], "os", "Stdout") || !wiringIsSelector(entry[0][3], "os", "Stderr") {
		t.Fatal("main must pass os.Stdout and then os.Stderr to the owning process")
	}
	process := wiringFunc(t, "root_qualification_parent.go", "rootQualificationParentProcess")
	if c := wiringCalls(process, "writeRootQualificationParent"); len(c) != 1 || len(c[0]) < 1 || !wiringIsIdent(c[0][0], "stdout") {
		t.Fatal("the result must be written to the stdout parameter, once")
	}
	if c := wiringCalls(process, "rootQualificationParentCase"); len(c) != 1 || len(c[0]) != 3 || !wiringIsIdent(c[0][2], "stderr") {
		t.Fatal("the stderr parameter must be handed to the case")
	}
	if wiringUses(process, "stdout") != 1 || wiringUses(process, "stderr") != 1 {
		t.Fatal("stdout and stderr must each be used exactly once in the owning process")
	}
	step := wiringFunc(t, "root_qualification_parent.go", "rootQualificationParentCase")
	if c := wiringCalls(step, "finishRootQualificationCreate"); len(c) != 1 || len(c[0]) != 6 || !wiringIsIdent(c[0][5], "diagnostic") {
		t.Fatal("the case must hand its diagnostic writer to the post-native step")
	}
	if wiringUses(step, "diagnostic") != 1 {
		t.Fatal("the diagnostic writer must be used exactly once in the case")
	}
}
