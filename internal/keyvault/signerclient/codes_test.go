package signerclient_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// codeConstants reads codes.go with go/parser and returns every exported
// Code* constant's string value, so the registry can be checked against
// the constants of the same file rather than against a second list.
func codeConstants(t *testing.T) map[string]string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "codes.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	constants := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value := spec.(*ast.ValueSpec)
			for i, name := range value.Names {
				if !strings.HasPrefix(name.Name, "Code") || i >= len(value.Values) {
					continue
				}
				lit, ok := value.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("%s is not a string literal", name.Name)
				}
				code, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				constants[name.Name] = code
			}
		}
	}
	return constants
}

// ErrorContract is complete and well-formed against its own file: every
// Code* constant of codes.go has exactly one row and every row's code is
// one of those constants (both directions, via go/parser, so a constant
// added without a row or a row typed as a bare string fails), codes are
// unique, every Exit is 1, 2 or 3, the three stream-only codes are
// Stream rows, and StreamErrorCodes/IsStreamCode/Lookup agree with the
// table.
func TestErrorContractRegistryComplete(t *testing.T) {
	constants := codeConstants(t)
	if len(constants) == 0 {
		t.Fatal("no Code* constants parsed from codes.go")
	}
	byCode := map[string]int{}
	for _, c := range constants {
		byCode[c]++
	}
	rows := map[string]signerclient.ErrorCode{}
	for _, row := range signerclient.ErrorContract {
		if _, dup := rows[row.Code]; dup {
			t.Errorf("registry lists %s twice", row.Code)
		}
		rows[row.Code] = row
		if byCode[row.Code] == 0 {
			t.Errorf("registry row %q has no Code* constant in codes.go", row.Code)
		}
		if row.Exit < signerclient.ExitFailure || row.Exit > signerclient.ExitRefused {
			t.Errorf("%s: exit class %d is not 1, 2 or 3", row.Code, row.Exit)
		}
		if row.When == "" {
			t.Errorf("%s: no When", row.Code)
		}
	}
	for name, code := range constants {
		if _, ok := rows[code]; !ok {
			t.Errorf("constant %s = %q has no registry row", name, code)
		}
	}
	for _, code := range []string{signerclient.CodeBadRequest, signerclient.CodeMissingID, signerclient.CodeUnknownOp} {
		if !rows[code].Stream {
			t.Errorf("%s is produced only by the signer stream and must be a Stream row", code)
		}
	}
	stream := signerclient.StreamErrorCodes()
	if !sort.StringsAreSorted(stream) {
		t.Errorf("StreamErrorCodes is not sorted: %v", stream)
	}
	want := 0
	for code, row := range rows {
		if row.Stream {
			want++
		}
		if signerclient.IsStreamCode(code) != row.Stream {
			t.Errorf("IsStreamCode(%s) = %v, row says %v", code, !row.Stream, row.Stream)
		}
		if got, ok := signerclient.Lookup(code); !ok || got != row {
			t.Errorf("Lookup(%s) = %+v %v", code, got, ok)
		}
	}
	if len(stream) != want {
		t.Errorf("StreamErrorCodes has %d codes, %d rows are Stream", len(stream), want)
	}
	if _, ok := signerclient.Lookup("no_such_code"); ok || signerclient.IsStreamCode("no_such_code") {
		t.Error("an undefined code looks up")
	}
	t.Logf("%d codes registered, %d declared for the stream", len(rows), len(stream))
}
