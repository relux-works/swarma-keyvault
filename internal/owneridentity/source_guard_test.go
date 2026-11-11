package owneridentity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The source guard is deliberately scoped to identity inputs and owner-key
// display/custody representations. Protocol constants are still valid. It is
// not whole-program data-flow analysis.
var ownerLiteral = regexp.MustCompile(`(?i)(?:/Users/|/home/|~[^ /]+/|\b[a-z0-9-]+[./]grants-owner-v1(?:\.v| v)[1-9][0-9]*)`)
var ownerScopeLiteral = regexp.MustCompile(`\bowner:[a-z0-9-]+`)
var matrixLiteral = regexp.MustCompile(`@[a-zA-Z0-9._=/-]+:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
var swiftFixedAssignment = regexp.MustCompile(`(?im)\b([a-z][a-z0-9_]*)\s*(?::\s*[a-z0-9_?]+\s*)?(?:==|!=|=)\s*(?:"[^"\\]+"|[0-9]+\b)`)
var swiftIdentityFallback = regexp.MustCompile(`(?im)\b([a-z][a-z0-9_]*)\s*\?\?\s*("[^"\\]+"|[a-z][a-z0-9_]*)`)

func identityField(name string) bool {
	name = strings.ToLower(strings.ReplaceAll(name, "_", ""))
	for _, prefix := range []string{"default", "fallback", "fixed", "legacy", "supplied", "configured"} {
		name = strings.TrimPrefix(name, prefix)
	}
	switch name {
	case "owner", "expectedowner", "ownermxid", "ownerprincipal", "owneraddress", "ownerkey",
		"principal", "service", "nostridentity", "namecoinidentity", "qualificationnostr", "qualificationnamecoin",
		"user", "username", "host", "hostname", "home", "homedir", "uid", "gid":
		return true
	}
	return false
}

func literalIdentity(path, value string) bool {
	if ownerLiteral.MatchString(value) || ownerScopeLiteral.MatchString(value) {
		return true
	}
	for _, match := range matrixLiteral.FindAllString(value, -1) {
		if !strings.HasPrefix(path, "internal/muinterop/") || !strings.HasSuffix(match, ":interop.invalid") {
			return true
		}
	}
	return false
}

func fieldName(e ast.Expr) string {
	switch a := e.(type) {
	case *ast.Ident:
		return a.Name
	case *ast.SelectorExpr:
		return a.Sel.Name
	case *ast.IndexExpr:
		return fieldName(a.Index)
	case *ast.BasicLit:
		if a.Kind == token.STRING {
			name, _ := strconv.Unquote(a.Value)
			return name
		}
	}
	return ""
}

// Recover directly embedded values, literal aliases, parentheses and string
// concatenation. Ignore unknown runtime expressions and guard their config at
// the public input boundary.
func fixedValue(e ast.Expr, depth int) (string, bool) {
	if depth > 16 {
		return "", false
	}
	switch n := e.(type) {
	case *ast.BasicLit:
		switch n.Kind {
		case token.STRING:
			value, err := strconv.Unquote(n.Value)
			return value, err == nil
		case token.INT:
			return n.Value, true
		}
	case *ast.ParenExpr:
		return fixedValue(n.X, depth+1)
	case *ast.BinaryExpr:
		if n.Op == token.ADD {
			a, oka := fixedValue(n.X, depth+1)
			b, okb := fixedValue(n.Y, depth+1)
			return a + b, oka && okb
		}
	case *ast.CallExpr:
		// String normalization does not make a fixed identity dynamic.
		method, ok := n.Fun.(*ast.SelectorExpr)
		if !ok || fieldName(method.X) != "strings" || len(n.Args) != 1 {
			return "", false
		}
		value, ok := fixedValue(n.Args[0], depth+1)
		if !ok {
			return "", false
		}
		switch method.Sel.Name {
		case "TrimSpace":
			return strings.TrimSpace(value), true
		case "ToLower":
			return strings.ToLower(value), true
		case "ToUpper":
			return strings.ToUpper(value), true
		}
	case *ast.Ident:
		if n.Obj != nil {
			switch decl := n.Obj.Decl.(type) {
			case *ast.ValueSpec:
				for i, name := range decl.Names {
					if name.Name == n.Name && i < len(decl.Values) {
						return fixedValue(decl.Values[i], depth+1)
					}
				}
			case *ast.AssignStmt:
				for i, name := range decl.Lhs {
					if fieldName(name) == n.Name && i < len(decl.Rhs) {
						return fixedValue(decl.Rhs[i], depth+1)
					}
				}
			}
		}
	}
	return "", false
}

func guardGo(path string, raw []byte) (string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, raw, 0)
	if err != nil {
		return "", err
	}
	var hit string
	record := func(e ast.Expr, reason string) {
		if hit == "" {
			hit = fset.Position(e.Pos()).String() + ": " + reason
		}
	}
	check := func(name string, e ast.Expr) {
		value, ok := fixedValue(e, 0)
		if !ok || value == "" {
			return
		}
		if identityField(name) {
			if name == "Service" && value == "swarma-grants" && path == "internal/grantrequester/request.go" {
				return
			}
			// The shared invariant test fixture deliberately injects an
			// uppercase service that the production grammar refuses.
			if name == "Service" && value == "TEST" && path == "internal/keyvault/recordtest/forgeries.go" {
				return
			}
			record(e, "fixed identity-bearing field")
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if hit != "" {
			return false
		}
		switch a := n.(type) {
		case *ast.KeyValueExpr:
			check(fieldName(a.Key), a.Value)
		case *ast.ValueSpec:
			for i := 0; i < min(len(a.Names), len(a.Values)); i++ {
				check(a.Names[i].Name, a.Values[i])
			}
		case *ast.AssignStmt:
			for i := 0; i < min(len(a.Lhs), len(a.Rhs)); i++ {
				check(fieldName(a.Lhs[i]), a.Rhs[i])
			}
		case *ast.BasicLit:
			if a.Kind == token.STRING {
				if v, ok := fixedValue(a, 0); ok && literalIdentity(path, v) {
					record(a, "fixed owner, account or home literal")
				}
			}
		}
		return hit == ""
	})
	return hit, nil
}

func guardSwift(raw []byte) string {
	if literalIdentity("swift", string(raw)) {
		return "fixed owner, account or home literal"
	}
	fixed := map[string]bool{}
	for _, match := range swiftFixedAssignment.FindAllSubmatch(raw, -1) {
		name := string(match[1])
		if identityField(name) || strings.EqualFold(name, "label") {
			return "fixed native identity-bearing field"
		}
		fixed[name] = true
	}
	for _, match := range swiftIdentityFallback.FindAllSubmatch(raw, -1) {
		source, fallback := string(match[1]), string(match[2])
		if identityField(source) && (strings.HasPrefix(fallback, `"`) || fixed[fallback]) {
			return "fixed native identity fallback"
		}
	}
	return ""
}

// Actual production source, including the native review helper, must pass the
// same checks as the bounded plants below. Tests and vendored source are out of
// scope; no build or native helper execution is performed by this test.
func TestNoFixedOwnerIdentityInSource(t *testing.T) {
	root := "../.."
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "third_party" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, "_test.go") || filepath.Ext(p) != ".go" && filepath.Ext(p) != ".swift" {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if filepath.Ext(p) == ".swift" {
			if hit := guardSwift(raw); hit != "" {
				t.Errorf("%s: %s", p, hit)
			}
			return nil
		}
		relative, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		hit, err := guardGo(filepath.ToSlash(relative), raw)
		if hit != "" {
			t.Error(hit)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Arbitrary, previously unknown fixed values fail for their intended rule,
// and trusted inputs passed through by parameter are admitted.
func TestOwnerIdentityGuardPlants(t *testing.T) {
	const copied = `package probe
type config struct { Owner, Service, Host, Home string; UID int }
func makeConfig(owner, service, host, home string, uid int) config {
	return config{Owner: owner, Service: service, Host: host, Home: home, UID: uid}
}
`
	for _, plant := range []struct{ old, injected, want string }{
		{"Owner: owner", `Owner: "opaque-principal"`, "fixed identity-bearing field"},
		{"Service: service", `Service: "another-" + "person"`, "fixed identity-bearing field"},
		{"Service: service", `Service: strings.TrimSpace(" unseen-person ")`, "fixed identity-bearing field"},
		{"Host: host", `Host: "some-new-host"`, "fixed identity-bearing field"},
		{"Home: home", `Home: "/var/private-user"`, "fixed identity-bearing field"},
		{"UID: uid", `UID: 4091`, "fixed identity-bearing field"},
		{"return config", "var tmp = \"/home/unknown-user\"; _ = tmp; return config", "fixed owner, account or home literal"},
	} {
		raw := strings.Replace(copied, plant.old, plant.injected, 1)
		hit, err := guardGo("copy/probe.go", []byte(raw))
		if err != nil || !strings.Contains(hit, plant.want) {
			t.Fatal("plant did not trigger intended check", plant.old, hit, err)
		}
	}
	if hit, err := guardGo("copy/probe.go", []byte(copied)); hit != "" || err != nil {
		t.Fatal("parameterized source was refused", hit, err)
	}
	const forgery = "internal/keyvault/recordtest/forgeries.go"
	known := strings.Replace(copied, "Service: service", `Service: "TEST"`, 1)
	if hit, err := guardGo(forgery, []byte(known)); hit != "" || err != nil {
		t.Fatal("uppercase refusal fixture was rejected by the guard", hit, err)
	}
	unknown := strings.Replace(known, `"TEST"`, `"unseen-person"`, 1)
	if hit, err := guardGo(forgery, []byte(unknown)); err != nil || !strings.Contains(hit, "fixed identity-bearing field") {
		t.Fatal("fixture exception admitted a different identity", hit, err)
	}
	if got := guardSwift([]byte(`let service = "a-hidden-person"`)); got != "fixed native identity-bearing field" {
		t.Fatal("native identity plant was not detected", got)
	}
	if got := guardSwift([]byte(`let fallbackService = "unseen-person"; let chosen = suppliedService ?? fallbackService`)); got != "fixed native identity-bearing field" {
		t.Fatal("native fixed fallback assignment was not detected", got)
	}
	if got := guardSwift([]byte(`let fallback = "unseen-person"; let chosen = suppliedService ?? fallback`)); got != "fixed native identity fallback" {
		t.Fatal("native fallback through a local alias was not detected", got)
	}
	if got := guardSwift([]byte(`guard label == "works.relux.mac-keyvault.key.unseen-person.grants-owner-v1.v41" else { return }`)); got != "fixed owner, account or home literal" {
		t.Fatal("native label plant was not detected", got)
	}
	if got := guardSwift([]byte(`let service = suppliedIdentity; let label = prefix + service`)); got != "" {
		t.Fatal("native parameterized input refused", got)
	}
}
