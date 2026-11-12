package owneridentity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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
var swiftFixedAssignment = regexp.MustCompile(`(?im)\b([a-z][a-z0-9_]*)\s*(?::\s*[a-z0-9_?]+\s*)?(?:==|!=|=)\s*\(*\s*(?:"[^"\\]+"|[0-9]+\b)`)
var swiftIdentityFallback = regexp.MustCompile(`(?im)\b([a-z][a-z0-9_]*)\s*\?\?\s*\(*\s*("[^"\\]+"|[a-z][a-z0-9_]*)`)

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

// Recover fixed identity sources through literals, aliases, parentheses,
// concatenation and calls with fixed arguments. Runtime roots are admitted here
// and validated separately at the public configuration boundary.
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
	case *ast.CompositeLit:
		values := make([]string, len(n.Elts))
		for i, element := range n.Elts {
			value, fixed := fixedValue(element, depth+1)
			if !fixed {
				return "", false
			}
			values[i] = value
		}
		return strings.Join(values, ""), true
	case *ast.CallExpr:
		// These transforms preserve the identity source in their string
		// argument even when an auxiliary cutset or predicate is dynamic.
		if method, ok := n.Fun.(*ast.SelectorExpr); ok && fieldName(method.X) == "strings" && len(n.Args) > 0 {
			switch method.Sel.Name {
			case "Trim", "TrimLeft", "TrimRight", "TrimSpace", "TrimPrefix", "TrimSuffix", "TrimFunc", "TrimLeftFunc", "TrimRightFunc", "ToLower", "ToUpper", "ToTitle", "ToValidUTF8", "Replace", "ReplaceAll", "Repeat", "Clone", "Join":
				return fixedValue(n.Args[0], depth+1)
			case "Map":
				if len(n.Args) == 2 {
					return fixedValue(n.Args[1], depth+1)
				}
			}
		}
		// Calls whose arguments are all fixed remain fixed identity sources,
		// including normalization and conversions not explicitly evaluated here.
		// A runtime argument keeps the expression dynamic.
		// flag.String/Int defaults are the configured value; flag name and
		// help text are protocol metadata, never identity defaults.
		if method, ok := n.Fun.(*ast.SelectorExpr); ok && (fieldName(method.X) == "fs" || fieldName(method.X) == "f") && (method.Sel.Name == "String" || method.Sel.Name == "Int") && len(n.Args) == 3 {
			return fixedValue(n.Args[1], depth+1)
		}
		if len(n.Args) == 0 {
			return "", false
		}
		values := make([]string, len(n.Args))
		for i, arg := range n.Args {
			value, fixed := fixedValue(arg, depth+1)
			if !fixed {
				return "", false
			}
			values[i] = value
		}
		return strings.Join(values, ""), true
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
			// This named seed creates a public fixture key object, not an
			// identity string. Keep its exact source/factory/value boundary.
			if name == "service" && (path == "internal/muinterop/linux.go" || path == "internal/muinterop/publisher2.go") {
				call, ok := e.(*ast.CallExpr)
				if ok && fieldName(call.Fun) == "Ed25519" && len(call.Args) == 1 && value == "keymaker-service-root" {
					return
				}
			}
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

func guardSwift(raw []byte) string { return guardSwiftSource("", raw) }

func guardSwiftSource(path string, raw []byte) string {
	if literalIdentity("swift", string(raw)) {
		return "fixed owner, account or home literal"
	}
	fixed := map[string]bool{}
	for _, match := range swiftFixedAssignment.FindAllSubmatchIndex(raw, -1) {
		name := string(raw[match[2]:match[3]])
		// One immutable public protocol namespace, not an owner identity.
		// Require the exact declaration and source; retain fallback detection.
		lineStart := bytes.LastIndexByte(raw[:match[0]], '\n') + 1
		lineEnd := bytes.IndexByte(raw[match[1]:], '\n')
		if lineEnd < 0 {
			lineEnd = len(raw)
		} else {
			lineEnd += match[1]
		}
		protocolService := path == "cmd/mac-keyvault-enclave/NamecoinJournalStorage.swift" &&
			strings.TrimSpace(string(raw[lineStart:lineEnd])) == `static let service = "works.relux.mac-keyvault.namecoin-journal.v1"`
		if (identityField(name) || strings.EqualFold(name, "label")) && !protocolService {
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

// Match the repository's Go and Swift test-file naming conventions. This is
// source inventory, not a compiler or an identity data-flow enforcement boundary.
func productionIdentitySource(path string) bool {
	return filepath.Ext(path) == ".go" && !strings.HasSuffix(path, "_test.go") ||
		filepath.Ext(path) == ".swift" && !strings.HasSuffix(path, "Tests.swift")
}

// The exact shipped namespace is compatible; changing its value, declaration,
// source or adding a fixed owner/fallback still trips the same bounded scanner.
func TestSwiftPublicProtocolNamespaceBoundary(t *testing.T) {
	const path = "cmd/mac-keyvault-enclave/NamecoinJournalStorage.swift"
	const declaration = `static let service = "works.relux.mac-keyvault.namecoin-journal.v1"`
	for _, row := range []struct{ path, source, want string }{
		{path, declaration, ""},
		{path, "    " + declaration + "\n", ""},
		{"copy/Storage.swift", declaration, "fixed native identity-bearing field"},
		{path, strings.Replace(declaration, ".v1", ".v2", 1), "fixed native identity-bearing field"},
		{path, strings.TrimPrefix(declaration, "static "), "fixed native identity-bearing field"},
		{path, strings.Replace(declaration, "let ", "var ", 1), "fixed native identity-bearing field"},
		{path, declaration + `; let owner = "fixture-person"`, "fixed native identity-bearing field"},
		{path, declaration + "\n" + `let owner = "fixture-person"`, "fixed native identity-bearing field"},
		{path, declaration + "\n" + `let chosen = suppliedService ?? service`, "fixed native identity fallback"},
	} {
		if got := guardSwiftSource(row.path, []byte(row.source)); got != row.want {
			t.Errorf("namespace boundary: got %q, want %q", got, row.want)
		}
	}
}

// Test fixtures are excluded consistently in both languages; near-miss names
// and production sources remain scanned rather than exempting a directory.
func TestProductionIdentitySourceInventory(t *testing.T) {
	for path, want := range map[string]bool{
		"internal/example/main.go": true, "internal/example/main_test.go": false,
		"cmd/example/Storage.swift": true, "cmd/example/StorageTests.swift": false,
		"cmd/example/StorageTest.swift": true, "cmd/example/TestsStorage.swift": true,
		"cmd/example/StorageTests.swift.go": true, "docs/example.md": false,
	} {
		if productionIdentitySource(path) != want {
			t.Errorf("incorrect source inventory: %s", path)
		}
	}
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
		if !productionIdentitySource(p) {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if filepath.Ext(p) == ".swift" {
			if hit := guardSwiftSource(filepath.ToSlash(relative), raw); hit != "" {
				t.Errorf("%s: %s", p, hit)
			}
			return nil
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
		{"Service: service", `Service: strings.Trim(" unseen-person ", " ")`, "fixed identity-bearing field"},
		{"Service: service", `Service: normalize(("unseen-person"))`, "fixed identity-bearing field"},
		{"Service: service", `Service: strings.TrimFunc("unseen-person", unicode.IsSpace)`, "fixed identity-bearing field"},
		{"Service: service", `Service: strings.Trim("unseen-person", suppliedCutset)`, "fixed identity-bearing field"},
		{"Service: service", `Service: strings.Join([]string{"unseen", "person"}, "-")`, "fixed identity-bearing field"},
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
	for _, plant := range []struct {
		source  string
		refused bool
	}{
		{`package probe; func f() { service := fs.String("service", "", "help"); _ = service }`, false},
		{`package probe; func f() { service := fs.String("service", "fixed-person", "help"); _ = service }`, true},
	} {
		hit, err := guardGo("copy/probe.go", []byte(plant.source))
		if err != nil || (hit != "") != plant.refused {
			t.Fatal("flag-default boundary control failed", hit, err)
		}
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
	for _, fallback := range []string{`("unseen-person")`, `(("unseen-person"))`, `(fallback)`} {
		source := `let fallback = "unseen-person"; let chosen = suppliedService ?? ` + fallback
		if got := guardSwift([]byte(source)); got != "fixed native identity fallback" {
			t.Fatal("parenthesized native fallback was admitted", got)
		}
	}
	if hit, err := guardGo("copy/probe.go", []byte(strings.Replace(copied, "Service: service", `Service: strings.Trim(service, " ")`, 1))); hit != "" || err != nil {
		t.Fatal("runtime normalization was refused", hit, err)
	}
	if got := guardSwift([]byte(`let fallback = ("unseen-person"); let chosen = suppliedService ?? fallback`)); got != "fixed native identity fallback" {
		t.Fatal("parenthesized fixed alias was admitted", got)
	}
	if got := guardSwift([]byte(`let chosen = suppliedService ?? otherService`)); got != "" {
		t.Fatal("runtime fallback input refused", got)
	}
	if got := guardSwift([]byte(`let service = suppliedIdentity; let label = prefix + service`)); got != "" {
		t.Fatal("native parameterized input refused", got)
	}
}

var fixtureMatrixLiteral = regexp.MustCompile(`[!@][a-zA-Z0-9._=/-]+:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

var fixtureProcessLabel = regexp.MustCompile(`(?i)\b(?:meta|keeper|orchestrator)\b`)

var fixtureRole = regexp.MustCompile(`(?i)(?:^|[._-])(?:keeper|orch)(?:[._-]|$)`)
var fixtureTransportIdentity = regexp.MustCompile(`^fixture-[a-z0-9]+(?:-[a-z0-9]+)*$`)
var fixtureBoardParent = regexp.MustCompile(`^(?:STORY|TASK)-fixture-[a-z0-9]+(?:-[a-z0-9]+)*$`)

func fixtureConfigIdentityHit(container, field string, value any) bool {
	var allowed *regexp.Regexp
	switch container + "." + field {
	case "a2a.identity", "a2a.profile":
		allowed = fixtureTransportIdentity
	case "task_board.parent":
		allowed = fixtureBoardParent
	default:
		return false
	}
	text, ok := value.(string)
	return !ok || !allowed.MatchString(text)
}

func fixtureGoConfigHit(entry *ast.KeyValueExpr) bool {
	fields, ok := entry.Value.(*ast.CompositeLit)
	if !ok {
		return false
	}
	for _, element := range fields.Elts {
		field, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		value, fixed := fixedValue(field.Value, 0)
		var input any
		if fixed {
			input = value
		}
		if fixtureConfigIdentityHit(fieldName(entry.Key), fieldName(field.Key), input) {
			return true
		}
	}
	return false
}

// Fixture principals use reserved example domains and neutral local labels.
// Recursion checks JSON strings and base64-encoded public fields as well as text.
func fixtureIdentityHit(raw string, depth int) bool {
	if raw == "" || depth > 8 || len(raw) > 1<<20 {
		return false
	}
	if fixtureProcessLabel.MatchString(raw) || fixtureRole.MatchString(raw) {
		return true
	}
	for _, scope := range ownerScopeLiteral.FindAllString(raw, -1) {
		if scope != "owner:example" && !strings.HasPrefix(scope, "owner:fixture-") {
			return true
		}
	}
	for _, principal := range fixtureMatrixLiteral.FindAllString(raw, -1) {
		local, domain, _ := strings.Cut(strings.TrimLeft(principal, "@!"), ":")
		example := strings.HasSuffix(domain, ".invalid") || domain == "example.com" || domain == "example.org" || domain == "example.net"
		if !example || fixtureRole.MatchString(local) {
			return true
		}
	}
	var value any
	if json.Unmarshal([]byte(raw), &value) == nil {
		var walk func(any, string) bool
		walk = func(v any, container string) bool {
			switch x := v.(type) {
			case string:
				return fixtureIdentityHit(x, depth+1)
			case []any:
				for _, item := range x {
					if walk(item, container) {
						return true
					}
				}
			case map[string]any:
				for key, item := range x {
					if fixtureConfigIdentityHit(container, key, item) || fixtureIdentityHit(key, depth+1) || walk(item, key) {
						return true
					}
				}
			}
			return false
		}
		if walk(value, "") {
			return true
		}
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(raw)
		if err == nil && fixtureIdentityHit(string(decoded), depth+1) {
			return true
		}
	}
	return false
}

func muFixtureSources(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, pattern := range []string{
		"../../cmd/swarma-keyvault/mu*_test.go",
		"../../internal/mugrant/*_test.go",
		"../../internal/grants/mu*_test.go",
		"../../internal/grants/linux*_test.go",
	} {
		matched, err := filepath.Glob(pattern)
		if err != nil || len(matched) == 0 {
			t.Fatal("MU fixture family unavailable", pattern, err)
		}
		files = append(files, matched...)
	}
	return files
}

// Retained MU test literals and shipped public JSON examples admit only neutral
// fixture principals, including decoded serialized fields. The source guard's
// deliberate arbitrary-value plants remain a separate, bounded scope.
func TestMUFixtureIdentityBoundary(t *testing.T) {
	files := muFixtureSources(t)
	for _, path := range files {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(node ast.Node) bool {
			if entry, ok := node.(*ast.KeyValueExpr); ok && fixtureGoConfigHit(entry) {
				t.Errorf("transport fixture configuration boundary failed in %s", filepath.Base(path))
			}
			literal, ok := node.(*ast.BasicLit)
			if ok && literal.Kind == token.STRING {
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				if fixtureIdentityHit(value, 0) {
					t.Errorf("fixture identity boundary failed in %s", filepath.Base(path))
				}
			}
			return true
		})
	}
	assets, err := filepath.Glob("../../agents/skills/swarma-keyvault/assets/local-verify/*.json")
	if err != nil || len(assets) == 0 {
		t.Fatal("public examples unavailable", err)
	}
	for _, path := range assets {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if fixtureIdentityHit(string(raw), 0) {
			t.Errorf("public fixture identity boundary failed in %s", filepath.Base(path))
		}
	}
}

// The fixture check detects raw, JSON and encoded violations, while legitimate
// reserved example principals pass in all supported serializations.
func TestFixtureIdentityBoundaryPlants(t *testing.T) {
	for _, tc := range []struct {
		principal string
		forbidden bool
	}{
		{"@reader:example.invalid", false}, {"@reader:interop.invalid", false},
		{"@reader:example.org", false}, {"@reader:unreserved.test", true},
		{"!fixture-room:example.invalid", false}, {"!fixture-room:outside.test", true},
		{"owner:fixture-owner", false}, {"owner:example", false}, {"owner:account", true},
		{"metadata", false}, {"keeper", true},
		{"fixture-receiver", false}, {"sample.orch-node", true},
		{"a2a.identity", false}, {"grant/1", false}, {"mac-keyvault", false},
		{"@sample.keeper-node:example.invalid", true},
	} {
		raw, err := json.Marshal(map[string]string{"principal": tc.principal})
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{tc.principal, string(raw), base64.RawURLEncoding.EncodeToString(raw)} {
			if fixtureIdentityHit(value, 0) != tc.forbidden {
				t.Fatal("fixture serialization control verdict differs")
			}
		}
	}
}

// Every retained library witness belongs to the scanned family, regardless of
// its current literal values. Removing a family from the collector fails here.
func TestMUFixtureScopeIncludesLibraries(t *testing.T) {
	files := map[string]bool{}
	for _, path := range muFixtureSources(t) {
		files[filepath.ToSlash(path)] = true
	}
	for _, path := range []string{
		"../../internal/mugrant/attestation_test.go",
		"../../internal/mugrant/binding_test.go",
		"../../internal/mugrant/issuer_test.go",
		"../../internal/mugrant/request_test.go",
		"../../internal/mugrant/keymaker_test.go",
		"../../internal/grants/mu_projection_test.go",
		"../../internal/grants/mu_docking_test.go",
		"../../internal/grants/mu_service_test.go",
		"../../internal/grants/mu_receiver_test.go",
		"../../internal/grants/linux_verifier_test.go",
	} {
		if !files[path] {
			t.Error("retained MU library fixture outside scan scope", path)
		}
	}
}

// Identity-bearing transport configuration fields admit neutral fixture names
// in Go maps, JSON and encoded JSON. Arbitrary, malformed and role-qualified
// values refuse; parent/profile protocol fields outside that config stay valid.
func TestFixtureTransportConfigBoundaryPlants(t *testing.T) {
	for _, field := range []struct {
		container, name, positive string
	}{
		{"a2a", "identity", "fixture-receiver"},
		{"a2a", "profile", "fixture-profile"},
		{"task_board", "parent", "STORY-fixture-parent"},
	} {
		for _, tc := range []struct {
			value     any
			forbidden bool
		}{
			{field.positive, false}, {"sample.receiver-node", true},
			{"sample.orch-node", true}, {"sample.keeper-node", true},
			{"fixture-", true}, {"", true}, {nil, true}, {1, true},
		} {
			raw, err := json.Marshal(map[string]any{field.container: map[string]any{field.name: tc.value}})
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range []string{string(raw), base64.RawURLEncoding.EncodeToString(raw)} {
				if fixtureIdentityHit(value, 0) != tc.forbidden {
					t.Fatal("transport fixture serialization verdict differs", field.name)
				}
			}
			if text, ok := tc.value.(string); ok {
				source := "map[string]any{" + strconv.Quote(field.container) + ": map[string]any{" + strconv.Quote(field.name) + ": " + strconv.Quote(text) + "}}"
				expression, err := parser.ParseExpr(source)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				ast.Inspect(expression, func(node ast.Node) bool {
					if entry, ok := node.(*ast.KeyValueExpr); ok && fixtureGoConfigHit(entry) {
						found = true
					}
					return true
				})
				if found != tc.forbidden {
					t.Fatal("Go transport fixture verdict differs", field.name)
				}
			}
		}
	}
	for _, raw := range []string{`{"type":"grant/1","parent":null}`, `{"profile":"mac-agent","parent":"sha256:fixture"}`} {
		if fixtureIdentityHit(raw, 0) {
			t.Fatal("product/protocol field refused outside transport configuration")
		}
	}
}
