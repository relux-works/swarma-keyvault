package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// SHA-256 of the exact bytes of the frozen public v1 record file, computed with
// the system shasum and not by product code. That file is the canonical encoding
// of its own record, so it is also the digest `recovery pub` must print for it.
const recoveryV1FixtureDigest = "7b1e72bac729e8c1e8872ac2017e3f1ed236b5340010e183ca4475944fd2465c"

func recoveryDigestFixture(t *testing.T) ([]byte, RecoveryRecord) {
	t.Helper()
	raw, err := os.ReadFile("testdata/recovery/v1-public-record.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseRecoveryRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, r
}

func recoveryDigestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Claim: the digest printed for the frozen public v1 record equals an
// independently computed literal (the file's own SHA-256), so a function that
// hashes some other encoding, a prefix, or hex of the wrong case fails. The
// literal is first checked against the file itself so a changed fixture cannot
// silently keep the test green. Limit: one frozen record; v2 is covered below.
func TestRecoveryPairDigestFixtureAnchor(t *testing.T) {
	raw, r := recoveryDigestFixture(t)
	if recoveryDigestOf(raw) != recoveryV1FixtureDigest {
		t.Fatal("fixture file changed; the literal pin no longer describes it")
	}
	got, err := r.PairMetadataSHA256()
	if err != nil || got != recoveryV1FixtureDigest {
		t.Fatalf("digest %q err %v, want the independent literal", got, err)
	}
	if len(got) != 64 || got != strings.ToLower(got) {
		t.Fatal("digest is not 64 lowercase hex")
	}
}

// Claim: for both retained schemas the value `recovery pub` prints for a pair
// that the manager described equals (a) the SHA-256 of the exact stored bytes,
// (b) what the attach's own binding computes, and (c) a pin the real attach
// preflight ACCEPTS and carries to the helper stage. The pair is served to the
// attach as bytes by the fake native; the printed side comes from the record the
// manager returns. Limit: fake store and fake native; no Keychain read.
func TestRecoveryPairDigestIsTheAttachPin(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, schema)
			raw := bytes.Clone(x.fake.pair)
			stored, err := parseRecoveryRecord(raw)
			if err != nil {
				t.Fatal(err)
			}
			manager := NewRecoveryManager(&recoveryFakeStore{groups: []RecoveryRecord{stored}}, FileLock{Path: t.TempDir() + "/recovery.lock"})
			described, err := manager.Describe(stored.Service, stored.Version)
			if err != nil {
				t.Fatal(err)
			}
			printed, err := described.PairMetadataSHA256()
			if err != nil {
				t.Fatal(err)
			}
			if printed != recoveryDigestOf(raw) {
				t.Fatalf("printed digest %s is not the SHA-256 of the stored bytes", printed)
			}
			if rootGrantsPairBinding(raw, described).MetadataSHA256 != printed {
				t.Fatal("printed digest differs from the attach binding")
			}
			q := rootGrantsAttachRequestFor(t, schema)
			q.ExpectedPairMetadataSHA256 = printed
			recorder := &rootGrantsRunRecorder{result: RootGrantsAttachResult{Outcome: "stored", PairUnchanged: true}}
			if _, err := attachRootGrantsPinned(context.Background(), x.vault, q, rootGrantsFixedNow, recorder.run); err != nil || recorder.calls != 1 {
				t.Fatalf("the printed digest was not accepted as the attach pin: %v calls=%d", err, recorder.calls)
			}
		})
	}
}

// Claim: the digest depends on every part of the canonical metadata. Each
// single-field change that leaves the record valid yields a digest different
// from the original and from every other change, and a one-byte change in the
// stored bytes changes it to the independently computed SHA-256 of those bytes.
// The attach refuses the ORIGINAL printed digest for a pair whose stored bytes
// changed by one byte, before the helper stage, and accepts the digest of the
// changed bytes (the pin binds the exact record; a constant or partial hash fails).
// Limit: a sample of fields, not an exhaustive byte sweep.
func TestRecoveryPairDigestBindsTheExactMetadata(t *testing.T) {
	raw, base := recoveryDigestFixture(t)
	original, err := base.PairMetadataSHA256()
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*RecoveryRecord){
		"created":          func(r *RecoveryRecord) { r.Created = "2026-01-02T03:04:06Z" },
		"group-id":         func(r *RecoveryRecord) { r.GroupID = strings.Repeat("1", 32) },
		"version":          func(r *RecoveryRecord) { r.Version = 2 },
		"service":          func(r *RecoveryRecord) { r.Service = "other" },
		"nostr-version":    func(r *RecoveryRecord) { r.Nostr.Version = 3 },
		"namecoin-version": func(r *RecoveryRecord) { r.Namecoin.Version = 2 },
	}
	seen := map[string]string{original: "original"}
	for name, mutate := range mutations {
		m := base
		mutate(&m)
		mraw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseRecoveryRecord(mraw); err != nil {
			t.Fatalf("%s: the mutation is not a valid record, so it proves nothing: %v", name, err)
		}
		digest, err := m.PairMetadataSHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if digest != recoveryDigestOf(mraw) {
			t.Fatalf("%s: digest is not the SHA-256 of the record bytes", name)
		}
		if other, dup := seen[digest]; dup {
			t.Fatalf("%s: digest equals the one of %s", name, other)
		}
		seen[digest] = name
	}
	flipped := bytes.Replace(raw, []byte("03:04:05Z"), []byte("03:04:06Z"), 1)
	if bytes.Equal(flipped, raw) {
		t.Fatal("fixture lost its created time; the one-byte change did not apply")
	}
	flippedRecord, err := parseRecoveryRecord(flipped)
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := flippedRecord.PairMetadataSHA256(); err != nil || digest == original || digest != recoveryDigestOf(flipped) {
		t.Fatalf("a one-byte change did not move the digest to the independent value: %v", err)
	}
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, schema)
			stored, err := parseRecoveryRecord(x.fake.pair)
			if err != nil {
				t.Fatal(err)
			}
			printed, _ := stored.PairMetadataSHA256()
			changed := stored
			changed.Created = "2026-01-02T03:04:06Z"
			changedRaw, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			changedDigest, _ := changed.PairMetadataSHA256()
			x.fake.pair = changedRaw
			q := rootGrantsAttachRequestFor(t, schema)
			q.ExpectedPairMetadataSHA256 = printed
			recorder := &rootGrantsRunRecorder{result: RootGrantsAttachResult{Outcome: "stored", PairUnchanged: true}}
			_, err = attachRootGrantsPinned(context.Background(), x.vault, q, rootGrantsFixedNow, recorder.run)
			failure, ok := RootGrantsAttachFailureOf(err)
			if !ok || failure.Code != "retained_record_mismatch" || recorder.calls != 0 {
				t.Fatalf("the stale digest was not refused before the helper: %v calls=%d", err, recorder.calls)
			}
			q.ExpectedPairMetadataSHA256 = changedDigest
			if _, err := attachRootGrantsPinned(context.Background(), x.vault, q, rootGrantsFixedNow, recorder.run); err != nil || recorder.calls != 1 {
				t.Fatalf("the digest of the changed bytes was refused: %v calls=%d", err, recorder.calls)
			}
		})
	}
}

// Claim: no digest is produced for a record the store or the attach would not
// accept, and the refusal is the closed invalid_record code. The valid control
// first shows that a function that refuses everything fails this test.
// Limit: representative invalid fields, one at a time.
func TestRecoveryPairDigestRefusesInvalidRecords(t *testing.T) {
	_, valid := recoveryDigestFixture(t)
	if digest, err := valid.PairMetadataSHA256(); err != nil || digest == "" {
		t.Fatal("positive control failed")
	}
	cases := map[string]RecoveryRecord{"zero": {}}
	for name, mutate := range map[string]func(*RecoveryRecord){
		"schema":            func(r *RecoveryRecord) { r.Schema = "keyvault-recovery/3" },
		"short-group-id":    func(r *RecoveryRecord) { r.GroupID = "00" },
		"upper-group-id":    func(r *RecoveryRecord) { r.GroupID = strings.Repeat("A", 32) },
		"created-form":      func(r *RecoveryRecord) { r.Created = "2026-01-02T03:04:05+00:00" },
		"nostr-presence":    func(r *RecoveryRecord) { r.Nostr.Presence = "biometry-any" },
		"namecoin-origin":   func(r *RecoveryRecord) { r.Namecoin.Origin = "[00000000/84h/7h/1h]" },
		"shared-wrapping":   func(r *RecoveryRecord) { r.Namecoin.WrappingPoint = r.Nostr.WrappingPoint },
		"empty-namecoin-xp": func(r *RecoveryRecord) { r.Namecoin.XPub = "" },
	} {
		m := valid
		mutate(&m)
		cases[name] = m
	}
	for name, r := range cases {
		digest, err := r.PairMetadataSHA256()
		var refusal *Refusal
		if digest != "" || !errors.As(err, &refusal) || refusal.Code != "recovery_invalid_record" {
			t.Fatalf("%s: digest %q err %v; want no digest and recovery_invalid_record", name, digest, err)
		}
	}
}

// Claim: describing a missing pair yields no record and therefore no digest, and
// an ambiguous pair (two records for one address) is refused the same way. The
// single-record control describes and digests normally. Limit: fake store.
func TestRecoveryDescribeMissingOrAmbiguousPairHasNoDigest(t *testing.T) {
	_, r := recoveryDigestFixture(t)
	newManager := func(groups ...RecoveryRecord) *RecoveryManager {
		return NewRecoveryManager(&recoveryFakeStore{groups: groups}, FileLock{Path: t.TempDir() + "/recovery.lock"})
	}
	if described, err := newManager(r).Describe(r.Service, r.Version); err != nil {
		t.Fatal(err)
	} else if digest, err := described.PairMetadataSHA256(); err != nil || digest != recoveryV1FixtureDigest {
		t.Fatal("positive control failed")
	}
	for name, m := range map[string]*RecoveryManager{"missing": newManager(), "ambiguous": newManager(r, r)} {
		described, err := m.Describe(r.Service, r.Version)
		if err == nil {
			t.Fatalf("%s: describe succeeded", name)
		}
		if digest, derr := described.PairMetadataSHA256(); digest != "" || derr == nil {
			t.Fatalf("%s: a digest exists for a pair that was not described", name)
		}
	}
	if _, err := newManager().Describe(r.Service, r.Version); !errors.Is(err, ErrNotFound) {
		t.Fatal("a missing pair is not ErrNotFound")
	}
}

// recoveryShared is the one function that may hash the pair metadata.
const recoveryShared = "recoveryMetadataSHA256"

// recoveryDigestSite names one place of the production source that produces a
// pair metadata digest and what the guard requires of it.
type recoveryDigestSite struct {
	// key is "name" or "Type.name" of the function.
	key string
	// field is the composite-literal key that holds the digest; empty means the
	// first result of every return that is not the empty string.
	field string
	// argument is the identifier the shared function must be called with.
	argument string
	// marshalOf, when set, means argument is defined exactly once as
	// `argument, _ := json.Marshal(marshalOf)`; when empty, argument must be the
	// function's first parameter and is never assigned.
	marshalOf string
}

var recoveryHashPackages = map[string]bool{"crypto": true, "crypto/md5": true, "crypto/sha1": true, "crypto/sha256": true, "crypto/sha512": true}

func recoveryFuncKey(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) == 1 {
		if id, ok := fd.Recv.List[0].Type.(*ast.Ident); ok {
			return id.Name + "." + fd.Name.Name
		}
	}
	return fd.Name.Name
}

// recoveryHashNames returns the local names under which the file imports a hash
// package (only that package when only is set) and whether it dot-imports one,
// which would hide every use.
func recoveryHashNames(f *ast.File, only string) (map[string]bool, bool) {
	names, dot := map[string]bool{}, false
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !recoveryHashPackages[path] || (only != "" && path != only) {
			continue
		}
		switch {
		case imp.Name == nil:
			names[path[strings.LastIndex(path, "/")+1:]] = true
		case imp.Name.Name == ".":
			dot = true
		case imp.Name.Name != "_":
			names[imp.Name.Name] = true
		}
	}
	return names, dot
}

// recoveryDigestProblems checks the expression that PRODUCES the digest, not the
// presence of a shared call: every digest-producing return result (or the
// composite-literal field) must be exactly recoveryMetadataSHA256(argument); the
// argument must be the unmodified input; the shared name must not be rebound; the
// field must not be assigned afterwards; and the body must not touch a hash
// package under any import name. An empty result means the site conforms.
func recoveryDigestProblems(src string, site recoveryDigestSite) []string {
	f, err := parser.ParseFile(token.NewFileSet(), "source.go", src, 0)
	if err != nil {
		return []string{"parse: " + err.Error()}
	}
	var fd *ast.FuncDecl
	for _, d := range f.Decls {
		if decl, ok := d.(*ast.FuncDecl); ok && decl.Body != nil && recoveryFuncKey(decl) == site.key {
			fd = decl
		}
	}
	if fd == nil {
		return []string{site.key + ": function not found"}
	}
	var problems []string
	note := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	isIdent := func(e ast.Expr, name string) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == name
	}
	var produced []ast.Expr
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if site.field == "" && len(x.Results) > 0 {
				if lit, ok := x.Results[0].(*ast.BasicLit); !ok || lit.Value != `""` {
					produced = append(produced, x.Results[0])
				}
			}
		case *ast.KeyValueExpr:
			if site.field != "" && isIdent(x.Key, site.field) {
				produced = append(produced, x.Value)
			}
		}
		return true
	})
	if len(produced) == 0 {
		note("no expression produces the digest")
	}
	for _, e := range produced {
		call, ok := e.(*ast.CallExpr)
		if !ok || !isIdent(call.Fun, recoveryShared) || len(call.Args) != 1 {
			note("the digest is not exactly %s(%s)", recoveryShared, site.argument)
			continue
		}
		if !isIdent(call.Args[0], site.argument) {
			note("%s is not called with the identifier %s", recoveryShared, site.argument)
		}
	}
	hashNames, dot := recoveryHashNames(f, "")
	if dot {
		note("the file dot-imports a hash package")
	}
	checkFields := func(list *ast.FieldList) {
		if list == nil {
			return
		}
		for _, field := range list.List {
			for _, name := range field.Names {
				if name.Name == recoveryShared {
					note("%s is rebound as a parameter or result", recoveryShared)
				}
			}
		}
	}
	checkFields(fd.Type.Params)
	checkFields(fd.Type.Results)
	if site.field == "" && fd.Type.Results != nil {
		for _, field := range fd.Type.Results.List {
			if len(field.Names) > 0 {
				note("named results hide the digest-producing expression")
			}
		}
	}
	defines := 0
	var defining ast.Expr
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			checkFields(x.Type.Params)
			checkFields(x.Type.Results)
		case *ast.ValueSpec:
			for _, name := range x.Names {
				if name.Name == recoveryShared {
					note("%s is rebound by a declaration", recoveryShared)
				}
				if name.Name == site.argument {
					defines++
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				switch target := lhs.(type) {
				case *ast.Ident:
					if target.Name == recoveryShared {
						note("%s is rebound by an assignment", recoveryShared)
					}
					if target.Name == site.argument {
						defines++
						if i == 0 && len(x.Rhs) == 1 {
							defining = x.Rhs[0]
						}
					}
				case *ast.IndexExpr:
					if isIdent(target.X, site.argument) {
						note("the bytes of %s are modified in place", site.argument)
					}
				case *ast.SelectorExpr:
					if site.field != "" && target.Sel.Name == site.field {
						note("the digest field is assigned after construction")
					}
				}
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && (id.Name == "copy" || id.Name == "clear") && len(x.Args) > 0 && isIdent(x.Args[0], site.argument) {
				note("the bytes of %s are modified in place", site.argument)
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && hashNames[id.Name] {
				note("the body uses a hash package directly")
			}
		}
		return true
	})
	if site.marshalOf != "" {
		conforming := false
		if call, ok := defining.(*ast.CallExpr); ok && defines == 1 && len(call.Args) == 1 && isIdent(call.Args[0], site.marshalOf) {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && isIdent(sel.X, "json") && sel.Sel.Name == "Marshal" {
				conforming = true
			}
		}
		if !conforming {
			note("%s is not defined exactly once as json.Marshal(%s)", site.argument, site.marshalOf)
		}
	} else {
		first := ""
		if params := fd.Type.Params; params != nil && len(params.List) > 0 && len(params.List[0].Names) > 0 {
			first = params.List[0].Names[0].Name
		}
		if first != site.argument || defines != 0 {
			note("%s must be the unmodified first parameter", site.argument)
		}
	}
	return problems
}

// recoveryHashers lists the functions of a source file that use the SHA-256
// package under any import name.
func recoveryHashers(src string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), "source.go", src, 0)
	if err != nil {
		return nil, err
	}
	names, dot := recoveryHashNames(f, "crypto/sha256")
	if dot {
		return []string{"<dot-import>"}, nil
	}
	var out []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		used := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && names[id.Name] {
					used = true
				}
			}
			return true
		})
		if used {
			out = append(out, recoveryFuncKey(fd))
		}
	}
	sort.Strings(out)
	return out, nil
}

func recoveryPrintSource(imports, body, extra string) string {
	return "package p\nimport (\n" + imports + "\n)\nfunc (r RecoveryRecord) PairMetadataSHA256() (string, error) {\n" + body + "\n}\n" + extra
}

func recoveryBindingSource(body, extra string) string {
	return "package p\nimport \"crypto/sha512\"\nfunc rootGrantsPairBinding(raw []byte, r RecoveryRecord) RootGrantsPairBinding {\n" + body + "\n}\n" + extra
}

// Claim: the printed digest and the attach binding each PRODUCE their digest by
// exactly recoveryMetadataSHA256(raw) on the unmodified input, and no other
// function of the two source files hashes with SHA-256 except the reviewed
// ones. A shared call that is present but whose result is discarded in favour of
// an independent hash (a helper, an alias, an import alias, an inline hash), a
// rebound or shadowed shared name, a sliced, replaced, reassigned or edited
// input, a transformed result and a digest field overwritten after construction
// are each planted below and must each be reported for their own reason (never
// by a parse error); the conforming forms must report nothing, and so must the
// real source. Limit: source shape only, over the two named functions; a hashing
// function added in a third file and called from them is caught at the call
// (the digest is not exactly the shared call), and the behavioural equality is
// TestRecoveryPairDigestIsTheAttachPin.
func TestRecoveryPairDigestHasOneDefinition(t *testing.T) {
	printSite := recoveryDigestSite{key: "RecoveryRecord.PairMetadataSHA256", argument: "raw", marshalOf: "r"}
	bindingSite := recoveryDigestSite{key: "rootGrantsPairBinding", field: "MetadataSHA256", argument: "raw"}
	const imports = "\"crypto/sha256\"\n\"encoding/hex\"\n\"encoding/json\"\n\"strings\""
	const prologue = "raw, err := json.Marshal(r)\nif err != nil {\nreturn \"\", recoveryRefuse(\"invalid_record\")\n}\nif _, err := parseRecoveryRecord(raw); err != nil {\nreturn \"\", err\n}\n"
	const copyHelper = "func recoveryMetadataCopy(raw []byte) string {\nh := sha256.Sum256(raw)\nreturn hex.EncodeToString(h[:])\n}\n"
	type plant struct {
		name, source, want string
		site               recoveryDigestSite
	}
	plants := []plant{
		{"discarded shared result, helper copy", recoveryPrintSource(imports, prologue+"_ = recoveryMetadataSHA256(raw)\nreturn recoveryMetadataCopy(raw), nil", copyHelper), "is not exactly", printSite},
		{"inline hash", recoveryPrintSource(imports, prologue+"h := sha256.Sum256(raw)\nreturn hex.EncodeToString(h[:]), nil", ""), "uses a hash package directly", printSite},
		{"aliased hash function", recoveryPrintSource(imports, prologue+"hash := sha256.Sum256\nh := hash(raw)\nreturn hex.EncodeToString(h[:]), nil", ""), "uses a hash package directly", printSite},
		{"import alias", recoveryPrintSource("shaX \"crypto/sha256\"\n\"encoding/hex\"\n\"encoding/json\"", prologue+"h := shaX.Sum256(raw)\nreturn hex.EncodeToString(h[:]), nil", ""), "uses a hash package directly", printSite},
		{"shared name shadowed", recoveryPrintSource(imports, prologue+"recoveryMetadataSHA256 := func(b []byte) string { return \"00\" }\nreturn recoveryMetadataSHA256(raw), nil", ""), "is rebound", printSite},
		{"sliced argument", recoveryPrintSource(imports, prologue+"return recoveryMetadataSHA256(raw[1:]), nil", ""), "is not called with the identifier", printSite},
		{"other input", recoveryPrintSource(imports, prologue+"other := []byte(r.Created)\nreturn recoveryMetadataSHA256(other), nil", ""), "is not called with the identifier", printSite},
		{"argument reassigned", recoveryPrintSource(imports, prologue+"raw = raw[1:]\nreturn recoveryMetadataSHA256(raw), nil", ""), "is not defined exactly once", printSite},
		{"argument edited in place", recoveryPrintSource(imports, prologue+"raw[0] = 0\nreturn recoveryMetadataSHA256(raw), nil", ""), "modified in place", printSite},
		{"result transformed", recoveryPrintSource(imports, prologue+"return strings.ToUpper(recoveryMetadataSHA256(raw)), nil", ""), "is not exactly", printSite},
		{"named result with a bare return", "package p\nimport (\n" + imports + "\n)\nfunc (r RecoveryRecord) PairMetadataSHA256() (digest string, err error) {\n" + prologue + "digest = recoveryMetadataCopy(raw)\nreturn\n}\n" + copyHelper, "named results", printSite},
		{"shared call without a digest result", recoveryPrintSource(imports, prologue+"_ = recoveryMetadataSHA256(raw)\nreturn \"\", nil", ""), "no expression produces the digest", printSite},
		{"binding: helper copy in the field", recoveryBindingSource("_ = recoveryMetadataSHA256(raw)\nreturn RootGrantsPairBinding{MetadataSHA256: recoveryMetadataCopy(raw)}", ""), "is not exactly", bindingSite},
		{"binding: sliced argument", recoveryBindingSource("return RootGrantsPairBinding{MetadataSHA256: recoveryMetadataSHA256(raw[1:])}", ""), "is not called with the identifier", bindingSite},
		{"binding: field overwritten later", recoveryBindingSource("b := RootGrantsPairBinding{MetadataSHA256: recoveryMetadataSHA256(raw)}\nb.MetadataSHA256 = recoveryMetadataCopy(raw)\nreturn b", ""), "assigned after construction", bindingSite},
		{"binding: parameter reassigned", recoveryBindingSource("raw = raw[1:]\nreturn RootGrantsPairBinding{MetadataSHA256: recoveryMetadataSHA256(raw)}", ""), "must be the unmodified first parameter", bindingSite},
	}
	for _, p := range plants {
		problems := recoveryDigestProblems(p.source, p.site)
		matched := false
		for _, problem := range problems {
			if strings.HasPrefix(problem, "parse:") || strings.HasSuffix(problem, "function not found") {
				t.Fatalf("%s: the plant is not valid source for the guard: %v", p.name, problems)
			}
			matched = matched || strings.Contains(problem, p.want)
		}
		if !matched {
			t.Fatalf("%s: the guard did not report %q: %v", p.name, p.want, problems)
		}
	}
	for name, source := range map[string]string{
		"conforming print form":   recoveryPrintSource(imports, prologue+"return recoveryMetadataSHA256(raw), nil", ""),
		"conforming binding form": recoveryBindingSource("return RootGrantsPairBinding{Schema: r.Schema, MetadataSHA256: recoveryMetadataSHA256(raw), Version: r.Version}", ""),
	} {
		site := printSite
		if strings.Contains(name, "binding") {
			site = bindingSite
		}
		if problems := recoveryDigestProblems(source, site); len(problems) != 0 {
			t.Fatalf("%s was rejected: %v", name, problems)
		}
	}
	// The package-level layer: a function that hashes with SHA-256 must be one of
	// the reviewed ones.
	if hashers, err := recoveryHashers("package p\nimport shaX \"crypto/sha256\"\nfunc helper(raw []byte) [32]byte {\nreturn shaX.Sum256(raw)\n}\nfunc other() {}\n"); err != nil || !reflect.DeepEqual(hashers, []string{"helper"}) {
		t.Fatalf("a helper hashing through an import alias was not listed: %v %v", hashers, err)
	}
	if hashers, err := recoveryHashers("package p\nimport \"crypto/sha256\"\n" + copyHelper + "func other() {}\n"); err != nil || !reflect.DeepEqual(hashers, []string{"recoveryMetadataCopy"}) {
		t.Fatalf("the helper copy was not listed: %v %v", hashers, err)
	}
	read := func(name string) string {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	binding, record := read("recovery_root_grants.go"), read("recovery_record.go")
	if problems := recoveryDigestProblems(record, printSite); len(problems) != 0 {
		t.Fatalf("the printed digest does not conform: %v", problems)
	}
	if problems := recoveryDigestProblems(binding, bindingSite); len(problems) != 0 {
		t.Fatalf("the attach binding does not conform: %v", problems)
	}
	reviewed := map[string][]string{
		"recovery_record.go": {"recoveryBinding", "recoveryMetadataSHA256", "recoverySeal", "validRecoveryNamecoinPins", "validateWrapping"},
	}
	for name, source := range map[string]string{"recovery_record.go": record, "recovery_root_grants.go": binding} {
		hashers, err := recoveryHashers(source)
		if err != nil {
			t.Fatal(err)
		}
		if want := reviewed[name]; len(want) == 0 && len(hashers) != 0 || len(want) != 0 && !reflect.DeepEqual(hashers, want) {
			t.Fatalf("%s: the functions that hash with SHA-256 are %v, not the reviewed %v; a new hashing function needs review", name, hashers, want)
		}
	}
}
