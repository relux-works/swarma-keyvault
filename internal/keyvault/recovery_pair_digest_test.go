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
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
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

// recoveryReviewedHashers is the reviewed inventory of the functions of the
// non-test source files of this package that use a hash package. A new hashing
// function anywhere in the package fails the guard by name until it is reviewed
// and added here.
var recoveryReviewedHashers = []string{
	"EnclaveStore.signOwnerDocument", "ExportRootGrants", "NewRootGrantsRecord", "RootQualificationCreate",
	"SSHAgent.signAudited", "deriveRecovery", "masterRecoveryNode", "mnemonicIndices", "newRecoveryAdoptionPlan",
	"prepareRootGrantsAttach", "recoveryBinding", "recoveryHash160", "recoveryMetadataSHA256", "recoveryNode.derive",
	"recoveryNode.xpub", "recoverySeal", "rootGrantsBIP85Entropy", "rootGrantsCompletionACK", "rootGrantsPlaintextBinding",
	"sealRootGrantsWithRandom", "validRecoveryNamecoinPins", "validateWrapping",
}

// recoveryIsHashPath is a BOUNDED list of the hash packages the inventory knows,
// not a proof that no other hash constructor exists: an unlisted package is not
// classified as hashing. The behavioural digest tests are the guarantee.
func recoveryIsHashPath(path string) bool {
	switch path {
	case "crypto", "crypto/md5", "crypto/sha1", "crypto/sha256", "crypto/sha3", "crypto/sha512", "crypto/hmac", "hash",
		"golang.org/x/crypto/sha3", "golang.org/x/crypto/blake2b", "golang.org/x/crypto/blake2s",
		"golang.org/x/crypto/ripemd160", "golang.org/x/crypto/pbkdf2", "golang.org/x/crypto/hkdf":
		return true
	}
	return strings.HasPrefix(path, "hash/") || strings.HasPrefix(path, "github.com/btcsuite/btcd/chainhash")
}

func recoveryFuncKey(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) == 1 {
		typ := fd.Recv.List[0].Type
		if star, ok := typ.(*ast.StarExpr); ok {
			typ = star.X
		}
		if id, ok := typ.(*ast.Ident); ok {
			return id.Name + "." + fd.Name.Name
		}
	}
	return fd.Name.Name
}

// recoveryWalk visits every node under root together with its parent.
func recoveryWalk(root ast.Node, visit func(n, parent ast.Node)) {
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		var parent ast.Node
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		visit(n, parent)
		stack = append(stack, n)
		return true
	})
}

// recoveryRefusingImporter loads nothing: every imported package becomes a fake
// package that keeps its import path, so that identifiers of the package itself,
// lexical bindings and package names resolve exactly while members of other
// packages stay unresolved (their errors are ignored).
type recoveryRefusingImporter struct{}

func (recoveryRefusingImporter) Import(path string) (*types.Package, error) {
	if path == "unsafe" {
		return types.Unsafe, nil
	}
	return nil, fmt.Errorf("package %s is not loaded", path)
}

// recoveryPackage is a set of source files type-checked as one package.
type recoveryPackage struct {
	files []*ast.File
	pkg   *types.Package
	info  *types.Info
	errs  []types.Error
}

func recoveryLoad(sources map[string]string) (*recoveryPackage, error) {
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, sources[name], parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	var errs []types.Error
	collect := func(err error) {
		if typeErr, ok := err.(types.Error); ok {
			errs = append(errs, typeErr)
		}
	}
	conf := types.Config{Importer: recoveryRefusingImporter{}, FakeImportC: true, DisableUnusedImportCheck: true, Error: collect}
	pkg, _ := conf.Check("keyvault", fset, files, info)
	if pkg == nil {
		return nil, errors.New("the sources did not type-check into a package")
	}
	return &recoveryPackage{files: files, pkg: pkg, info: info, errs: errs}, nil
}

func (p *recoveryPackage) object(name string) types.Object { return p.pkg.Scope().Lookup(name) }

// resolvesTo reports whether e is an identifier that denotes exactly obj.
func (p *recoveryPackage) resolvesTo(e ast.Expr, obj types.Object) bool {
	id, ok := e.(*ast.Ident)
	return ok && obj != nil && p.info.Uses[id] == obj
}

// isPackage reports whether e is an identifier that denotes the imported package
// with the given path, under whatever local name.
func (p *recoveryPackage) isPackage(e ast.Expr, path string) bool {
	id, ok := e.(*ast.Ident)
	if !ok {
		return false
	}
	name, ok := p.info.Uses[id].(*types.PkgName)
	return ok && name.Imported().Path() == path
}

func (p *recoveryPackage) isNil(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	if !ok {
		return false
	}
	_, nilObject := p.info.Uses[id].(*types.Nil)
	return nilObject
}

// findFunc returns the declaration of key and how many times it is declared.
func (p *recoveryPackage) findFunc(key string) (*ast.FuncDecl, int) {
	var found *ast.FuncDecl
	count := 0
	for _, f := range p.files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil && recoveryFuncKey(fd) == key {
				if found == nil {
					found = fd
				}
				count++
			}
		}
	}
	return found, count
}

// sharedCall reports whether e is exactly recoveryMetadataSHA256(argument): the
// callee resolves to the package-level function (a local binding of the same
// name does not) and the single argument denotes exactly argObj.
func (p *recoveryPackage) sharedCall(e ast.Expr, argObj types.Object) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || call.Ellipsis != token.NoPos {
		return false
	}
	shared, ok := p.object(recoveryShared).(*types.Func)
	return ok && p.resolvesTo(call.Fun, shared) && p.resolvesTo(call.Args[0], argObj)
}

// uses counts the uses of obj under body and how many of them are NOT the single
// argument of a call to one of the callees.
func (p *recoveryPackage) uses(body ast.Node, obj types.Object, callees ...types.Object) (total, stray int) {
	if obj == nil {
		return 0, 0
	}
	recoveryWalk(body, func(n, parent ast.Node) {
		id, ok := n.(*ast.Ident)
		if !ok || p.info.Uses[id] != obj {
			return
		}
		total++
		if call, ok := parent.(*ast.CallExpr); ok && len(call.Args) == 1 && call.Args[0] == ast.Expr(id) {
			for _, callee := range callees {
				if p.resolvesTo(call.Fun, callee) {
					return
				}
			}
		}
		stray++
	})
	return total, stray
}

// shapeProblems reports named results, function literals and every statement form
// other than a block, an if, a return and a := definition.
func shapeProblems(body *ast.BlockStmt, note func(string, ...any)) {
	recoveryWalk(body, func(n, _ ast.Node) {
		switch s := n.(type) {
		case *ast.BlockStmt, *ast.IfStmt, *ast.ReturnStmt:
		case *ast.AssignStmt:
			if s.Tok != token.DEFINE {
				note("statement form not admitted: an assignment other than :=")
			}
		case *ast.FuncLit:
			note("function literals are not admitted")
		case ast.Stmt:
			note("statement form not admitted: %T", s)
		}
	})
}

func namedResults(fd *ast.FuncDecl) bool {
	if fd.Type.Results == nil {
		return false
	}
	for _, field := range fd.Type.Results.List {
		if len(field.Names) > 0 {
			return true
		}
	}
	return false
}

// printerProblems checks the digest printer by construction: the input is defined
// by the first statement as json.Marshal of the receiver and is only ever passed
// to parseRecoveryRecord and to the shared function; every return is a refusal
// (the empty string and a non-nil error) or exactly recoveryMetadataSHA256 of the
// input with a nil error; no named results, closures, loops or other statements.
func (p *recoveryPackage) printerProblems(key string) []string {
	var problems []string
	note := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	fd, count := p.findFunc(key)
	if count != 1 {
		return []string{fmt.Sprintf("%s is declared %d times in the selected build, not once", key, count)}
	}
	if _, ok := p.object(recoveryShared).(*types.Func); !ok {
		note("%s is not a package-level function", recoveryShared)
	}
	if namedResults(fd) {
		note("named results are not admitted")
	}
	shapeProblems(fd.Body, note)
	var raw types.Object
	if fd.Recv != nil && len(fd.Recv.List) == 1 && len(fd.Recv.List[0].Names) == 1 && len(fd.Body.List) > 0 {
		receiver := p.info.Defs[fd.Recv.List[0].Names[0]]
		if as, ok := fd.Body.List[0].(*ast.AssignStmt); ok && as.Tok == token.DEFINE && len(as.Lhs) == 2 && len(as.Rhs) == 1 {
			if call, ok := as.Rhs[0].(*ast.CallExpr); ok && len(call.Args) == 1 {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Marshal" && p.isPackage(sel.X, "encoding/json") && p.resolvesTo(call.Args[0], receiver) {
					if id, ok := as.Lhs[0].(*ast.Ident); ok {
						raw = p.info.Defs[id]
					}
				}
			}
		}
	}
	if raw == nil {
		note("the first statement does not define the input as json.Marshal of the receiver")
		return problems
	}
	if _, stray := p.uses(fd.Body, raw, p.object("parseRecoveryRecord"), p.object(recoveryShared)); stray > 0 {
		note("the input is used outside parseRecoveryRecord and %s (%d uses)", recoveryShared, stray)
	}
	digests := 0
	recoveryWalk(fd.Body, func(n, _ ast.Node) {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return
		}
		if len(ret.Results) != 2 {
			note("a return does not have exactly two results")
			return
		}
		if lit, ok := ret.Results[0].(*ast.BasicLit); ok && lit.Kind == token.STRING && lit.Value == `""` {
			if p.isNil(ret.Results[1]) {
				note("a refusal return carries no error")
			}
			return
		}
		if p.sharedCall(ret.Results[0], raw) && p.isNil(ret.Results[1]) {
			digests++
			return
		}
		note("a return does not produce the digest by exactly %s on the unmodified input", recoveryShared)
	})
	if digests == 0 {
		note("no return produces the digest")
	}
	return problems
}

// bindingProblems checks the attach binding by construction: the body is exactly
// one return of a keyed composite literal of RootGrantsPairBinding whose
// MetadataSHA256 field is exactly recoveryMetadataSHA256 of the first parameter,
// and that parameter is used nowhere else.
func (p *recoveryPackage) bindingProblems(key string) []string {
	var problems []string
	note := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	fd, count := p.findFunc(key)
	if count != 1 {
		return []string{fmt.Sprintf("%s is declared %d times in the selected build, not once", key, count)}
	}
	if namedResults(fd) {
		note("named results are not admitted")
	}
	recoveryWalk(fd.Body, func(n, _ ast.Node) {
		if _, ok := n.(*ast.FuncLit); ok {
			note("function literals are not admitted")
		}
	})
	if len(fd.Body.List) != 1 {
		note("the body is not exactly one return statement")
	}
	var raw types.Object
	if params := fd.Type.Params; params != nil && len(params.List) > 0 && len(params.List[0].Names) > 0 {
		raw = p.info.Defs[params.List[0].Names[0]]
	}
	if raw == nil {
		note("the function has no first parameter")
		return problems
	}
	if total, stray := p.uses(fd.Body, raw, p.object(recoveryShared)); total != 1 || stray != 0 {
		note("the first parameter is used %d times (%d outside the shared call); it must be used exactly once, in the shared call", total, stray)
	}
	var ret *ast.ReturnStmt
	if len(fd.Body.List) > 0 {
		ret, _ = fd.Body.List[len(fd.Body.List)-1].(*ast.ReturnStmt)
	}
	if ret == nil || len(ret.Results) != 1 {
		note("the body does not end in a return of one value")
		return problems
	}
	lit, ok := ret.Results[0].(*ast.CompositeLit)
	if !ok || !p.resolvesTo(lit.Type, p.object("RootGrantsPairBinding")) {
		note("the returned value is not a composite literal of RootGrantsPairBinding")
		return problems
	}
	fields := 0
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			note("the binding literal has an unkeyed element")
			continue
		}
		if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "MetadataSHA256" {
			fields++
			if !p.sharedCall(kv.Value, raw) {
				note("the MetadataSHA256 field is not exactly %s on the unmodified first parameter", recoveryShared)
			}
		}
	}
	if fields != 1 {
		note("the binding literal does not set MetadataSHA256 exactly once")
	}
	return problems
}

// hasherProblems compares the set of functions that use a hash package, resolved
// by import path under any local name, with the reviewed inventory.
func (p *recoveryPackage) hasherProblems(reviewed []string) []string {
	var problems []string
	allowed := map[string]bool{}
	for _, key := range reviewed {
		allowed[key] = true
	}
	seen := map[string]bool{}
	for _, f := range p.files {
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err == nil && imp.Name != nil && imp.Name.Name == "." && recoveryIsHashPath(path) {
				problems = append(problems, "a hash package is dot-imported: "+path)
			}
		}
		for _, d := range f.Decls {
			key := "<package-level>"
			switch decl := d.(type) {
			case *ast.FuncDecl:
				if decl.Body == nil {
					continue
				}
				key = recoveryFuncKey(decl)
			case *ast.GenDecl:
				if decl.Tok == token.IMPORT {
					continue
				}
			}
			used := false
			ast.Inspect(d, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok {
					if name, ok := p.info.Uses[id].(*types.PkgName); ok && recoveryIsHashPath(name.Imported().Path()) {
						used = true
					}
				}
				return true
			})
			if used {
				seen[key] = true
			}
		}
	}
	var unreviewed, missing []string
	for key := range seen {
		if !allowed[key] {
			unreviewed = append(unreviewed, key)
		}
	}
	for _, key := range reviewed {
		if !seen[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(unreviewed)
	sort.Strings(missing)
	for _, key := range unreviewed {
		problems = append(problems, "unreviewed hashing function "+key)
	}
	for _, key := range missing {
		problems = append(problems, "reviewed hashing function not found: "+key)
	}
	return problems
}

// contractProblems applies the call-site contract to a BUILD-SELECTED package and
// fails closed when a required declaration is ambiguous or cannot be typed: a
// duplicate declaration anywhere in the view, a function declared other than
// once, or any type error inside the two checked functions.
func (p *recoveryPackage) contractProblems() []string {
	problems := p.printerProblems("RecoveryRecord.PairMetadataSHA256")
	problems = append(problems, p.bindingProblems("rootGrantsPairBinding")...)
	for _, err := range p.errs {
		if strings.Contains(err.Msg, "redeclared") || strings.Contains(err.Msg, "already declared") {
			problems = append(problems, "duplicate declaration in the selected build: "+err.Msg)
		}
	}
	for _, key := range []string{"RecoveryRecord.PairMetadataSHA256", "rootGrantsPairBinding"} {
		fd, count := p.findFunc(key)
		if count != 1 {
			continue
		}
		for _, err := range p.errs {
			if err.Pos >= fd.Pos() && err.Pos <= fd.End() {
				problems = append(problems, "type error inside "+key+": "+err.Msg)
			}
		}
	}
	return problems
}

var recoveryViews = []struct{ goos, goarch string }{{"darwin", "arm64"}, {"linux", "amd64"}}

// recoverySelect returns the files that the Go build would compile for the
// platform with the default tags, decided by go/build from the file names and
// build constraints (the file contents come from sources).
func recoverySelect(sources map[string]string, goos, goarch string) (map[string]string, error) {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = goos, goarch, true
	ctx.OpenFile = func(path string) (io.ReadCloser, error) {
		source, ok := sources[filepath.Base(path)]
		if !ok {
			return nil, os.ErrNotExist
		}
		return io.NopCloser(strings.NewReader(source)), nil
	}
	selected := map[string]string{}
	for name, source := range sources {
		match, err := ctx.MatchFile(".", name)
		if err != nil {
			return nil, err
		}
		if match {
			selected[name] = source
		}
	}
	return selected, nil
}

// recoveryContractProblems applies the one-definition contract: the hash
// inventory over ALL source files (a separate, text-level view) and, for each
// platform view, the call-site contract on the package that platform compiles.
// An empty result means the sources conform.
func recoveryContractProblems(sources map[string]string, reviewed []string) ([]string, error) {
	all, err := recoveryLoad(sources)
	if err != nil {
		return nil, err
	}
	problems := all.hasherProblems(reviewed)
	for _, view := range recoveryViews {
		selected, err := recoverySelect(sources, view.goos, view.goarch)
		if err != nil {
			return nil, err
		}
		p, err := recoveryLoad(selected)
		if err != nil {
			return nil, err
		}
		for _, problem := range p.contractProblems() {
			problems = append(problems, view.goos+"/"+view.goarch+": "+problem)
		}
	}
	return problems, nil
}

const recoveryStubTypes = `package keyvault
type RecoveryRecord struct{ Created string }
type RootGrantsPairBinding struct{ Schema, MetadataSHA256 string }
func recoveryRefuse(code string) error { return nil }
func parseRecoveryRecord(raw []byte) (RecoveryRecord, error) { return RecoveryRecord{}, nil }
`

const recoveryStubShared = `package keyvault
import (
	"crypto/sha256"
	"encoding/hex"
)
func recoveryMetadataSHA256(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
`

// recoveryStubCopy is an independent hashing helper in an ordinary source file.
const recoveryStubCopy = `package keyvault
import (
	"crypto/sha256"
	"encoding/hex"
)
func recoveryMetadataCopy(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func recoveryPairBindingCopy(raw []byte, r RecoveryRecord) RootGrantsPairBinding {
	h := sha256.Sum256(raw)
	return RootGrantsPairBinding{Schema: r.Created, MetadataSHA256: hex.EncodeToString(h[:])}
}
`

func recoveryStubPrinter(imports, tail string) string {
	return "package keyvault\nimport (\n\"encoding/json\"\n" + imports + "\n)\n" +
		"func (r RecoveryRecord) PairMetadataSHA256() (string, error) {\n" +
		"raw, err := json.Marshal(r)\nif err != nil {\nreturn \"\", recoveryRefuse(\"invalid_record\")\n}\n" +
		"if _, err := parseRecoveryRecord(raw); err != nil {\nreturn \"\", err\n}\n" + tail + "\n}\n"
}

func recoveryStubBinding(body string) string {
	return "package keyvault\nfunc rootGrantsPairBinding(raw []byte, r RecoveryRecord) RootGrantsPairBinding {\n" + body + "\n}\n"
}

func recoveryStubPackage(printer, binding string, extra map[string]string) map[string]string {
	files := map[string]string{"types.go": recoveryStubTypes, "shared.go": recoveryStubShared, "printer.go": printer, "binding.go": binding}
	for name, source := range extra {
		files[name] = source
	}
	return files
}

// Claim: the printed digest and the attach binding each PRODUCE their digest by
// exactly recoveryMetadataSHA256 of the unmodified input, established on the
// type-checked package rather than on text. Identity comes from go/types: the
// callee must RESOLVE to the package-level function, so a range variable, a
// closure, a parameter or a local function value of the same name fails by
// construction; the input must resolve to the variable defined by the first
// statement and may only be passed to parseRecoveryRecord and the shared
// function. The printer admits only := definitions, ifs and returns, every
// return being a refusal or exactly the shared call; the binding is exactly one
// return of a keyed RootGrantsPairBinding literal whose MetadataSHA256 is the
// shared call on the first parameter (a discarded or other literal does not
// count). The set of functions of ALL non-test source files that use a hash
// package (by import path, under any local name) must equal the reviewed
// inventory, so a new hashing helper anywhere is reported by name. Controls: the
// conforming package and the real source report nothing; the plants (the
// reviewer's two mutants among them) must each be reported for their own
// reason on a package that type-checks the same way. Limits: the type check
// loads no imports, so members of other packages are unresolved (identity of this
// package's own symbols and of package names is exact); hash packages are known
// by import path, so a hand-rolled hash that imports none is outside the
// inventory (it can still not reach the two sites); the command-line printer's
// call of PairMetadataSHA256 is not covered; behaviour is covered by
// TestRecoveryPairDigestIsTheAttachPin.
//
// Bounded lint, not a proof: the behavioural tests (the frozen fixture anchor,
// the exact-metadata and attach-pin tests and the command-line goldens) are the
// guarantee that the printed digest equals the attach binding's; this guard only
// makes the likeliest regressions fail early. The call-site contract is
// evaluated on the files the Go build selects for darwin/arm64 and linux/amd64
// with the default tags, and fails closed on a duplicate or ambiguous
// declaration or a type error inside the two checked functions; the hash
// inventory is a separate view over all files and a bounded list of hash
// packages.
func TestRecoveryPairDigestHasOneDefinition(t *testing.T) {
	reviewed := []string{recoveryShared}
	conformingPrinter := recoveryStubPrinter("", "return recoveryMetadataSHA256(raw), nil")
	conformingBinding := recoveryStubBinding("return RootGrantsPairBinding{Schema: r.Created, MetadataSHA256: recoveryMetadataSHA256(raw)}")
	copyFile := map[string]string{"copy.go": recoveryStubCopy}
	type plant struct {
		name, want string
		files      map[string]string
		reviewed   []string
	}
	printer := func(name, imports, tail, want string, extra map[string]string) plant {
		return plant{name, want, recoveryStubPackage(recoveryStubPrinter(imports, tail), conformingBinding, extra), reviewed}
	}
	binding := func(name, body, want string, extra map[string]string) plant {
		return plant{name, want, recoveryStubPackage(conformingPrinter, recoveryStubBinding(body), extra), reviewed}
	}
	const notExactly = "a return does not produce the digest by exactly"
	const strayInput = "the input is used outside"
	const shaImports = "\"crypto/sha256\"\n\"encoding/hex\""
	plants := []plant{
		printer("discarded shared result, helper copy", "", "_ = recoveryMetadataSHA256(raw)\nreturn recoveryMetadataCopy(raw), nil", notExactly, copyFile),
		printer("inline hash", shaImports, "h := sha256.Sum256(raw)\nreturn hex.EncodeToString(h[:]), nil", "unreviewed hashing function RecoveryRecord.PairMetadataSHA256", nil),
		printer("aliased hash function value", shaImports, "hash := sha256.Sum256\nh := hash(raw)\nreturn hex.EncodeToString(h[:]), nil", "unreviewed hashing function RecoveryRecord.PairMetadataSHA256", nil),
		printer("import alias", "shaX \"crypto/sha256\"\n\"encoding/hex\"", "h := shaX.Sum256(raw)\nreturn hex.EncodeToString(h[:]), nil", "unreviewed hashing function RecoveryRecord.PairMetadataSHA256", nil),
		printer("shared name shadowed by a range variable (review mutant)", "", "for _, recoveryMetadataSHA256 := range []func([]byte) string{recoveryMetadataCopy} {\nreturn recoveryMetadataSHA256(raw), nil\n}\nreturn \"\", recoveryRefuse(\"invalid_record\")", notExactly, copyFile),
		printer("shared name shadowed by a closure", "", "recoveryMetadataSHA256 := func(b []byte) string { return \"00\" }\nreturn recoveryMetadataSHA256(raw), nil", notExactly, nil),
		printer("input shadowed by a range variable", "", "for _, raw := range [][]byte{nil} {\nreturn recoveryMetadataSHA256(raw), nil\n}\nreturn \"\", recoveryRefuse(\"invalid_record\")", notExactly, nil),
		printer("sliced argument", "", "return recoveryMetadataSHA256(raw[1:]), nil", notExactly, nil),
		printer("other input", "", "other := []byte(r.Created)\nreturn recoveryMetadataSHA256(other), nil", notExactly, nil),
		printer("input reassigned", "", "raw = raw[1:]\nreturn recoveryMetadataSHA256(raw), nil", strayInput, nil),
		printer("input aliased", "", "x := raw\nreturn recoveryMetadataSHA256(x), nil", strayInput, nil),
		printer("input edited in place", "", "raw[0] = 0\nreturn recoveryMetadataSHA256(raw), nil", strayInput, nil),
		printer("result transformed", "\"strings\"", "return strings.ToUpper(recoveryMetadataSHA256(raw)), nil", notExactly, nil),
		printer("digest returned with a non-nil error", "", "return recoveryMetadataSHA256(raw), err", notExactly, nil),
		printer("no return produces the digest", "", "_ = recoveryMetadataSHA256(raw)\nreturn \"\", nil", "no return produces the digest", nil),
		{"named result with a bare return", "named results are not admitted", recoveryStubPackage("package keyvault\nimport \"encoding/json\"\nfunc (r RecoveryRecord) PairMetadataSHA256() (digest string, err error) {\nraw, err := json.Marshal(r)\ndigest = recoveryMetadataCopy(raw)\nreturn\n}\n", conformingBinding, copyFile), reviewed},
		{"input marshals another value", "the first statement does not define the input", recoveryStubPackage("package keyvault\nimport \"encoding/json\"\nfunc (r RecoveryRecord) PairMetadataSHA256() (string, error) {\nraw, err := json.Marshal(RecoveryRecord{})\nif err != nil {\nreturn \"\", err\n}\nreturn recoveryMetadataSHA256(raw), nil\n}\n", conformingBinding, nil), reviewed},
		binding("discarded literal, returned helper (review mutant)", "_ = RootGrantsPairBinding{MetadataSHA256: recoveryMetadataSHA256(raw)}\nreturn recoveryPairBindingCopy(raw, r)", "the body is not exactly one return statement", copyFile),
		binding("helper copy in the field", "return RootGrantsPairBinding{MetadataSHA256: recoveryMetadataCopy(raw)}", "the MetadataSHA256 field is not exactly", copyFile),
		binding("sliced argument", "return RootGrantsPairBinding{MetadataSHA256: recoveryMetadataSHA256(raw[1:])}", "the MetadataSHA256 field is not exactly", nil),
		binding("field overwritten after construction", "b := RootGrantsPairBinding{MetadataSHA256: recoveryMetadataSHA256(raw)}\nb.MetadataSHA256 = recoveryMetadataCopy(raw)\nreturn b", "the body is not exactly one return statement", copyFile),
		binding("variable returned", "b := RootGrantsPairBinding{MetadataSHA256: recoveryMetadataSHA256(raw)}\nreturn b", "the body is not exactly one return statement", nil),
		binding("parameter reassigned", "raw = raw[1:]\nreturn RootGrantsPairBinding{MetadataSHA256: recoveryMetadataSHA256(raw)}", "the body is not exactly one return statement", nil),
		binding("unkeyed element", "return RootGrantsPairBinding{\"x\", recoveryMetadataSHA256(raw)}", "the binding literal has an unkeyed element", nil),
		binding("literal of another type", "return RootGrantsOther{MetadataSHA256: recoveryMetadataSHA256(raw)}", "the returned value is not a composite literal of RootGrantsPairBinding", nil),
		binding("parameter used twice", "return RootGrantsPairBinding{Schema: recoveryMetadataSHA256(raw), MetadataSHA256: recoveryMetadataSHA256(raw)}", "the first parameter is used 2 times", nil),
		binding("shared name shadowed by a closure", "recoveryMetadataSHA256 := func(b []byte) string { return \"00\" }\nreturn RootGrantsPairBinding{MetadataSHA256: recoveryMetadataSHA256(raw)}", "function literals are not admitted", nil),
		{"hashing helper in a third file, never called", "unreviewed hashing function recoveryMetadataCopy", recoveryStubPackage(conformingPrinter, conformingBinding, copyFile), reviewed},
		{"hashing helper through an import alias", "unreviewed hashing function aliased", recoveryStubPackage(conformingPrinter, conformingBinding, map[string]string{"alias.go": "package keyvault\nimport shaX \"crypto/sha256\"\nfunc aliased(b []byte) [32]byte {\nreturn shaX.Sum256(b)\n}\n"}), reviewed},
		{"hash constructor through hmac and sha512", "unreviewed hashing function macCopy", recoveryStubPackage(conformingPrinter, conformingBinding, map[string]string{"mac.go": "package keyvault\nimport (\n\"crypto/hmac\"\n\"crypto/sha512\"\n)\nfunc macCopy(key []byte) []byte {\nreturn hmac.New(sha512.New, key).Sum(nil)\n}\n"}), reviewed},
		{"method with a pointer receiver", "unreviewed hashing function thing.sum", recoveryStubPackage(conformingPrinter, conformingBinding, map[string]string{"thing.go": "package keyvault\nimport \"crypto/sha256\"\ntype thing struct{}\nfunc (t *thing) sum(b []byte) [32]byte {\nreturn sha256.Sum256(b)\n}\n"}), reviewed},
		{"package-level hash constructor", "unreviewed hashing function <package-level>", recoveryStubPackage(conformingPrinter, conformingBinding, map[string]string{"var.go": "package keyvault\nimport \"crypto/sha256\"\nvar newDigest = sha256.New\n"}), reviewed},
		{"dot-imported hash package", "a hash package is dot-imported", recoveryStubPackage(conformingPrinter, conformingBinding, map[string]string{"dot.go": "package keyvault\nimport . \"crypto/sha256\"\nfunc dotted(b []byte) [32]byte {\nreturn Sum256(b)\n}\n"}), reviewed},
		{"reviewed function no longer hashes", "reviewed hashing function not found: ghost", recoveryStubPackage(conformingPrinter, conformingBinding, nil), []string{recoveryShared, "ghost"}},
		printer("excluded build-tagged file holds a conforming copy, the compiled printer hashes raw[1:] (review mutant)", "", "return recoveryMetadataSHA256(raw[1:]), nil", notExactly, map[string]string{"a_decoy.go": "//go:build review_guard_disabled\n\n" + recoveryStubPrinter("", "return recoveryMetadataSHA256(raw), nil")}),
		{"two selected declarations of the printer", "is declared 2 times in the selected build", recoveryStubPackage(conformingPrinter, conformingBinding, map[string]string{"dup.go": conformingPrinter}), reviewed},
		{"unconstrained platform duplicates", "duplicate declaration in the selected build", recoveryStubPackage(conformingPrinter, conformingBinding, map[string]string{"plat_a.go": "package keyvault\nfunc platform() string { return \"a\" }\n", "plat_b.go": "package keyvault\nfunc platform() string { return \"b\" }\n"}), reviewed},
		{"standard-library sha3 constructor", "unreviewed hashing function sha3Copy", recoveryStubPackage(conformingPrinter, conformingBinding, map[string]string{"sha3.go": "package keyvault\nimport \"crypto/sha3\"\nfunc sha3Copy(b []byte) []byte {\nh := sha3.New256()\n_, _ = h.Write(b)\nreturn h.Sum(nil)\n}\n"}), reviewed},
	}
	for _, p := range plants {
		problems, err := recoveryContractProblems(p.files, p.reviewed)
		if err != nil {
			t.Fatalf("%s: the plant is not valid source for the guard: %v", p.name, err)
		}
		matched := false
		for _, problem := range problems {
			matched = matched || strings.Contains(problem, p.want)
		}
		if !matched {
			t.Fatalf("%s: the guard did not report %q: %v", p.name, p.want, problems)
		}
	}
	if problems, err := recoveryContractProblems(recoveryStubPackage(conformingPrinter, conformingBinding, nil), reviewed); err != nil || len(problems) != 0 {
		t.Fatalf("the conforming package was rejected: %v %v", problems, err)
	}
	variants := map[string]string{
		"plat_darwin.go": "package keyvault\nfunc platform() string { return \"d\" }\n",
		"plat_other.go":  "//go:build !darwin\n\npackage keyvault\nfunc platform() string { return \"o\" }\n",
	}
	if problems, err := recoveryContractProblems(recoveryStubPackage(conformingPrinter, conformingBinding, variants), reviewed); err != nil || len(problems) != 0 {
		t.Fatalf("legitimate platform variants were rejected: %v %v", problems, err)
	}
	// The real source: every non-test file of the package, whatever its build
	// constraint, so that the result is the same on every platform.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		sources[name] = string(raw)
	}
	if len(sources) < 50 {
		t.Fatalf("only %d source files were read", len(sources))
	}
	problems, err := recoveryContractProblems(sources, recoveryReviewedHashers)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Fatalf("the real source does not conform to the one-definition contract: %v", problems)
	}
}
