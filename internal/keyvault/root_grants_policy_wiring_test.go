package keyvault

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

// markerAccessDescriptor is the description of the public-marker item that the
// attended qualification observed; the production descriptor replaces it in the
// predicted production forms.
const markerAccessDescriptor = "Root ACL public qualification"

func loadObservedProjections(t *testing.T) (before, after rootqualification.Projection) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "rootqualification", "testdata", "observed", "h4-frames.json"))
	if err != nil {
		t.Fatal(err)
	}
	var observed struct {
		Before rootqualification.Projection `json:"before"`
		After  rootqualification.Projection `json:"after"`
	}
	if err := json.Unmarshal(raw, &observed); err != nil {
		t.Fatal(err)
	}
	return observed.Before, observed.After
}

func substituteDescriptor(p rootqualification.Projection, from, to string) rootqualification.Projection {
	acls := make([]rootqualification.ACLProjection, len(p.ACLs))
	copy(acls, p.ACLs)
	for i := range acls {
		if acls[i].Description == from {
			acls[i].Description = to
		}
	}
	p.ACLs = acls
	return p
}

// Claim: the Go constant of the production descriptor equals the literal that the
// native store unit builds every root item's access object with, so the allowlist
// instance compares against the description the native code actually writes. A
// literal that drifts on either side fails here. Limit: it reads source; the native
// in-process test compares the projected frame itself.
func TestRootGrantsAccessDescriptorEqualsTheNativeLiteral(t *testing.T) {
	src, err := os.ReadFile("root_grants_store_darwin.c")
	if err != nil {
		t.Fatal(err)
	}
	found := regexp.MustCompile(`static const char \*KVRGAccessDescriptor = "([^"\\]*)";`).FindAllStringSubmatch(string(src), -1)
	if len(found) != 1 || found[0][1] != rootGrantsAccessDescriptor {
		t.Fatalf("the native descriptor literal %v differs from %q", found, rootGrantsAccessDescriptor)
	}
	if rootGrantsAccessDescriptor == markerAccessDescriptor {
		t.Fatal("production and public-marker items must not share a descriptor")
	}
}

// Claim: the production policy admits the predicted production forms, the observed
// intended and stored forms of the public marker with the production descriptor
// substituted, each through its own entry point, and it refuses the marker's own
// frames: a production item that carried the marker's description would not be
// admitted. This is the wiring check that the instance is built with the right
// descriptor. Limit: the production stored form is a prediction until the
// rehearsal observes a real production item.
func TestRootGrantsProductionPolicyAdmitsThePredictedProductionFormsOnly(t *testing.T) {
	policy := productionRootGrantsACLPolicy()
	before, after := loadObservedProjections(t)
	if err := policy.AdmitIntended(substituteDescriptor(before, markerAccessDescriptor, rootGrantsAccessDescriptor)); err != nil {
		t.Fatalf("the predicted production intended form is refused: %v", err)
	}
	if err := policy.AdmitStored(substituteDescriptor(after, markerAccessDescriptor, rootGrantsAccessDescriptor)); err != nil {
		t.Fatalf("the predicted production stored form is refused: %v", err)
	}
	if err := policy.AdmitIntended(before); !errors.Is(err, rootqualification.ErrPolicyRefused) {
		t.Fatalf("the production policy admitted the marker's intended frame: %v", err)
	}
	if err := policy.AdmitStored(after); !errors.Is(err, rootqualification.ErrPolicyRefused) {
		t.Fatalf("the production policy admitted the marker's stored frame: %v", err)
	}
	// Not interchangeable: each frame is refused by the other entry point.
	if err := policy.AdmitStored(substituteDescriptor(before, markerAccessDescriptor, rootGrantsAccessDescriptor)); !errors.Is(err, rootqualification.ErrPolicyRefused) {
		t.Fatalf("the stored entry point admitted the intended form: %v", err)
	}
	if err := policy.AdmitIntended(substituteDescriptor(after, markerAccessDescriptor, rootGrantsAccessDescriptor)); !errors.Is(err, rootqualification.ErrPolicyRefused) {
		t.Fatalf("the intended entry point admitted the stored form: %v", err)
	}
}

// Claim (fail closed): if the allowlist cannot be built, the value that production
// holds is the refuse-all stub and every projection is refused through both entry
// points; the allowlist is built for the real descriptor.
func TestRootGrantsPolicyFallsBackToTheRefuseAllStubWhenTheAllowlistCannotBeBuilt(t *testing.T) {
	before, after := loadObservedProjections(t)
	for _, bad := range []string{"", strings.Repeat("a", 129), "bad\ndescriptor"} {
		policy := rootGrantsPolicyFor(bad)
		if _, ok := policy.(rootGrantsNoACLPolicy); !ok {
			t.Fatalf("descriptor %q built %T, not the stub", bad, policy)
		}
		for _, p := range []rootqualification.Projection{before, after, {}} {
			if !errors.Is(policy.AdmitIntended(p), errRootGrantsACLPolicyUnavailable) || !errors.Is(policy.AdmitStored(p), errRootGrantsACLPolicyUnavailable) {
				t.Fatalf("descriptor %q: the fallback admitted a projection", bad)
			}
		}
	}
	if _, ok := rootGrantsPolicyFor(rootGrantsAccessDescriptor).(*rootqualification.StoragePolicy); !ok {
		t.Fatal("the real descriptor did not build the allowlist")
	}
}

// Claim (source guard): the policy has exactly two call sites in non-test code,
// each asking its own form: AdmitIntended in prepareAdmittedAdd (the object before
// the add, also used by the check made before the helper starts) and AdmitStored in
// RootGrantsPublicMetadata (the stored item's ACL). The refuse-all stub is named
// only in its own declarations and in the constructor fallback. A new or swapped
// call site, or a path that builds the stub into production, fails here. Limit: it
// reads the syntax of this package; it does not follow calls across packages.
func TestRootGrantsPolicyHasExactlyTwoCallSitesEachOnItsOwnForm(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources: %v", err)
	}
	type site struct{ Function, Entry string }
	var sites []site
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ownsStub := fn.Name.Name == "rootGrantsPolicyFor"
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				if id, ok := fn.Recv.List[0].Type.(*ast.Ident); ok && id.Name == "rootGrantsNoACLPolicy" {
					ownsStub = true
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					if sel, ok := node.Fun.(*ast.SelectorExpr); ok && strings.HasPrefix(sel.Sel.Name, "Admit") {
						sites = append(sites, site{fn.Name.Name, sel.Sel.Name})
					}
				case *ast.Ident:
					if node.Name == "rootGrantsNoACLPolicy" && !ownsStub {
						t.Errorf("%s: the refuse-all stub is referenced in %s", name, fn.Name.Name)
					}
				}
				return true
			})
		}
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].Function != sites[j].Function {
			return sites[i].Function < sites[j].Function
		}
		return sites[i].Entry < sites[j].Entry
	})
	want := []site{{"RootGrantsPublicMetadata", "AdmitStored"}, {"prepareAdmittedAdd", "AdmitIntended"}}
	if !reflect.DeepEqual(sites, want) {
		t.Fatalf("policy call sites %v, want %v", sites, want)
	}
}
