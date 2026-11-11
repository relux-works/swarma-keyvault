package codesigntest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Even with unchanged PASS lines, a missing or wrong native status or a
// changed helper receipt causes the outer runner's evidence check to fail.
func TestRecoveryEvidenceRequiresStatusAndReceipt(t *testing.T) {
	const statuses = "" +
		"codesigntest recovery observation: hardened status=0 accepted=true\n" +
		"codesigntest recovery observation: no-runtime status=-25293 accepted=false\n" +
		"codesigntest recovery observation: wrong-hash status=-25293 accepted=false\n" +
		"codesigntest recovery observation: debug-entitlement status=-25293 accepted=false\n"
	const passes = "" +
		"--- PASS: TestRecoveryActualChildCodeBoundary/hardened (0.00s)\n" +
		"--- PASS: TestRecoveryActualChildCodeBoundary/no-runtime (0.00s)\n" +
		"--- PASS: TestRecoveryActualChildCodeBoundary/wrong-hash (0.00s)\n" +
		"--- PASS: TestRecoveryActualChildCodeBoundary/debug-entitlement (0.00s)\n"
	run := filepath.Join(t.TempDir(), "qa[lab]", "run-fixture")
	root := filepath.Join(run, "identity-fixture")
	for _, mode := range []string{"hardened", "no-runtime", "wrong-hash", "debug-entitlement"} {
		if err := os.MkdirAll(filepath.Join(root, mode), 0700); err != nil {
			t.Fatal(err)
		}
	}
	positive := filepath.Join(root, "hardened", "pass.received")
	if err := os.WriteFile(positive, []byte("request received"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(output, want string) {
		t.Helper()
		err := CheckRecoveryEvidence([]byte(output), run)
		if want == "" {
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("recovery evidence = %v, wanted %q", err, want)
		}
	}
	check(statuses+passes, "")
	check(strings.Replace(statuses, "wrong-hash status=-25293", "wrong-hash status=-1", 1)+passes, "native status for wrong-hash")
	check(strings.Replace(statuses, "codesigntest recovery observation: wrong-hash status=-25293 accepted=false\n", "", 1)+passes, "native status for wrong-hash")
	refused := filepath.Join(root, "debug-entitlement", "pass.received")
	if err := os.WriteFile(refused, []byte("request received"), 0600); err != nil {
		t.Fatal(err)
	}
	check(statuses+passes, "debug-entitlement has a receipt")
	if err := os.Remove(refused); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(positive); err != nil {
		t.Fatal(err)
	}
	check(statuses+passes, "admitted recovery fixture did not record request receipt")
}

// The runner looks for each base below the exact parent path. A bracketed
// parent works, and missing or duplicate bases still fail the build count.
func TestFixtureBaseLookupUsesLiteralPath(t *testing.T) {
	run := filepath.Join(t.TempDir(), "qa[lab]", "run-fixture")
	for _, prefix := range []string{"recovery-base-", "kek-base-"} {
		path := filepath.Join(run, prefix+"one")
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if got, err := FindSingleFixtureDir(run, prefix); err != nil || got != path {
			t.Fatalf("fixture base = %q, %v", got, err)
		}
	}
	if _, err := FindSingleFixtureDir(run, "missing-base-"); err == nil || !strings.Contains(err.Error(), "missing retained fixture") {
		t.Fatalf("missing base = %v", err)
	}
	if err := os.Mkdir(filepath.Join(run, "kek-base-two"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := FindSingleFixtureDir(run, "kek-base-"); err == nil || !strings.Contains(err.Error(), "multiple retained fixtures") {
		t.Fatalf("duplicate base = %v", err)
	}
}
