package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Actual go mod edit grammar grounds both accepted and forbidden forms. These
// tests qualify pin selection/equality only, not namespaces or measured latency.
func TestModuleToolchainGrammar(t *testing.T) {
	cases := []struct{ name, module, actual, refusal string }{
		{"explicit", "go 1.26.0\ntoolchain go1.26.10\n", "go1.26.10", ""},
		{"implicit", "go 1.26.10\n", "go1.26.10", ""},
		{"language-with-pin", "go 1.26\ntoolchain go1.26.10\n", "go1.26.10", ""},
		{"comments", "// neutral comment\ngo 1.26 // minimum\ntoolchain go1.26.10 // exact\n", "go1.26.10", ""},
		{"implicit-eof", "go 1.26.10", "go1.26.10", ""},
		{"explicit-eof", "go 1.26\ntoolchain go1.26.10", "go1.26.10", ""},
		{"go-trailing", "go 1.26.10 garbage\n", "go1.26.10", "grammar refused"},
		{"toolchain-trailing", "go 1.26\ntoolchain go1.26.10 garbage\n", "go1.26.10", "grammar refused"},
		{"go-duplicate", "go 1.26.0\ngo 1.26.10\n", "go1.26.10", "grammar refused"},
		{"toolchain-duplicate", "go 1.26\ntoolchain go1.26.0\ntoolchain go1.26.10\n", "go1.26.10", "grammar refused"},
		{"missing", "module example.invalid/test\n", "go1.26.10", "exact released toolchain pin required"},
		{"no-exact-fallback", "go 1.26\n", "go1.26.10", "exact released toolchain pin required"},
		{"toolchain-default", "go 1.26.10\ntoolchain default\n", "go1.26.10", "exact released toolchain pin required"},
		{"minimum-release-newer", "go 1.27.0\ntoolchain go1.26.10\n", "go1.26.10", "below the module Go minimum"},
		{"minimum-patch-newer", "go 1.26.11\ntoolchain go1.26.10\n", "go1.26.10", "below the module Go minimum"},
		{"mismatch-explicit", "go 1.26\ntoolchain go1.26.10\n", "go1.26.11", "runtime differs"},
		{"mismatch-implicit", "go 1.26.10\n", "go1.26.0", "runtime differs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture.mod")
			if err := os.WriteFile(path, []byte(tc.module), 0600); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			err := qualify(path, tc.actual)
			if tc.refusal == "" {
				if err != nil {
					t.Fatalf("valid module refused: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.refusal) {
				t.Fatalf("wrong refusal: got %v, want %s", err, tc.refusal)
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil || string(after) != string(before) {
				t.Fatal("parser modified module fixture")
			}
		})
	}
}

// The actual module file must work in canonical form without being rewritten.
func TestRepositoryModule(t *testing.T) {
	if err := qualify("../../go.mod", "go1.26.10"); err != nil {
		t.Fatal(err)
	}
}
